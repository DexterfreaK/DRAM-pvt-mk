"""stub_emitter.py — emit a sound KLEE stub C file for a summarized function.

Produces a file that mirrors the hand-written stubs (bmc_hash_stub.c,
do_gather_stub.c): preserves the original headers/macros, reproduces the
function signature, and replaces the body with klee_make_symbolic calls
bounded by Stage 2 (side-effect) and Stage 3 (return-value) analysis.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

from .ir_analyzer import SideEffect
from .hash_bounds import BoundResult


# ── Header extraction from C source ──────────────────────────────────────────

_KEEP_RE = re.compile(
    r'^\s*(?:#\s*(?:include|define|ifndef|ifdef|endif|undef)\b|typedef\b)'
)


def _extract_headers(c_text: str, func_name: str) -> list[str]:
    """Return include/define/typedef lines that appear before the definition."""
    # Require the stop line to START with a word char (return type token),
    # so comment mentions like "/* Called by foo() */" don't trigger early.
    stop_re = re.compile(
        r'^[A-Za-z_][\w\s\*]*\b' + re.escape(func_name) + r'\s*\('
    )
    lines = []
    for line in c_text.splitlines():
        if stop_re.match(line):
            break
        if _KEEP_RE.match(line) or line.strip() == "":
            lines.append(line)
    return lines


# ── C function signature extraction ──────────────────────────────────────────

def _extract_signature(c_text: str, func_name: str) -> Optional[str]:
    """Return the full function signature (return type + name + params).

    We anchor to the start of the line that contains the return type to avoid
    grabbing numeric literals or comments from preceding lines.
    """
    # Find the function DEFINITION: a line that starts with a return-type token
    # (word char, not a comment '/' or '*'), then has the function name.
    # This skips comment mentions like "/* Called by foo() */" and call sites
    # inside other function bodies.
    m_name = re.search(
        r'^[A-Za-z_][\w\s\*]*\b' + re.escape(func_name) + r'\s*\(',
        c_text, re.MULTILINE
    )
    if not m_name:
        return None

    # The regex matched "RETURNTYPE funcname(" — split it.
    matched = m_name.group(0)              # e.g. "u32 get_packet_hash("
    fn_offset = matched.rfind(func_name)   # offset of func_name within match
    ret_type_raw = matched[:fn_offset].strip()
    if not ret_type_raw:
        return None

    # Position of the opening '(' is right after the match (it was consumed).
    paren_start = m_name.end() - 1        # m_name.end() is just past '('
    depth = 0
    for i, ch in enumerate(c_text[paren_start:], paren_start):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                params_raw = c_text[paren_start:i + 1]
                sig = ret_type_raw + ' ' + func_name + params_raw
                # Collapse internal whitespace but keep structure.
                sig = re.sub(r'\s+', ' ', sig).strip()
                return sig
    return None


def _param_names(sig: str, func_name: str) -> list[str]:
    """Extract parameter names from a C signature string."""
    m = re.search(re.escape(func_name) + r'\s*\(([^)]*)\)', sig)
    if not m:
        return []
    names = []
    for param in re.split(r',\s*', m.group(1)):
        param = param.strip()
        # Last word (possibly with * prefix) is the name
        words = param.split()
        if words:
            # Strip leading '*' (pointer) and trailing '[N]' (array dimension).
            name = re.sub(r'\[.*\]$', '', words[-1]).lstrip('*')
            names.append(name)
    return names


# ── Stub body generation ──────────────────────────────────────────────────────

def _void_inputs(param_names: list[str], output_params: set[str]) -> list[str]:
    """Emit (void)param; for every non-output parameter."""
    lines = []
    for n in param_names:
        if n not in output_params:
            lines.append(f"    (void){n};")
    return lines


def _side_effect_block(fx: SideEffect) -> list[str]:
    """Emit the klee_make_symbolic + klee_assume for one side-effect param."""
    # Derive the C element type from the pointer type string.
    # e.g. "unsigned int *" → "unsigned int"
    elem_type = re.sub(r'\s*\*\s*$', '', fx.c_type).strip()
    if not elem_type:
        elem_type = "unsigned int"  # fallback

    var = fx.param  # use the param name as the local variable name

    lines = [
        f"    /* [Stage 2] side effect: *{fx.param} */",
        f"    {elem_type} {var}_se;",
        f"    klee_make_symbolic(&{var}_se, sizeof {var}_se, \"{var}\");",
    ]
    if fx.upper_expr is not None:
        # Relational bound derived from precondition-aware Clam analysis.
        lo = fx.lower if fx.lower is not None else 0
        lines.append(f"    klee_assume({var}_se >= {lo} && {var}_se <= {fx.upper_expr});")
    elif fx.upper is not None:
        lo = fx.lower if fx.lower is not None else 0
        if lo != 0:
            lines.append(f"    klee_assume({var}_se >= {lo});")
        lines.append(f"    klee_assume({var}_se <= {fx.upper});")
    lines.append(f"    *{fx.param} = {var}_se;")
    return lines


def _return_block(ret_type: str, bound: BoundResult) -> list[str]:
    """Emit the klee_make_symbolic + klee_assume for the return value."""
    var = "result"
    lines = [
        f"    /* [Stage 3] return value bound: {bound.mod_type} "
        f"mod_val={bound.mod_val} → max={bound.max} */",
        f"    {ret_type} {var};",
        f"    klee_make_symbolic(&{var}, sizeof {var}, \"{var}\");",
    ]
    assume = bound.klee_assume_expr(var)
    if assume:
        lines.append(f"    klee_assume({assume});")
    lines.append(f"    return {var};")
    return lines


def _return_type(sig: str, func_name: str) -> str:
    """Extract the C return type from the signature string."""
    m = re.match(
        r'([\w\s\*]+?)\s+' + re.escape(func_name) + r'\s*\(',
        sig
    )
    if m:
        return m.group(1).strip()
    return "uint32_t"


# ── Public API ────────────────────────────────────────────────────────────────

def emit(
    source: Path,
    func_name: str,
    side_effects: list[SideEffect],
    return_bound: BoundResult,
    out: Path,
    klee_inc: Optional[str] = None,
) -> None:
    """Write the C stub to `out`."""
    c_text = source.read_text()
    headers = _extract_headers(c_text, func_name)
    sig = _extract_signature(c_text, func_name)
    if sig is None:
        sys.stderr.write(f"[stub_emitter] could not find signature for {func_name}\n")
        sys.exit(1)

    ret_type = _return_type(sig, func_name)
    param_names = _param_names(sig, func_name)
    output_params = {fx.param for fx in side_effects}

    # ── Assemble file ────────────────────────────────────────────────────────
    lines: list[str] = []

    # Preserve original headers.
    lines.extend(headers)

    # Ensure klee/klee.h is included.
    klee_already = any("klee" in h for h in headers)
    if not klee_already:
        lines.append("#include <klee/klee.h>")

    lines.append("")
    lines.append(
        "/*\n"
        f" * AI-derived function summary for {func_name}().\n"
        " * Auto-generated by lifting_tools/summarizer/summarize.py\n"
        " *\n"
        " * Stage 2 (side effects):  Clam zones-domain invariants at loop exit.\n"
        " * Stage 3 (return bound):  known-bits ⊗ interval domain\n"
        f" *   mod_type={return_bound.mod_type}  mod_val={return_bound.mod_val}"
        f"  → result ∈ [0, {return_bound.max}]\n"
        " */"
    )
    lines.append(f"{sig}")
    lines.append("{")

    # Void the input params.
    void_lines = _void_inputs(param_names, output_params)
    if void_lines:
        lines.extend(void_lines)
        lines.append("")

    # Side-effect blocks.
    for fx in side_effects:
        lines.extend(_side_effect_block(fx))
        lines.append("")

    # Return-value block.
    lines.extend(_return_block(ret_type, return_bound))

    lines.append("}")
    lines.append("")

    out.write_text("\n".join(lines))
    print(f"[stub_emitter] wrote {out}")
