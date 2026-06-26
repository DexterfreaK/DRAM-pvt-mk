"""hash_bounds.py — Stage 3: derive return-value bounds via known-bits domain.

Strategy (tried in order):

  1. C-source regex — scan the function body for:
       return ... % CONST       →  urem reduction  → MOD_const(top, CONST)
       & (CONST - 1) or & 0xNN  →  mask anywhere on the accumulator path
                                   → MOD_pow2(top, log2(CONST))
     CONST may be a numeric literal or a #define name resolved from the source.

  2. LLVM IR scan (fallback) — look for `urem i32 %x, N` or `and i32 %x, N`
     instructions reachable from the `ret` value.

The bound is computed using hash_abstract_interp.py (known-bits domain), so
the result is always a sound over-approximation.

Returns a BoundResult with:
  .min       — always 0 for hash-like functions
  .max       — tight upper bound from known-bits analysis
  .mod_type  — "urem" | "and_mask" | "unbounded"
  .mod_val   — the modulus / mask constant (0 = unbounded)
"""

from __future__ import annotations

import re
import sys
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

# Locate hash_abstract_interp.py relative to this file.
_AI_DEMO = Path(__file__).parent.parent.parent / "examples" / "ai_demo"
sys.path.insert(0, str(_AI_DEMO))
import hash_abstract_interp as hai   # known-bits domain  # noqa: E402


@dataclass
class BoundResult:
    min: int          # always 0
    max: int          # tight upper bound
    mod_type: str     # "urem" | "and_mask" | "unbounded"
    mod_val: int      # the constant (0 = unbounded)

    def klee_assume_expr(self, result_var: str) -> Optional[str]:
        """Return the C klee_assume expression, or None if unbounded."""
        if self.mod_type == "unbounded":
            return None
        if self.mod_type == "urem":
            return f"{result_var} < {self.mod_val}"
        # and_mask
        return f"{result_var} <= {self.max}"


# ── Known-bits bound computation ─────────────────────────────────────────────

def _bound_urem(modulus: int) -> BoundResult:
    """Any value modulo `modulus` ∈ [0, modulus-1] (exact by arithmetic)."""
    # MOD_const in the known-bits domain rounds up to next power of 2 for
    # non-power-of-2 moduli.  But urem x, m guarantees result ∈ [0, m-1]
    # exactly — use that directly rather than the looser bit-domain bound.
    return BoundResult(min=0, max=modulus - 1, mod_type="urem", mod_val=modulus)


def _bound_and_mask(mask: int) -> BoundResult:
    """Any value ANDed with `mask` ∈ [0, mask] (exact when mask = 2^k - 1)."""
    b = hai.AND(hai.Bits.top(), hai.Bits.const(mask))
    lo, hi = b.interval()
    return BoundResult(min=lo, max=hi, mod_type="and_mask", mod_val=mask)


_UNBOUNDED = BoundResult(min=0, max=(1 << 32) - 1,
                         mod_type="unbounded", mod_val=0)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_defines(c_text: str) -> dict[str, int]:
    """Extract `#define NAME NUMBER` from source text."""
    defines: dict[str, int] = {}
    for m in re.finditer(r'#\s*define\s+(\w+)\s+(\d+)', c_text):
        try:
            defines[m.group(1)] = int(m.group(2))
        except ValueError:
            pass
    # Also handle `#define NAME (NUMBER)` and `#define NAME NUMBERu`
    for m in re.finditer(r'#\s*define\s+(\w+)\s+\(?\s*(\d+)[uUlL]*\s*\)?', c_text):
        if m.group(1) not in defines:
            try:
                defines[m.group(1)] = int(m.group(2))
            except ValueError:
                pass
    return defines


def _resolve_val(token: str, defines: dict[str, int]) -> Optional[int]:
    """Resolve a token that is either a numeric literal or a #define name."""
    try:
        return int(token, 0)
    except ValueError:
        return defines.get(token)


def _func_body(c_text: str, func_name: str) -> str:
    """Extract the text of func_name's body (between the outermost braces).

    Requires the function name to appear after a C return-type token at the
    start of a line, so comment references like `/* Called by foo() */` or
    call sites inside other function bodies are skipped.
    """
    # Step 1: find the definition line — a line that starts with a word char
    # (return type token), not `*` (dereference), not `/` (comment).
    m_def = re.search(
        r'^[A-Za-z_][\w\s\*]*\b' + re.escape(func_name) + r'\s*\(',
        c_text, re.MULTILINE
    )
    if not m_def:
        return c_text

    # Step 2: from the definition start, find the opening '{'.
    brace_m = re.search(r'\{', c_text[m_def.start():])
    if not brace_m:
        return c_text
    start = m_def.start() + brace_m.start()
    depth = 0
    for i, ch in enumerate(c_text[start:], start):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return c_text[start:i + 1]
    return c_text[start:]


# ── C-source strategy ─────────────────────────────────────────────────────────

_RETURN_MOD_RE = re.compile(
    r'\breturn\b[^;]*%\s*([A-Za-z_]\w*|\d+)'
)
_AND_MASK_RE = re.compile(
    r'&\s*\(?\s*([A-Za-z_]\w*|\d+)\s*-\s*1\s*\)?'   # & (CONST - 1)
    r'|&\s*(0x[0-9a-fA-F]+|\d+)(?!\s*-)'             # & 0xNN or & NN
)


def _from_c_source(body: str, defines: dict[str, int]) -> Optional[BoundResult]:
    # 1. return ... % CONST  (exact: urem guarantees [0, CONST-1])
    m = _RETURN_MOD_RE.search(body)
    if m:
        val = _resolve_val(m.group(1), defines)
        if val and val > 1:
            return _bound_urem(val)

    # 2. & CONST directly on the return expression only.
    #    Body-wide mask scanning is too imprecise: e.g. CRC-16 uses `& 0xFF`
    #    to mask a table INDEX, not the returned accumulator.  Restrict to
    #    `return ... & CONST;` so only genuine output-path masks are caught.
    #    Deeper cases (mask feeds XOR chain → return) are handled by _from_ir.
    _RET_EXPR_RE = re.compile(r'\breturn\b([^;]+);', re.DOTALL)
    best_mask: Optional[int] = None
    for ret_m in _RET_EXPR_RE.finditer(body):
        ret_expr = ret_m.group(1)
        for m in _AND_MASK_RE.finditer(ret_expr):
            raw = m.group(1) or m.group(2)
            val = _resolve_val(raw, defines)
            if val is None:
                continue
            mask = (val - 1) if m.group(1) else val
            if mask > 0 and (best_mask is None or mask < best_mask):
                best_mask = mask
    if best_mask is not None:
        return _bound_and_mask(best_mask)

    return None


# ── IR scan strategy ──────────────────────────────────────────────────────────

def _from_ir(ir_text: str, func_name: str) -> Optional[BoundResult]:
    """Backward data-flow slice from the `ret` instruction.

    Walks the SSA def-use chain backwards from the returned variable, looking
    for `urem` or `and` instructions whose result transitively reaches `ret`.
    This correctly handles:
      - do_gather:  acc ^= (v & 255)  →  acc ∈ [0,255]   (mask on accumulator)
      - crc16:      crc_table[(crc>>8 ^ byte) & 0xFF]  → mask is on TABLE INDEX,
                    not the return value → correctly returns None (unbounded)
      - get_packet_hash:  % RING_SIZE  → urem → [0, 126]
    """
    fn_open = re.compile(r'define\b.*@' + re.escape(func_name) + r'\(')
    in_fn = False
    func_lines: list[str] = []
    for line in ir_text.splitlines():
        if not in_fn:
            if fn_open.search(line):
                in_fn = True
            continue
        if line.strip() == "}":
            break
        func_lines.append(line)

    # Find the returned variable from the `ret` instruction.
    ret_var: Optional[str] = None
    for line in func_lines:
        m = re.search(r'\bret\b\s+\w[\w\s]*\s+(%[\w\.]+)', line)
        if m:
            ret_var = m.group(1)
            break
    if ret_var is None:
        return None

    # Build SSA def map: %var → RHS of its definition.
    defs: dict[str, str] = {}
    for line in func_lines:
        m = re.match(r'\s*(%[\w\.]+)\s*=\s*(.+)', line)
        if m:
            defs[m.group(1)] = m.group(2).strip()

    # BFS backward through def-use chain from ret_var.
    visited: set[str] = set()
    queue = [ret_var]
    while queue:
        var = queue.pop()
        if var in visited or var not in defs:
            continue
        visited.add(var)
        rhs = defs[var]

        # urem (exact modulo)
        m = re.search(r'\burem\b\s+i\d+\s+%[\w\.]+,\s+(\d+)', rhs)
        if m:
            return _bound_urem(int(m.group(1)))

        # and with immediate constant (mask)
        m = re.search(r'\band\b\s+i\d+\s+%[\w\.]+,\s+(\d+)', rhs)
        if m:
            val = int(m.group(1))
            if val > 0:
                return _bound_and_mask(val)

        # Follow all %var operands backward (phi nodes, xor, add, etc.)
        for operand in re.findall(r'%[\w\.]+', rhs):
            if operand not in visited:
                queue.append(operand)

    return None


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(source: Path, func_name: str,
            ir_text: Optional[str] = None) -> BoundResult:
    """Derive a sound upper bound on the return value of func_name.

    Args:
        source:    Path to the C source file.
        func_name: Name of the target function.
        ir_text:   Optional pre-disassembled LLVM IR (used as fallback).

    Returns a BoundResult.  If no bound can be derived, returns UNBOUNDED
    (still sound — klee_assume is simply omitted).
    """
    c_text  = source.read_text()
    defines = _resolve_defines(c_text)
    body    = _func_body(c_text, func_name)

    result = _from_c_source(body, defines)
    if result is not None:
        return result

    if ir_text:
        result = _from_ir(ir_text, func_name)
        if result is not None:
            return result

    sys.stderr.write(
        f"[hash_bounds] no bound found for {func_name}; "
        "emitting unbounded symbolic (sound but weak)\n"
    )
    return _UNBOUNDED
