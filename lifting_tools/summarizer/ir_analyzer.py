"""ir_analyzer.py — Stage 2: side-effect detection and bounds via Clam.

Stage 2a: scan the LLVM IR for `store` instructions to pointer-typed function
           parameters → identifies which output params the function writes.
Stage 2b: run Clam (--crab-dom=zones) on the optimised bitcode; parse invariants
           at loop-exit/return blocks to obtain upper bounds on stored values.

The zones domain (linear arithmetic) handles loop counters (add/sub) precisely
and survives through the type of loops we care about (bmc_hash key_len counter).
It cannot bound XOR/multiply outputs (that's Stage 3's job).
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CLANG   = "clang-13"
OPT     = "opt-13"
DIS     = "llvm-dis-14"
CLAM    = Path("/root/clam/build/bin/clam")

# ── invariant parsing (adapted from examples/ai_demo/triage.py) ──────────────

_INV_LINE      = re.compile(r"/\*\*\s*INVARIANTS:\s*\([^,]*,\s*(\{[^}]*\})\)\s*\*\*/")
_BLOCK_HDR     = re.compile(r"^([\w\.@]+):\s*$")
_FUNC_DECL     = re.compile(r"^([\w\.@]+):\w+\s+declare\s+([\w\.@]+)\(")
_UPPER         = re.compile(r"^\s*([\w\.@]+)\s*<=\s*(-?\d+)\s*$")
_LOWER         = re.compile(r"^\s*-\s*([\w\.@]+)\s*<=\s*(-?\d+)\s*$")
# Relational octagon constraint: -PARAM+VAR <= C  →  VAR ≤ PARAM + C
_RELATIONAL_UB = re.compile(r"^\s*-([\w\.@]+)\+([\w\.@]+)\s*<=\s*(-?\d+)\s*$")


def _parse_clam_invariants(text: str, func_name: str) -> dict[str, dict[str, int]]:
    """Return {ssa_var: {upper?: int, lower?: int}} aggregated over all blocks,
    keeping the tightest upper and loosest lower bound seen (conservative for
    variables that only appear in loop-exit blocks).

    For sound stubbing we want the *exit* invariant (after all iterations), so
    we look at blocks whose names suggest they follow the loop: for.end, exit,
    loop.end, *.end, return, or the block containing `ret`.
    """
    # Match only the canonical loop-exit block names that LLVM/Clang emits.
    # Deliberately avoid "\.end$" — that would catch in-loop blocks like
    # "if.end" whose invariants are path-specific and can be tighter (unsound).
    exit_names = re.compile(r"^(for\.end\d*|while\.end\d*|loop\.end\d*|exit\d*|return\d*|cleanup\d*)$")

    # Collect per-block invariants for our target function.
    fn_section = False
    cur_block: Optional[str] = None
    block_invs: dict[str, str] = {}

    for raw in text.splitlines():
        line = raw.strip()
        m = _FUNC_DECL.match(raw)
        if m:
            fn_section = (m.group(2) == func_name)
            cur_block = None
            continue
        if not fn_section:
            continue
        m = _BLOCK_HDR.match(raw)
        if m:
            cur_block = m.group(1)
            continue
        m = _INV_LINE.search(line)
        if m and cur_block and cur_block not in block_invs:
            # Keep only the FIRST invariant per block — that is the join of all
            # incoming paths (sound).  Later invariants in the same block are
            # path-specific sub-invariants that can be tighter but unsound as
            # a summary (e.g. key_len.0 <= 11 on the '\r' break path vs
            # key_len.0 <= 12 at the actual for.end join point).
            block_invs[cur_block] = m.group(1)

    # Pick the exit / return-block invariants preferentially; fall back to all.
    chosen = {b: v for b, v in block_invs.items() if exit_names.search(b)}
    if not chosen:
        chosen = block_invs

    # Parse bounds from chosen blocks.
    bounds: dict[str, dict] = {}
    for inv_set in chosen.values():
        inner = inv_set.strip().strip("{}").strip()
        for piece in inner.split(";"):
            piece = piece.strip()
            if not piece:
                continue
            m = _UPPER.match(piece)
            if m:
                var, val = m.group(1), int(m.group(2))
                if var not in bounds:
                    bounds[var] = {}
                if "upper" not in bounds[var] or val < bounds[var]["upper"]:
                    bounds[var]["upper"] = val
                continue
            m = _LOWER.match(piece)
            if m:
                var, val = m.group(1), -int(m.group(2))
                if var not in bounds:
                    bounds[var] = {}
                if "lower" not in bounds[var] or val > bounds[var]["lower"]:
                    bounds[var]["lower"] = val
                continue
            # Relational: -PARAM+VAR <= C  →  VAR ≤ PARAM + C
            m = _RELATIONAL_UB.match(piece)
            if m:
                param_clam, var, offset = m.group(1), m.group(2), int(m.group(3))
                if var not in bounds:
                    bounds[var] = {}
                # Keep tightest (smallest) offset seen for this var.
                if ("upper_expr" not in bounds[var]
                        or offset < bounds[var].get("upper_offset", 0)):
                    bounds[var]["upper_expr"]   = param_clam   # e.g. "arg1"
                    bounds[var]["upper_offset"] = offset        # e.g. -1 or 0
    return bounds


# ── Precondition injection ────────────────────────────────────────────────────

def _inject_preconditions(c_text: str, func_name: str,
                           preconditions: list[dict]) -> str:
    """Insert __builtin_assume(param op value) at the top of the function body.

    Clam's Crab-LLVM respects @llvm.assume (what __builtin_assume lowers to),
    adding it as a hard constraint at the entry block.  This prunes infeasible
    paths (e.g. maxlen < 0) so the octagon join at exit can prove relational
    bounds like *out_key_len ≤ maxlen.
    """
    if not preconditions:
        return c_text
    m = re.search(
        re.escape(func_name) + r'\s*\([^{]*\)\s*\{',
        c_text, re.DOTALL
    )
    if not m:
        return c_text
    assumes = "".join(
        f"\n    __builtin_assume({p['param']} {p['op']} {p['value']});"
        for p in preconditions
    )
    pos = m.end()
    return c_text[:pos] + assumes + c_text[pos:]


# ── Clam name ↔ source name mapping ──────────────────────────────────────────

def _find_scalar_params(ir_text: str, func_name: str) -> list[tuple[str, str]]:
    """Return [(ir_type, ssa_name)] for non-pointer params of func_name."""
    m = re.search(
        r'define\b[^@]*@' + re.escape(func_name) + r'\(([^)]*)\)',
        ir_text
    )
    if not m:
        return []
    result = []
    for tok in m.group(1).split(","):
        tok = tok.strip()
        pm = re.match(r'(i\d+)\s+%(\w[\w\.]*)', tok)  # scalar: "i32 %maxlen"
        if pm:
            result.append((pm.group(1), pm.group(2)))
    return result


def _clam_param_names(clam_out: str, func_name: str) -> list[str]:
    """Return ordered list of @V_N names from Clam's function declaration."""
    m = re.search(
        r'declare\s+' + re.escape(func_name) + r'\(([^)]*)\)',
        clam_out
    )
    if not m:
        return []
    result = []
    for tok in m.group(1).split(","):
        tok = tok.strip()
        pm = re.match(r'(@[\w\.]+)', tok)
        if pm:
            result.append(pm.group(1))
    return result


def _build_clam_name_map(clam_out: str, ir_text: str,
                          func_name: str) -> dict[str, str]:
    """Return {clam_name: source_param_name} for scalar parameters.

    Clam renames scalar params to @V_N in its declaration and to arg1/arg2/...
    in invariants.  We correlate them with the LLVM IR's SSA names (which keep
    the original source names due to -fno-discard-value-names) by position.

    Example for hash_payload(i8* key, i32 maxlen, i32* out_key_len):
      IR scalar params in order: [(i32, maxlen)]
      Clam declaration:  declare hash_payload(@V_6:int32)
      Result: {@V_6: maxlen, arg1: maxlen}
    """
    ir_scalars   = _find_scalar_params(ir_text, func_name)
    clam_scalars = _clam_param_names(clam_out, func_name)
    mapping: dict[str, str] = {}
    for i, (_, src_name) in enumerate(ir_scalars):
        if i < len(clam_scalars):
            mapping[clam_scalars[i]] = src_name   # @V_6 → maxlen
        mapping[f"arg{i + 1}"] = src_name          # arg1  → maxlen
    return mapping


# ── LLVM IR helpers ───────────────────────────────────────────────────────────

def _compile_to_opt_bc(source: Path, extra_cflags: list[str],
                        tmpdir: Path) -> Optional[Path]:
    bc     = tmpdir / f"{source.stem}.bc"
    opt_bc = tmpdir / f"{source.stem}.opt.bc"

    r = subprocess.run(
        [CLANG, "-O0", "-g",
         "-Xclang", "-disable-O0-optnone",
         "-fno-discard-value-names",
         "-emit-llvm", "-c",
         str(source), "-o", str(bc)]
        + extra_cflags,
        capture_output=True, text=True
    )
    if r.returncode != 0:
        sys.stderr.write(f"[ir_analyzer] clang error:\n{r.stderr}\n")
        return None

    r2 = subprocess.run(
        [OPT, "-mem2reg", "-instcombine", "-simplifycfg", str(bc), "-o", str(opt_bc)],
        capture_output=True, text=True
    )
    if r2.returncode != 0:
        sys.stderr.write(f"[ir_analyzer] opt error:\n{r2.stderr}\n")
        return None

    return opt_bc


def _bc_to_ir(bc: Path) -> str:
    r = subprocess.run([DIS, str(bc), "-o", "-"], capture_output=True, text=True)
    return r.stdout


def _find_func_params(ir_text: str, func_name: str) -> list[tuple[str, str]]:
    """Return [(ir_type, ssa_name)] for all params of func_name."""
    m = re.search(
        r'define\b[^@]*@' + re.escape(func_name) + r'\(([^)]*)\)',
        ir_text
    )
    if not m:
        return []
    params = []
    for tok in m.group(1).split(","):
        tok = tok.strip()
        # e.g. "i8* %payload"  or  "%struct.bpf_map_def* %tbl"
        pm = re.match(r'(.*?\*)\s+%(\w[\w\.]*)', tok)
        if pm:
            params.append((pm.group(1).strip(), pm.group(2)))
    return params


def _stores_to_params(ir_text: str, func_name: str,
                       param_names: set[str]) -> dict[str, str]:
    """Find `store TYPE %val, TYPE* %param` in func body.
    Returns {param_name: stored_ssa_var}.
    """
    in_fn = False
    fn_open = re.compile(r'define\b.*@' + re.escape(func_name) + r'\(')
    stores: dict[str, str] = {}

    for line in ir_text.splitlines():
        if not in_fn:
            if fn_open.search(line):
                in_fn = True
            continue
        if line.strip() == "}":
            break
        # store i32 %val, i32* %param_name, align N
        m = re.match(
            r'\s*store\s+\S+\s+%(\w[\w\.]*),\s+\S+\*\s+%(\w[\w\.]*)',
            line
        )
        if m:
            stored_var, target = m.group(1), m.group(2)
            if target in param_names:
                stores[target] = stored_var
    return stores


# ── C-source helpers for type mapping ─────────────────────────────────────────

def _c_pointer_params(c_text: str, func_name: str) -> dict[str, str]:
    """Parse the C function signature; return {param_name: pointee_c_type}
    for pointer-typed params.

    Handles multi-line signatures and common C type patterns.
    """
    # Collect the full signature text between func_name( and the first {
    m = re.search(
        re.escape(func_name) + r'\s*\(([^{]+?)\)\s*\{',
        c_text, re.DOTALL
    )
    if not m:
        return {}

    params_str = m.group(1)
    result: dict[str, str] = {}
    for param in re.split(r',\s*', params_str):
        param = param.strip().rstrip()
        if not param:
            continue
        # Remove trailing newlines / whitespace
        param = re.sub(r'\s+', ' ', param)
        # Must have a * to be a pointer
        if '*' not in param:
            continue
        # Last word is the name; everything before (without trailing *) is type
        words = param.rsplit(None, 1)
        if len(words) < 2:
            continue
        name = words[1].lstrip('*')
        type_part = words[0].rstrip() + (' *' if '*' in words[1] else '')
        # Strip any leading * from name that belonged to type
        result[name] = type_part.strip()
    return result


# ── Public API ────────────────────────────────────────────────────────────────

@dataclass
class SideEffect:
    param: str                   # C/IR name of the output pointer param
    c_type: str                  # C type of the param (e.g. "unsigned int *")
    stored_var: str              # SSA name of value stored through it
    upper: Optional[int]         # Clam constant upper bound (None = unbounded)
    lower: Optional[int]         # Clam constant lower bound (None = unbounded)
    upper_expr: Optional[str] = None  # Source param name for relational bound
                                      # e.g. "maxlen" → klee_assume(se <= maxlen)


def analyze(
    source: Path,
    func_name: str,
    extra_cflags: list[str] = field(default_factory=list),
    tmpdir: Optional[Path] = None,
    preconditions: Optional[list[dict]] = None,
) -> list[SideEffect]:
    """Run Stages 2a + 2b; return SideEffect list (may be empty)."""
    own_tmpdir = tmpdir is None
    if own_tmpdir:
        import tempfile as _tmp
        _td = _tmp.TemporaryDirectory()
        tmpdir = Path(_td.name)

    try:
        return _analyze(source, func_name, list(extra_cflags), tmpdir,
                        preconditions or [])
    finally:
        if own_tmpdir:
            _td.cleanup()


def _analyze(source: Path, func_name: str,
             extra_cflags: list[str], tmpdir: Path,
             preconditions: list[dict]) -> list[SideEffect]:
    c_text = source.read_text()

    # Always include the source file's own directory so local #include "..." works.
    src_inc = f"-I{source.parent}"
    if src_inc not in extra_cflags:
        extra_cflags = [src_inc] + extra_cflags

    # If preconditions supplied, inject __builtin_assume and compile modified src.
    if preconditions:
        modified = _inject_preconditions(c_text, func_name, preconditions)
        mod_src = tmpdir / f"{source.stem}_pre.c"
        mod_src.write_text(modified)
        compile_src = mod_src
    else:
        compile_src = source

    opt_bc = _compile_to_opt_bc(compile_src, extra_cflags, tmpdir)
    if opt_bc is None:
        sys.stderr.write("[ir_analyzer] compilation failed; returning no side effects\n")
        return []

    ir_text = _bc_to_ir(opt_bc)
    ptr_params = _find_func_params(ir_text, func_name)
    if not ptr_params:
        return []

    param_names = {name for _, name in ptr_params}
    stores = _stores_to_params(ir_text, func_name, param_names)
    if not stores:
        return []   # no pointer params are written → no side effects

    # Clam bounds.
    clam_bounds: dict[str, dict] = {}
    clam_name_map: dict[str, str] = {}
    if CLAM.exists():
        r = subprocess.run(
            [str(CLAM), str(opt_bc),
             "--crab-dom=soct", "--crab-print-invariants"],
            capture_output=True, text=True
        )
        clam_out = r.stdout + r.stderr
        clam_bounds   = _parse_clam_invariants(clam_out, func_name)
        clam_name_map = _build_clam_name_map(clam_out, ir_text, func_name)
    else:
        sys.stderr.write("[ir_analyzer] Clam not found; side-effect bounds will be unbounded\n")

    c_ptypes = _c_pointer_params(c_text, func_name)

    effects = []
    for ir_type, ir_name in ptr_params:
        if ir_name not in stores:
            continue
        stored = stores[ir_name]
        b = clam_bounds.get(stored, {})

        # Resolve relational upper bound: Clam name → source parameter name.
        # Two cases:
        #   1. Clam used its own alias (arg1, @V_6) → look up clam_name_map
        #   2. Clam used the actual LLVM SSA name (e.g. "maxlen" due to
        #      -fno-discard-value-names) → use directly as it already IS the source name
        upper_expr: Optional[str] = None
        if "upper_expr" in b:
            clam_param = b["upper_expr"]
            src_param  = clam_name_map.get(clam_param)
            if src_param is None and clam_param.replace(".", "_").isidentifier():
                src_param = clam_param   # SSA name == source name
            if src_param:
                upper_expr = src_param

        effects.append(SideEffect(
            param=ir_name,
            c_type=c_ptypes.get(ir_name, ir_type),
            stored_var=stored,
            upper=b.get("upper"),
            lower=b.get("lower"),
            upper_expr=upper_expr,
        ))

    return effects
