#!/usr/bin/env python3
"""detect.py — Stage 1: rank LLVM IR functions by KLEE path-explosion risk.

Four explosion axes detected from LLVM IR (obtained via llvm-dis-14):

  A: per-byte loop — loop + load i8 from pointer + icmp+br per iter
     Score = estimated_loop_bound × branch_pairs_in_loop × 2
     Catches: bmc_hash_keys (FNV byte loop over 12 bytes → 3^12 paths)

  C: nested symbolic lookups — loop + bpf_map_lookup_elem where the result
     feeds back as the key for the next iteration
     Score = loop_bound_estimate × lookup_count²
     Catches: do_gather / xdp_main gather loops (Z3 solver cost explosion)

  D: conditional branch per loop iteration, any type (including csum-fold style)
     Loop present + icmp+br inside the body, even without byte loads
     Score = loop_bound × branch_pairs
     Catches: csum_fold_helper (4-iter loop, 1 branch per iter → 2⁴ paths/call)

  E: flat sequential byte classifier — no loop, many byte equality checks
     load i8 → zext to i32 → icmp eq i32 %val, CONST → br i1, repeated
     Score = number of (icmp eq, br i1) pairs
     Catches: compute_message_type (30+ payload byte comparisons, no loop)
     Note: clang -O0 promotes i8 → i32 before icmp, so pattern is icmp eq i32

is_inline=True is set when the explosion is detected inside a top-level BPF
entry function (e.g. xdp_main, tc_main, or __stub__-prefixed functions).
These cannot be auto-stubbed without manual extraction or the KLEE runtime
budget (Strategy B). Use --all to include them in output.

Usage:
  python3 detect.py <bc_or_ll_file> [--top N] [--min-score N] [--json] [--all]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


LLVM_DIS = "llvm-dis-14"

# Functions that are BPF entry points and cannot be directly stubbed.
_ENTRY_SUFFIXES = ("_main", "_prog", "_filter", "_kern")
_ENTRY_NAMES    = {"main", "xdp_main", "tc_main", "sk_main"}


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class Candidate:
    func_name: str
    axis: str        # "A", "C", or "D"
    score: int       # estimated explosion severity (higher = worse)
    is_inline: bool  # True = explosion is inside a top-level / entry function
    detail: str      # human-readable evidence


# ── IR parsing helpers ────────────────────────────────────────────────────────

def _disassemble(path: Path) -> str:
    """Disassemble a .bc file to LLVM IR text; pass .ll files through."""
    if path.suffix == ".ll":
        return path.read_text()
    r = subprocess.run([LLVM_DIS, str(path), "-o", "-"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(f"[detect] llvm-dis-14 failed:\n{r.stderr}\n")
        return ""
    return r.stdout


def _parse_functions(ir_text: str) -> dict[str, list[str]]:
    """Return {func_name: body_lines} for every defined function in the module.
    Excludes declarations (no body) and debug-info intrinsics."""
    funcs: dict[str, list[str]] = {}
    cur_name: str | None = None
    cur_lines: list[str] = []
    brace_depth = 0

    define_re = re.compile(r'^define\b.*@([\w\.]+)\s*\(')

    for line in ir_text.splitlines():
        if cur_name is None:
            m = define_re.match(line)
            if m:
                cur_name = m.group(1)
                cur_lines = [line]
                brace_depth = line.count("{") - line.count("}")
        else:
            cur_lines.append(line)
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                funcs[cur_name] = cur_lines
                cur_name = None
                cur_lines = []

    return funcs


def _is_entry(func_name: str) -> bool:
    """True if func_name looks like a BPF entry point."""
    if func_name in _ENTRY_NAMES:
        return True
    return any(func_name.endswith(s) for s in _ENTRY_SUFFIXES)


# ── Axis detectors ────────────────────────────────────────────────────────────

def _detect_axis_a(func_name: str, lines: list[str]) -> Candidate | None:
    """Axis A: loop with per-byte symbolic branches.

    Requirements:
      - Function has a phi node (back-edge → loop)
      - Function has 'load i8' instructions (byte-level memory access)
      - Function has icmp+br pairs (branching on loaded values)
    """
    body = "\n".join(lines)

    has_loop      = _has_loop(body)
    has_byte_load = bool(re.search(r'\bload i8\b', body))
    icmp_count   = len(re.findall(r'\bicmp\b', body))
    br_i1_count  = len(re.findall(r'\bbr i1\b', body))
    branch_pairs = min(icmp_count, br_i1_count)

    if not (has_loop and has_byte_load and branch_pairs >= 2):
        return None

    # Estimate loop bound from 'icmp [su]lt i32 %var, N' loop guards.
    loop_bound = _estimate_loop_bound(body)

    # Score: each loop iteration can take branch_pairs + 1 paths.
    score = loop_bound * (branch_pairs + 1)
    detail = (f"loop+byte-load: loop={has_loop}, byte_loads=yes, "
              f"branch_pairs={branch_pairs}, est_loop_bound={loop_bound}")
    return Candidate(func_name=func_name, axis="A", score=score,
                     is_inline=_is_entry(func_name), detail=detail)


def _detect_axis_c(func_name: str, lines: list[str]) -> Candidate | None:
    """Axis C: nested symbolic lookups (solver cost explosion).

    Requirements:
      - Function has a phi node (loop) OR multiple bpf_map_lookup_elem calls
      - bpf_map_lookup_elem (or map_lookup_elem) call count >= 1 inside a loop
    """
    body = "\n".join(lines)

    lookup_count = len(re.findall(
        r'call\b.*@(?:bpf_map_lookup_elem|map_lookup_elem|array_lookup_elem)',
        body))

    if lookup_count < 1:
        return None

    has_loop = _has_loop(body)
    if not has_loop and lookup_count < 2:
        # Single lookup outside a loop: not an Axis C target.
        return None

    loop_bound = _estimate_loop_bound(body) if has_loop else 1
    score = (loop_bound * lookup_count) ** 2 // max(lookup_count, 1)

    detail = (f"map_lookups={lookup_count}, loop={has_loop}, "
              f"est_loop_bound={loop_bound}, "
              "solver cost grows as nested symbolic array-select depth")
    return Candidate(func_name=func_name, axis="C", score=score,
                     is_inline=_is_entry(func_name), detail=detail)


def _detect_axis_d(func_name: str, lines: list[str]) -> Candidate | None:
    """Axis D: loop with conditional branch per iteration (no byte-load required).

    Catches short bounded loops with one branch per iteration:
      csum_fold_helper: for (i=0; i<4; i++) { if (csum>>16) ... }
      → 2^4 = 16 paths per call, × call-site count in the program

    Only flags when branch_pairs ≥ 1 AND the loop is present.  Axis A takes
    priority (byte loads), so Axis D fires only when no byte loads are found.
    """
    body = "\n".join(lines)

    has_loop      = _has_loop(body)
    has_byte_load = bool(re.search(r'\bload i8\b', body))

    # Don't duplicate Axis A.
    if has_byte_load:
        return None

    icmp_count  = len(re.findall(r'\bicmp\b', body))
    br_i1_count = len(re.findall(r'\bbr i1\b', body))
    branch_pairs = min(icmp_count, br_i1_count)

    if not (has_loop and branch_pairs >= 1):
        return None

    loop_bound = _estimate_loop_bound(body)
    # Each iteration doubles the number of paths.
    score = (2 ** min(loop_bound, 16)) * branch_pairs  # cap at 2^16 for ranking
    detail = (f"loop+branch (no byte loads): loop={has_loop}, "
              f"branch_pairs={branch_pairs}, est_loop_bound={loop_bound}, "
              f"est_paths_per_call=2^{min(loop_bound, 16)}")
    return Candidate(func_name=func_name, axis="D", score=score,
                     is_inline=_is_entry(func_name), detail=detail)


def _detect_axis_e(func_name: str, lines: list[str]) -> Candidate | None:
    """Axis E: flat sequential byte classifier — no loop, many byte equality checks.

    Pattern (clang -O0 emits this for multi-field header classifiers):
      load i8, i8* %arrayidx   →  byte from symbolic buffer
      %conv = zext i8 to i32   →  promotion to i32
      icmp eq i32 %conv, N     →  equality check against a literal
      br i1 …                  →  fork: match / no-match

    Each (icmp eq, br i1) pair is one independent fork on a symbolic input.
    Path count ≈ number of pairs (sequential, not exponential), but 20-40
    comparisons in a single function is still a significant explosion.

    Distinguishing from Axis A: Axis A requires a loop; Axis E explicitly
    requires no loop. They cannot fire on the same function.
    """
    body = "\n".join(lines)

    # Must not have a loop — Axis A handles loop+byte-load.
    if _has_loop(body):
        return None

    has_byte_load = bool(re.search(r'\bload i8\b', body))
    if not has_byte_load:
        return None

    # icmp eq on any integer type covers i8, i16, i32 (clang promotes i8→i32)
    icmp_eq_count = len(re.findall(r'\bicmp eq\b', body))
    br_i1_count   = len(re.findall(r'\bbr i1\b', body))
    byte_cmp_pairs = min(icmp_eq_count, br_i1_count)

    if byte_cmp_pairs < 5:
        return None

    score = byte_cmp_pairs  # one path fork per comparison pair
    detail = (f"flat byte classifier: no loop, load_i8=yes, "
              f"icmp_eq={icmp_eq_count}, byte_cmp_pairs={byte_cmp_pairs}")
    return Candidate(func_name=func_name, axis="E", score=score,
                     is_inline=_is_entry(func_name), detail=detail)


# ── Loop bound estimator ──────────────────────────────────────────────────────

def _has_loop(body: str) -> bool:
    """True when the function body contains a back-edge (loop).

    Works for both mem2reg IR (phi nodes) and -O0 memory-form IR (no phi nodes)
    by checking three indicators:
      1. phi node — present after mem2reg pass
      2. !llvm.loop metadata — LLVM adds to every loop back-edge regardless of opt
      3. Block-name patterns — clang emits for.cond / while.cond / loop.header etc.
    """
    if re.search(r'\bphi\b', body):
        return True
    if re.search(r'!llvm\.loop', body):
        return True
    if re.search(
        r'\b(?:for\.cond|for\.body|for\.inc|for\.end'
        r'|while\.cond|while\.body|while\.end'
        r'|loop\.header|loop\.body|loop\.latch)\b', body
    ):
        return True
    return False


def _estimate_loop_bound(body: str) -> int:
    """Heuristically extract the loop trip count from 'icmp slt/ult %var, N'."""
    # Match loop-guard comparisons like: icmp slt i32 %i, 251
    m = re.search(r'\bicmp\s+(?:slt|ult|sle|ule)\s+i\d+\s+%[\w\.]+,\s+(\d+)', body)
    if m:
        return int(m.group(1))
    # Try loop-guard of the form: icmp ne %i, N
    m = re.search(r'\bicmp\s+ne\s+i\d+\s+%[\w\.]+,\s+(\d+)', body)
    if m:
        return int(m.group(1))
    return 32  # conservative default if bound not found


# ── Public API ────────────────────────────────────────────────────────────────

def detect(path: Path, include_inline: bool = False) -> list[Candidate]:
    """Analyze a .bc or .ll file; return Candidates ranked by score desc."""
    ir_text = _disassemble(path)
    if not ir_text:
        return []

    functions = _parse_functions(ir_text)
    candidates: list[Candidate] = []

    for func_name, lines in functions.items():
        # Skip KLEE and LLVM intrinsics.
        if func_name.startswith(("llvm.", "klee_", "__klee", "klee__")):
            continue

        # Try axes in priority order (A > C > D > E).
        # A and E are mutually exclusive by loop check, so order between them
        # doesn't matter, but keeping A first is cleaner.
        cand = (_detect_axis_a(func_name, lines)
                or _detect_axis_c(func_name, lines)
                or _detect_axis_d(func_name, lines)
                or _detect_axis_e(func_name, lines))
        if cand is not None:
            candidates.append(cand)

    # Sort: non-inline before inline, then by score descending.
    candidates.sort(key=lambda c: (c.is_inline, -c.score))

    if not include_inline:
        candidates = [c for c in candidates if not c.is_inline]

    return candidates


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Rank LLVM BC functions by KLEE path-explosion risk.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("bc", type=Path, help=".bc or .ll file to analyze")
    ap.add_argument("--top",       type=int, default=10,
                    help="Print top N candidates (default 10)")
    ap.add_argument("--min-score", type=int, default=1,
                    help="Minimum score threshold (default 1)")
    ap.add_argument("--all",       action="store_true",
                    help="Include is_inline=True candidates (entry-point functions)")
    ap.add_argument("--json",      action="store_true",
                    help="Output JSON instead of human-readable table")
    args = ap.parse_args()

    if not args.bc.exists():
        print(f"error: file not found: {args.bc}", file=sys.stderr)
        return 1

    candidates = detect(args.bc, include_inline=args.all)
    candidates = [c for c in candidates if c.score >= args.min_score]
    candidates = candidates[:args.top]

    if not candidates:
        print("No path-explosive candidates found.")
        return 0

    if args.json:
        print(json.dumps([asdict(c) for c in candidates], indent=2))
        return 0

    # Human-readable table.
    print(f"{'FUNCTION':<35} {'AXIS':>4} {'SCORE':>6}  {'INLINE':>6}  DETAIL")
    print("-" * 90)
    for c in candidates:
        inline_flag = "yes" if c.is_inline else "no"
        print(f"{c.func_name:<35} {c.axis:>4} {c.score:>6}  {inline_flag:>6}  {c.detail}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
