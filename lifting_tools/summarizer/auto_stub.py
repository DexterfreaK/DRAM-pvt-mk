#!/usr/bin/env python3
"""auto_stub.py — Strategy A: automatic stub detector + KLEE rollback driver.

Algorithm:
  Phase 0 — Static triage: run detect.py on the input .bc to rank candidates.
  Phase 1 — Baseline KLEE run: run KLEE with --max-time=<timeout>.
             If KLEE finishes without timeout, report success and exit.
  Phase 2 — Stub injection loop (per ranked candidate in source_map.json):
             a. Run summarize.py to generate <func>_stub.c
             b. Compile <func>_stub.c → stub.bc
             c. Build stub_variant.bc using:
                  llvm-link-14 --override=stub.bc <original.bc> -o stub_variant.bc
             d. Run KLEE on stub_variant.bc with the same timeout
             e. Accept if: path_count decreases AND verdict is compatible
             f. Reject if: path_count increases (counterproductive stub)
  Phase 3 — Report comparison table and exit.

Source map format (source_map.json):
  {
    "func_name": {
      "source": "path/to/func.c",    # relative to the BC directory (or absolute)
      "defines": ["K=12", "N=3250"]  # -D flags for clang compilation
    }
  }

The "rollback" is: kill the struggling KLEE run (--max-time handled by KLEE
itself), recompile with stub via llvm-link --override, restart KLEE from
scratch on the new BC. No KLEE state is transferred between runs.

Usage:
  python3 auto_stub.py \\
      --bc examples/bmc-cache/bmc_e2e_real.bc \\
      --source-map examples/bmc-cache/source_map.json \\
      --klee-inc /root/DRACO-pvt/klee/include \\
      --timeout 60 \\
      [--path-threshold 500] \\
      [--max-candidates 3]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Allow running directly.
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from lifting_tools.summarizer import detect as _detect_mod

CLANG    = "clang-13"
LLVMLINK = "llvm-link-14"
KLEE     = "/root/DRACO-pvt/klee/build/bin/klee"
KLEE_INC_DEFAULT = "/root/DRACO-pvt/klee/include"

CFLAGS = [
    "-O0", "-g",
    "-Xclang", "-disable-O0-optnone",
    "-fno-discard-value-names",
    "-emit-llvm", "-c",
]


# ── Result parsing ────────────────────────────────────────────────────────────

@dataclass
class KleeResult:
    completed_paths: int
    partial_paths: int
    wall_time: float
    verdict: str   # "SAFE", "UNSAFE", "TIMEOUT", "ERROR", "UNKNOWN"
    klee_dir: str


def _run_klee(bc: Path, timeout_s: int, outdir: Path,
              extra_flags: list[str] | None = None) -> KleeResult:
    """Run KLEE on a .bc file; return parsed KleeResult."""
    # Create the parent dir so KLEE can write the output dir itself.
    # Do NOT pre-create outdir — KLEE refuses to use a pre-existing directory.
    outdir.parent.mkdir(parents=True, exist_ok=True)
    if outdir.exists():
        import shutil; shutil.rmtree(outdir)
    cmd = [
        KLEE,
        f"--output-dir={outdir}",
        f"--max-time={timeout_s}s",
        "--search=dfs",
        "--solver-backend=z3",
        "--silent-klee-assume",
    ]
    if extra_flags:
        cmd += extra_flags
    cmd.append(str(bc))

    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    wall_time = time.time() - t0

    # Parse klee-last/info (KLEE writes info even for incomplete runs).
    info_path = outdir / "info"
    completed = 0
    partial   = 0
    if info_path.exists():
        info = info_path.read_text()
        m = re.search(r"completed paths\s*=\s*(\d+)", info)
        if m:
            completed = int(m.group(1))
        m = re.search(r"partially completed paths\s*=\s*(\d+)", info)
        if m:
            partial = int(m.group(1))

    # Determine verdict.
    msgs_path = outdir / "messages.txt"
    verdict = "UNKNOWN"
    if msgs_path.exists():
        msgs = msgs_path.read_text()
        if "HaltTimer" in msgs:
            verdict = "TIMEOUT"
        elif "ASSERTION FAIL" in msgs or "INVALID" in msgs:
            verdict = "UNSAFE"
        elif r.returncode == 0 or "done" in (r.stdout + r.stderr).lower():
            verdict = "SAFE"
    elif r.returncode == 0:
        verdict = "SAFE"

    return KleeResult(
        completed_paths=completed,
        partial_paths=partial,
        wall_time=wall_time,
        verdict=verdict,
        klee_dir=str(outdir),
    )


# ── Stub compilation + linking ────────────────────────────────────────────────

def _compile_stub(stub_c: Path, klee_inc: str, defines: list[str],
                  out_bc: Path, source_dir: Path | None = None) -> bool:
    """Compile a stub .c file to LLVM bitcode."""
    # Include the original source's directory so that relative #include "..."
    # headers (e.g. "synth_common.h") resolve correctly.
    extra_inc = [f"-I{source_dir}"] if source_dir else []
    cmd = (
        [CLANG]
        + CFLAGS
        + [f"-I{klee_inc}"]
        + extra_inc
        + [f"-D{d}" for d in defines]
        + [str(stub_c), "-o", str(out_bc)]
    )
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(f"[auto_stub] clang error:\n{r.stderr}\n")
        return False
    return True


def _link_with_stub_override(original_bc: Path, stub_bc: Path,
                             out_bc: Path) -> bool:
    """Link original BC with stub BC, letting stub override the real function.

    Uses llvm-link-14 --override which gives precedence to the stub module.
    """
    cmd = [LLVMLINK, f"--override={stub_bc}", str(original_bc), "-o", str(out_bc)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(f"[auto_stub] llvm-link error:\n{r.stderr}\n")
        return False
    return True


# ── Core logic ────────────────────────────────────────────────────────────────

def _is_improvement(baseline: KleeResult, stub: KleeResult,
                    path_threshold: int) -> tuple[bool, str]:
    """Return (accept, reason)."""
    # If baseline was TIMEOUT or explosion (paths > threshold): any non-timeout
    # result with fewer paths is an improvement.
    if baseline.verdict == "TIMEOUT":
        if stub.verdict == "TIMEOUT":
            return False, "stub still timed out"
        if stub.verdict == "UNSAFE":
            return True, ("stub finished (UNSAFE — possible false alarm from "
                          "over-approximation; validate with real implementation)")
        return True, f"timeout rescued: {baseline.completed_paths} paths → {stub.completed_paths} paths"

    # If baseline completed SAFE and stub is UNSAFE: the stub introduced false
    # positives — an over-approximate stub fires assertions the real function
    # never would.  Reject outright even if path count dropped.
    if baseline.verdict == "SAFE" and stub.verdict == "UNSAFE":
        return False, ("stub is UNSAFE while baseline was SAFE — "
                       "over-approximate stub introduced false positives")

    # If baseline completed: require strictly fewer paths.
    if stub.completed_paths >= baseline.completed_paths:
        return False, (f"path count did not decrease "
                       f"({baseline.completed_paths} → {stub.completed_paths}); "
                       "stub may introduce more downstream symbolic state")

    pct = int(100 * (1 - stub.completed_paths / max(baseline.completed_paths, 1)))
    return True, f"{baseline.completed_paths} → {stub.completed_paths} paths ({pct}% reduction)"


def run(
    bc: Path,
    source_map: dict,
    klee_inc: str,
    timeout: int,
    path_threshold: int,
    max_candidates: int,
    work_dir: Path,
    verbose: bool,
    extra_klee_flags: list[str] | None = None,
) -> int:
    """Main loop. Returns exit code (0 = success)."""

    # ── Phase 0: static triage ────────────────────────────────────────────────
    print(f"\n[auto_stub] Phase 0 — Static triage: {bc}")
    candidates = _detect_mod.detect(bc, include_inline=False)
    if not candidates:
        print("[auto_stub] No path-explosive candidates detected by static analysis.")
        print("            Run with --all to include entry-point functions (inline).")
    else:
        print(f"[auto_stub] Top candidates (by explosion score):")
        for c in candidates[:max_candidates]:
            print(f"  {c.func_name:30s}  axis={c.axis}  score={c.score:5d}  {c.detail}")

    # ── Phase 1: baseline KLEE run ────────────────────────────────────────────
    klee_flags = extra_klee_flags or []

    print(f"\n[auto_stub] Phase 1 — Baseline KLEE run (timeout={timeout}s) …")
    baseline_dir = work_dir / "klee_baseline"
    baseline = _run_klee(bc, timeout, baseline_dir, extra_flags=klee_flags)
    _print_result("  baseline", baseline)

    # If baseline finishes and is under the path threshold, nothing to do.
    if (baseline.verdict not in ("TIMEOUT", "ERROR")
            and baseline.completed_paths <= path_threshold):
        print(f"\n[auto_stub] Baseline finished cleanly "
              f"({baseline.completed_paths} paths ≤ threshold {path_threshold}). "
              "No stub needed.")
        return 0

    if not candidates:
        print("\n[auto_stub] Baseline struggled but no candidates found. "
              "Consider --path-threshold or running detect.py manually.")
        return 1

    # ── Phase 2: stub injection loop ──────────────────────────────────────────
    print(f"\n[auto_stub] Phase 2 — Stub injection ({len(candidates[:max_candidates])} candidates)")

    accepted: list[tuple[str, KleeResult, str]] = []  # (func_name, result, reason)

    for i, cand in enumerate(candidates[:max_candidates]):
        func_name = cand.func_name
        print(f"\n  [{i+1}] Trying stub for: {func_name}  (axis={cand.axis})")

        if func_name not in source_map:
            print(f"       SKIP — not in source_map.json (add an entry to enable)")
            continue

        entry = source_map[func_name]
        source_rel    = entry.get("source", "")
        defines       = entry.get("defines", [])
        preconditions = entry.get("preconditions", [])

        # Resolve source path (relative to BC directory, or absolute).
        source_path = Path(source_rel)
        if not source_path.is_absolute():
            source_path = bc.parent / source_rel
        if not source_path.exists():
            print(f"       SKIP — source not found: {source_path}")
            continue

        # Step 2a: generate stub.c via summarize.py.
        stub_c = work_dir / f"{func_name}_stub.c"
        print(f"       Generating stub: {stub_c.name} …")
        summarize_argv = [
            sys.executable,
            str(Path(__file__).parent / "summarize.py"),
            "--source", str(source_path),
            "--function", func_name,
            "--output", str(stub_c),
            "--klee-inc", klee_inc,
        ]
        if defines:
            summarize_argv += ["--defines"] + defines
        if preconditions:
            # Convert [{"param":"maxlen","op":">=","value":1}] → ["maxlen>=1"]
            summarize_argv += ["--preconditions"] + [
                f"{p['param']}{p['op']}{p['value']}" for p in preconditions
            ]
        if verbose:
            summarize_argv.append("--verbose")
        r = subprocess.run(summarize_argv, capture_output=not verbose, text=True)
        if r.returncode != 0 or not stub_c.exists():
            print(f"       FAIL — summarize.py returned {r.returncode}")
            if not verbose:
                sys.stderr.write(r.stderr + "\n")
            continue

        # Step 2b: compile stub.c → stub.bc.
        stub_bc = work_dir / f"{func_name}_stub.bc"
        print(f"       Compiling stub BC …")
        if not _compile_stub(stub_c, klee_inc, defines, stub_bc,
                             source_dir=source_path.parent):
            print("       FAIL — stub compilation failed")
            continue

        # Step 2c: link stub_bc into original BC via --override.
        variant_bc = work_dir / f"variant_{func_name}.bc"
        print(f"       Linking variant BC (llvm-link --override) …")
        if not _link_with_stub_override(bc, stub_bc, variant_bc):
            print("       FAIL — llvm-link override failed")
            continue

        # Step 2d: run KLEE on variant.
        print(f"       Running KLEE on stub variant (timeout={timeout}s) …")
        stub_dir = work_dir / f"klee_stub_{func_name}"
        stub_result = _run_klee(variant_bc, timeout, stub_dir, extra_flags=klee_flags)
        _print_result(f"       stub({func_name})", stub_result)

        # Step 2e: verdict check.
        ok, reason = _is_improvement(baseline, stub_result, path_threshold)
        if ok:
            print(f"       ACCEPT: {reason}")
            accepted.append((func_name, stub_result, reason))
        else:
            print(f"       REJECT: {reason}")

    # ── Phase 3: report ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("[auto_stub] Summary")
    print("=" * 70)
    _print_result("  Baseline", baseline)
    if accepted:
        fname, res, reason = accepted[0]
        _print_result(f"  Best stub ({fname})", res)
        print(f"  Improvement: {reason}")
        if len(accepted) > 1:
            print(f"  Also accepted: {', '.join(f for f, _, _ in accepted[1:])}")
        print(f"\n  Stub variant BC: {work_dir}/variant_{fname}.bc")
        return 0
    else:
        print("  No beneficial stub found.")
        if candidates:
            print("  Candidates not in source_map.json:")
            for c in candidates[:max_candidates]:
                if c.func_name not in source_map:
                    print(f"    {c.func_name} (axis={c.axis}, score={c.score})")
            print("  Add entries to source_map.json to enable auto-stubbing.")
        return 1


def _print_result(label: str, r: KleeResult) -> None:
    print(f"{label:40s}  verdict={r.verdict:7s}  "
          f"paths={r.completed_paths:6d}+{r.partial_paths}partial  "
          f"time={r.wall_time:.1f}s")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Automatic stub detector + KLEE rollback driver (Strategy A).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--bc",             required=True, type=Path,
                    help="Input .bc file to verify")
    ap.add_argument("--source-map",     required=True, type=Path,
                    help="JSON file mapping func_name → {source, defines}")
    ap.add_argument("--klee-inc",       default=KLEE_INC_DEFAULT,
                    help=f"KLEE headers directory (default: {KLEE_INC_DEFAULT})")
    ap.add_argument("--timeout",        type=int, default=60,
                    help="KLEE timeout in seconds (default: 60)")
    ap.add_argument("--path-threshold", type=int, default=500,
                    help="Path count above which we trigger stub search (default: 500)")
    ap.add_argument("--max-candidates", type=int, default=3,
                    help="Try at most N stub candidates (default: 3)")
    ap.add_argument("--klee-flags",     default="", metavar="FLAGS",
                    help="Extra KLEE flags as a single quoted string "
                         "(e.g. '-kdalloc -libc=uclibc --external-calls=all')")
    ap.add_argument("--work-dir",       type=Path, default=None,
                    help="Working directory for intermediate files (default: temp dir)")
    ap.add_argument("--keep",           action="store_true",
                    help="Keep working directory after exit")
    ap.add_argument("--verbose",        action="store_true")
    args = ap.parse_args()

    if not args.bc.exists():
        print(f"error: BC not found: {args.bc}", file=sys.stderr)
        return 1
    if not args.source_map.exists():
        print(f"error: source map not found: {args.source_map}", file=sys.stderr)
        return 1

    source_map = json.loads(args.source_map.read_text())

    import shlex as _shlex
    # source_map.json may include a "_klee_flags" top-level key as a convenience.
    map_klee_flags = _shlex.split(source_map.pop("_klee_flags", ""))

    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=True)
        work_dir = args.work_dir
        td = None
    else:
        td = tempfile.TemporaryDirectory(prefix="auto_stub_")
        work_dir = Path(td.name)

    extra_klee_flags = (map_klee_flags
                        + (_shlex.split(args.klee_flags) if args.klee_flags else []))

    try:
        rc = run(
            bc=args.bc.resolve(),
            source_map=source_map,
            klee_inc=args.klee_inc,
            timeout=args.timeout,
            path_threshold=args.path_threshold,
            max_candidates=args.max_candidates,
            work_dir=work_dir,
            verbose=args.verbose,
            extra_klee_flags=extra_klee_flags,
        )
    finally:
        if td and not args.keep:
            td.cleanup()

    return rc


if __name__ == "__main__":
    sys.exit(main())
