#!/usr/bin/env python3
"""summarize.py — auto-generate a KLEE stub for a path-explosive function.

Three-stage pipeline:
  Stage 1 (deferred): function identification — pass --function explicitly.
  Stage 2: side-effect analysis via Clam zones domain.
  Stage 3: return-value bound via known-bits ⊗ interval abstract interpreter.

Usage examples:

  # Test case #1 — bmc_hash (path explosion, side effects, non-power-of-2 mod)
  python3 summarize.py \\
      --source examples/bmc_ai_demo/bmc_hash_mini.c \\
      --function hash_keys_mini \\
      --defines KEY_BYTES=12 TABLE_SIZE=3250 \\
      --klee-inc /root/DRACO-pvt/klee/include \\
      --output examples/bmc_ai_demo/bmc_hash_stub_gen.c

  # Test case #2 — do_gather (solver cost, no side effects, power-of-2 mask)
  python3 summarize.py \\
      --source examples/symbolic_addr_gather/do_gather.c \\
      --function do_gather \\
      --defines CHAIN=128 TBL_SIZE=256 \\
      --klee-inc /root/DRACO-pvt/klee/include \\
      --extra-cflags="-I examples/symbolic_addr_gather" \\
      --output examples/symbolic_addr_gather/do_gather_stub_gen.c
"""

import argparse
import re
import sys
import tempfile
from pathlib import Path

# Allow running directly (not as a package).
if __name__ == "__main__":
    import os
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from lifting_tools.summarizer import ir_analyzer, hash_bounds, stub_emitter


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Auto-generate a KLEE stub via abstract interpretation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--source",   required=True, type=Path,
                   help="C source file containing the target function.")
    p.add_argument("--function", required=True,
                   help="Name of the function to summarize.")
    p.add_argument("--output",   required=True, type=Path,
                   help="Output path for the generated stub .c file.")
    p.add_argument("--klee-inc", default="/root/DRACO-pvt/klee/include",
                   help="Path to KLEE headers (for #include <klee/klee.h>).")
    p.add_argument("--defines",  nargs="*", default=[],
                   metavar="NAME=VAL",
                   help="Extra -D defines to pass to clang (e.g. KEY_BYTES=12).")
    p.add_argument("--extra-cflags", default="",
                   help="Additional clang flags as a single quoted string.")
    p.add_argument("--no-clam",  action="store_true",
                   help="Skip Stage 2 Clam analysis (no side-effect bounds).")
    p.add_argument("--preconditions", nargs="*", default=[], metavar="PARAM>=VALUE",
                   help="Parameter preconditions injected as __builtin_assume "
                        "(e.g. maxlen>=1).  Enables relational side-effect bounds.")
    p.add_argument("--verbose",  action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    source: Path = args.source.resolve()
    if not source.exists():
        print(f"error: source file not found: {source}", file=sys.stderr)
        return 1

    # Build extra cflags for compilation.
    extra = [f"-D{d}" for d in args.defines]
    if args.extra_cflags:
        import shlex
        extra += shlex.split(args.extra_cflags)

    print(f"[summarize] source   : {source}")
    print(f"[summarize] function : {args.function}")

    with tempfile.TemporaryDirectory(prefix="summarizer_") as td:
        tmpdir = Path(td)

        # ── Stage 2: side effects ─────────────────────────────────────────
        if args.no_clam:
            effects = []
            print("[summarize] Stage 2: skipped (--no-clam)")
        else:
            print("[summarize] Stage 2: running Clam zones analysis…")
            # Parse --preconditions "maxlen>=1" → [{"param":"maxlen","op":">=","value":1}]
            preconditions = []
            for raw in (args.preconditions or []):
                pm = re.match(r'(\w+)\s*(>=|<=|>|<|==)\s*(-?\d+)', raw)
                if pm:
                    preconditions.append({"param": pm.group(1),
                                          "op":    pm.group(2),
                                          "value": int(pm.group(3))})
            effects = ir_analyzer.analyze(
                source=source,
                func_name=args.function,
                extra_cflags=extra,
                tmpdir=tmpdir,
                preconditions=preconditions,
            )
            if effects:
                for fx in effects:
                    if fx.upper_expr is not None:
                        bound_str = f"[{fx.lower or 0}, {fx.upper_expr}]  (relational)"
                    elif fx.upper is not None:
                        bound_str = f"[{fx.lower or 0}, {fx.upper}]"
                    else:
                        bound_str = "unbounded"
                    print(f"  side effect: *{fx.param} ({fx.c_type}) "
                          f"stored_var={fx.stored_var} bound={bound_str}")
            else:
                print("  (no side effects found)")

        # ── Stage 3: return-value bound ───────────────────────────────────
        print("[summarize] Stage 3: computing return-value bound…")

        # Ensure opt.bc exists for the IR scan strategy — Stage 2 may have
        # produced it already; if not (e.g. --no-clam), compile now.
        import subprocess
        opt_bc = tmpdir / f"{source.stem}.opt.bc"
        if not opt_bc.exists():
            ir_analyzer._compile_to_opt_bc(source, extra, tmpdir)

        ir_text = None
        if opt_bc.exists():
            r = subprocess.run(
                ["llvm-dis-14", str(opt_bc), "-o", "-"],
                capture_output=True, text=True
            )
            ir_text = r.stdout if r.returncode == 0 else None

        bound = hash_bounds.analyze(
            source=source,
            func_name=args.function,
            ir_text=ir_text,
        )
        print(f"  return bound: mod_type={bound.mod_type}  "
              f"mod_val={bound.mod_val}  → [0, {bound.max}]")

        # ── Emit stub ─────────────────────────────────────────────────────
        print("[summarize] Emitting stub…")
        stub_emitter.emit(
            source=source,
            func_name=args.function,
            side_effects=effects,
            return_bound=bound,
            out=args.output,
            klee_inc=args.klee_inc,
        )

    print(f"[summarize] done → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
