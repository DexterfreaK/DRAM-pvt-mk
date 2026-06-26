#!/usr/bin/env python3
"""
triage.py — per-region AI-precision and KLEE-explosion-risk heuristic.

Reads a Clam invariants dump (--crab-print-invariants output) and the
post-mem2reg .ll, and emits a JSON file with a summarize/augment/ignore
decision per loop region. See HEURISTIC.md for the rationale.

Usage:
    triage.py <clam_text> <input.ll> <output.json>

The Clam text is the per-block CFG with `/** INVARIANTS: ({}, {...}) **/`
lines that --crab-print-invariants produces.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

# ---------- Clam invariants parser ----------------------------------------

INV_LINE = re.compile(r"/\*\*\s*INVARIANTS:\s*\((\{[^}]*\}),\s*(\{[^}]*\})\)\s*\*\*/")
BLOCK_HEADER = re.compile(r"^([A-Za-z_][\w\.@]*):\s*$")

def parse_clam_text(path: Path) -> dict[str, dict[str, str]]:
    """
    Returns: {function_name: {block_name: linear_constraint_text}}.

    The first non-empty function declaration in the file determines the
    current function. We only keep the *exit* invariant of each block (the
    one printed after the block body) since that's what flows into the next
    block — and for the loop header that's the post-fixpoint widened bound.
    """
    out: dict[str, dict[str, str]] = defaultdict(dict)
    fn = None
    cur_block = None
    last_inv_for_block: dict[str, str] = {}

    for raw in path.read_text().splitlines():
        line = raw.strip()
        m_decl = re.match(r"^([\w\.@]+):\w+\s+declare\s+([\w\.@]+)\(", line)
        if m_decl:
            fn = m_decl.group(2)
            continue
        m_block = BLOCK_HEADER.match(raw)
        if m_block:
            cur_block = m_block.group(1)
            continue
        m_inv = INV_LINE.search(line)
        if m_inv and fn and cur_block:
            # second group is the linear-constraint set
            last_inv_for_block[(fn, cur_block)] = m_inv.group(2)

    for (fn, blk), inv in last_inv_for_block.items():
        out[fn][blk] = inv
    return out


# ---------- Variable bound extraction --------------------------------------

# A linear constraint set looks like:
#   {key_len.0-off.0 = 0; -key_len.0 <= 0; key_len.0 <= 251; ...}
# We split on `;` and pick out single-variable bounds.

UPPER = re.compile(r"^\s*([\w\.@]+)\s*<=\s*(-?\d+)\s*$")
LOWER = re.compile(r"^\s*-\s*([\w\.@]+)\s*<=\s*(-?\d+)\s*$")

def variable_bounds(inv_set: str) -> dict[str, dict[str, int]]:
    """
    Returns {var: {"upper": int?, "lower": int?}} from one constraint set.
    A var is "bounded" iff it has BOTH upper and lower; "partial" if only
    one; "top" otherwise.
    """
    inner = inv_set.strip().strip("{}").strip()
    bounds: dict[str, dict[str, int]] = defaultdict(dict)
    for piece in inner.split(";"):
        piece = piece.strip()
        if not piece:
            continue
        m = UPPER.match(piece)
        if m:
            bounds[m.group(1)]["upper"] = int(m.group(2))
            continue
        m = LOWER.match(piece)
        if m:
            # -v <= k  <=>  v >= -k
            bounds[m.group(1)]["lower"] = -int(m.group(2))
    return bounds


def precision_of(var: str, bounds: dict[str, dict[str, int]]) -> str:
    b = bounds.get(var, {})
    if "upper" in b and "lower" in b:
        return "bounded"
    if "upper" in b or "lower" in b:
        return "partial"
    return "top"


# ---------- LL parser: loops, branch factor, escaping vars ----------------

DEF_RE = re.compile(r"^\s*%([\w\.]+)\s*=\s*([a-z]+)\s")
PHI_RE = re.compile(r"^\s*%([\w\.]+)\s*=\s*phi\b")
BR_COND_RE = re.compile(r"^\s*br\s+i1\s+%[\w\.]+\s*,\s*label")
SWITCH_RE = re.compile(r"^\s*switch\s+")
LABEL_RE = re.compile(r"^([\w\.]+):")
RET_RE = re.compile(r"^\s*ret\b")

# Opcodes that hurt numerical AI domains (mul/bitwise/division).
HOSTILE = {"mul", "udiv", "sdiv", "urem", "srem", "xor", "and", "or",
           "shl", "lshr", "ashr"}
FRIENDLY = {"add", "sub", "icmp", "phi", "select", "zext", "sext", "trunc"}

def parse_function_blocks(ll_text: str, fn_name: str) -> dict[str, list[str]]:
    """Returns {block_label: [instruction_lines]} for one function."""
    blocks: dict[str, list[str]] = {}
    cur = None
    in_fn = False
    fn_open = re.compile(rf"^define\b.*@{re.escape(fn_name)}\(")
    for line in ll_text.splitlines():
        if not in_fn:
            if fn_open.match(line):
                in_fn = True
                cur = "entry"
                blocks[cur] = []
            continue
        if line.strip() == "}":
            break
        m = LABEL_RE.match(line)
        if m and not line.startswith(" "):
            cur = m.group(1)
            blocks[cur] = []
            continue
        if cur is not None:
            blocks[cur].append(line)
    return blocks


def loop_phi_vars(header_lines: list[str]) -> list[str]:
    """SSA names of PHI nodes in the loop header — these are the variables
    that survive across iterations and escape the loop."""
    out = []
    for ln in header_lines:
        m = PHI_RE.match(ln)
        if m:
            out.append(m.group(1))
    return out


def find_loops(blocks: dict[str, list[str]]) -> list[dict]:
    """
    Identify natural loops by spotting blocks that are PHI-targets of a
    back-edge. We approximate: a block is a loop header iff it has a PHI
    whose incoming labels include any block whose terminator branches back
    to this header.

    Returns a list of {header, body_blocks, branch_factor, defs_in_loop}.
    """
    # Map block -> successors (parsed from terminator).
    succ: dict[str, list[str]] = {}
    for blk, lines in blocks.items():
        s: list[str] = []
        for ln in lines:
            for lbl in re.findall(r"label\s+%([\w\.]+)", ln):
                s.append(lbl)
        succ[blk] = s

    headers = []
    for blk, lines in blocks.items():
        # Any PHI?
        phi_lines = [ln for ln in lines if PHI_RE.match(ln)]
        if not phi_lines:
            continue
        # Does any block reach this one via its terminator?
        backedge_preds = []
        for other, slist in succ.items():
            if blk in slist:
                # Is there a path other -> ... -> blk that loops back?
                # Cheap check: PHI on `blk` lists `other` as an incoming.
                for pl in phi_lines:
                    if re.search(rf"%{re.escape(other)}\b", pl):
                        if other != blk:
                            backedge_preds.append(other)
        if backedge_preds:
            headers.append((blk, list(set(backedge_preds))))

    # Backward-reachability index: which blocks can reach which.
    pred: dict[str, list[str]] = defaultdict(list)
    for b, ss in succ.items():
        for s in ss:
            pred[s].append(b)

    def reachable_forward(start: str) -> set[str]:
        seen, stk = set(), [start]
        while stk:
            x = stk.pop()
            if x in seen: continue
            seen.add(x)
            for s in succ.get(x, []):
                if s not in seen: stk.append(s)
        return seen

    def reachable_backward(target: str) -> set[str]:
        seen, stk = set(), [target]
        while stk:
            x = stk.pop()
            if x in seen: continue
            seen.add(x)
            for p in pred.get(x, []):
                if p not in seen: stk.append(p)
        return seen

    loops = []
    for header, backpreds in headers:
        # Loop body = blocks that lie on some cycle through header,
        # i.e. forward-reachable from header AND backward-reachable to header.
        fwd = reachable_forward(header)
        bwd = reachable_backward(header)
        body = fwd & bwd
        body.add(header)

        # Branch factor: count cond-br / switch in body.
        # Also count exits — successors that point OUTSIDE the loop body —
        # because each exit contributes a "break" path (linear in trip count
        # rather than multiplicative).
        bf = 0
        exits = 0
        defs = []
        op_friendly = 0
        op_hostile = 0
        for b in body:
            for ln in blocks.get(b, []):
                if BR_COND_RE.match(ln):
                    bf += 1
                elif SWITCH_RE.match(ln):
                    bf += max(1, ln.count("label") - 1)
                m = DEF_RE.match(ln)
                if m:
                    var, op = m.group(1), m.group(2)
                    defs.append(var)
                    if op in HOSTILE:
                        op_hostile += 1
                    elif op in FRIENDLY:
                        op_friendly += 1
            for s in succ.get(b, []):
                if s not in body:
                    exits += 1
        loops.append({
            "header": header,
            "body": sorted(body),
            "branch_factor": bf,
            "exits": exits,
            "defs": defs,
            "phi_defs": loop_phi_vars(blocks.get(header, [])),
            "op_friendly": op_friendly,
            "op_hostile": op_hostile,
        })
    return loops


# ---------- Heuristic --------------------------------------------------------

THRESHOLD_LOG_PATHS = 8.0     # log2 path count above which KLEE is "HIGH risk"
AI_SCORE_OK         = 0.5     # min fraction of vars Clam must bound

def trip_count_bound(header: str, invariants: dict[str, str], defs: list[str]) -> int | None:
    """
    Pick a likely loop-counter variable from the header's defs (a PHI named
    like *.0 or *.idx) and return its upper bound from the invariants.
    """
    inv = invariants.get(header, "")
    if not inv:
        return None
    bounds = variable_bounds(inv)
    # Prefer counter-shaped names; fall back to any bounded def.
    candidates = [v for v in defs if v in bounds and "upper" in bounds[v]]
    if not candidates:
        return None
    counter_like = [v for v in candidates if re.search(r"(off|idx|i|key_len|cnt)\b", v)]
    pick = counter_like[0] if counter_like else candidates[0]
    return bounds[pick]["upper"]


def triage_loop(loop: dict, invariants: dict[str, str]) -> dict:
    header = loop["header"]
    inv_at_header = invariants.get(header, "")
    bounds_header = variable_bounds(inv_at_header)

    # AI precision is what KLEE will *see* after the loop, so look at the
    # loop-PHI variables (escapers) at the loop exit if available, falling
    # back to the header invariants.
    exit_inv = ""
    for blk, inv in invariants.items():
        if blk in {"for.end", "exit", "loop.end"} or blk.endswith(".end"):
            exit_inv = inv
            break
    bounds_exit = variable_bounds(exit_inv) if exit_inv else bounds_header

    phi_defs = loop["phi_defs"] or loop["defs"]
    bounded = sum(1 for v in phi_defs if precision_of(v, bounds_exit) == "bounded")
    partial = sum(1 for v in phi_defs if precision_of(v, bounds_exit) == "partial")
    top     = sum(1 for v in phi_defs if precision_of(v, bounds_exit) == "top")
    total   = max(1, len(phi_defs))
    ai_score_inv = (bounded + 0.5 * partial) / total

    # Backup signal from opcodes.
    of, oh = loop["op_friendly"], loop["op_hostile"]
    ai_score_op = of / max(1, of + oh)

    # Combined: invariant-derived dominates if Clam saw the loop.
    ai_score = round(0.7 * ai_score_inv + 0.3 * ai_score_op, 3)

    bf = max(1, loop["branch_factor"])
    exits = loop.get("exits", 1)
    tc = trip_count_bound(header, invariants, loop["defs"])

    # KLEE-risk model:
    #   - exits >= 2  ⇒ break-on-condition pattern: paths grow linearly
    #     (~ tc * exits), even though bf can be high. KLEE handles this OK.
    #   - exits == 1  ⇒ single-exit loop. Branches inside the body fork
    #     independent subtrees ⇒ exponential O(bf^tc). This is the explosion case.
    #   - tc unbounded ⇒ HIGH regardless of shape.
    if tc is None:
        klee_risk_value = float("inf")
        klee_risk = "HIGH"
        risk_reason = "trip count unbounded by AI"
    elif exits >= 2:
        klee_risk_value = math.log2(max(1, tc * exits))
        klee_risk = "HIGH" if klee_risk_value > THRESHOLD_LOG_PATHS else "LOW"
        risk_reason = (f"break-on-cond loop (exits={exits}); paths≈tc*exits"
                       f"={tc*exits} (log2={klee_risk_value:.1f})")
    else:
        klee_risk_value = tc * math.log2(bf) if bf > 1 else 0.0
        klee_risk = "HIGH" if klee_risk_value > THRESHOLD_LOG_PATHS else "LOW"
        risk_reason = (f"single-exit loop, bf={bf}, tc={tc}; "
                       f"log2-paths={klee_risk_value:.1f}")

    if ai_score >= AI_SCORE_OK and klee_risk == "HIGH":
        decision = "summarize"
        rationale = "AI precise + KLEE would explode."
    elif ai_score >= AI_SCORE_OK:
        decision = "ignore"
        rationale = ("AI precise but KLEE handles this fine — assumes would "
                     "add solver work without pruning paths.")
    elif klee_risk == "HIGH":
        decision = "ignore"
        rationale = ("KLEE-risky but AI-imprecise on too many vars — current "
                     "domain can't summarize soundly. Try a richer domain.")
    else:
        decision = "ignore"
        rationale = "Neither AI-precise nor KLEE-risky."

    return {
        "header":      header,
        "body":        loop["body"],
        "ai_score":    ai_score,
        "ai_breakdown": {"bounded": bounded, "partial": partial,
                         "top": top, "ops_friendly": of, "ops_hostile": oh},
        "klee_risk":   klee_risk,
        "klee_risk_detail": risk_reason,
        "branch_factor": bf,
        "trip_count_upper": tc,
        "decision":    decision,
        "rationale":   rationale,
    }


# ---------- Main -----------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) != 4:
        sys.stderr.write(__doc__)
        return 2
    clam_path, ll_path, out_path = map(Path, argv[1:])
    clam_invs = parse_clam_text(clam_path)
    ll_text   = ll_path.read_text()

    result = {"input_ll": str(ll_path),
              "clam_text": str(clam_path),
              "functions": []}

    for fn, invariants in clam_invs.items():
        blocks = parse_function_blocks(ll_text, fn)
        if not blocks:
            continue
        loops = find_loops(blocks)
        loop_decisions = [triage_loop(l, invariants) for l in loops]
        result["functions"].append({
            "name":  fn,
            "loops": loop_decisions,
        })

    out_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
