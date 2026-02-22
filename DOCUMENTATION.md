# DRACO Conditional Policy – Documentation

Single consolidated document for conditional policy refactoring (February 2026): architecture, changes, implementation, mandatory fields, comparison, testing, technical spec, node design, return value constraints, and quick reference.

---

## Table of Contents

1. [Executive Summary & Changes (February 2026)](#1-executive-summary--changes-february-2026)
2. [Quick Reference: Policy Changes](#2-quick-reference-policy-changes)
3. [Mandatory Fields Guide](#3-mandatory-fields-guide)
4. [Comparison: Old vs New Format](#4-comparison-old-vs-new-format)
5. [Architecture Diagrams](#5-architecture-diagrams)
6. [Policy Node Design](#6-policy-node-design)
7. [Technical Spec: JSON Structure and Fields](#7-technical-spec-json-structure-and-fields)
8. [Intermediate Memory Access](#8-intermediate-memory-access)
9. [Return Value Constraints](#9-return-value-constraints)
10. [Implementation Summary](#10-implementation-summary)
11. [Final Implementation Notes](#11-final-implementation-notes)
12. [Testing Plan](#12-testing-plan)
13. [Full JSON Examples](#13-full-json-examples)

---

## 1. Executive Summary & Changes (February 2026)

### Executive Summary

Successfully implemented separation of **conditions** (guards/predicates) from **actions** (enforcement/invariants) in DRACO's conditional policy system. This refactoring improves semantic clarity, aligns with formal verification best practices, and adds powerful new features while maintaining full backward compatibility.

### What Was Changed

**1. Core Architecture**

- **Before**: Mixed conditions and actions in single `memory` field  
  `"memory": [{"conditions": [...], "read-access": [...], "write-access": [...]}]`
- **After**: Separate fields for conditions and actions  
  `"memory_conditions": [{"offset": 12, "size": 2, "value": "0x0800"}]`  
  `"memory_access": [{"read-access": ["*"], "write-access": ["x"]}]`

**2. Tree Structure Clarification**

- **Leaf nodes**: Use `memory_conditions` only
- **Intermediate nodes**: Use `memory_conditions` only
- **Root nodes**: Use `memory_access`, `map_access`, `allowed_helpers` only

**3. New Features**

1. **OR Logic**: Compose dependencies with OR instead of just AND
2. **Statistics**: Track policy coverage, violations, and dead policies
3. **Validation**: Warn about structural issues in policies
4. **Dead Policy Detection**: Identify policies that never trigger

**4. Critical Bug Fix**

Fixed memory operation hooks to use tree-based evaluation instead of flat iteration.

### Files Modified

- **Core**: `ExecutionState.h`, `Executor.h`, `Executor.cpp`, `main.cpp`, `Interpreter.h`
- **Examples**: `conditional_constraints_06_match_action_minimal.json`, `07_match_action_tree.json`, `08_or_logic.json`
- **Docs**: See table in Quick Reference section; also `DevPlan.md` (lines 148–310) for design rationale

### New JSON Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `memory_conditions` | array | Value checks for tree traversal | `[{"offset": 12, "size": 2, "value": "0x0800"}]` |
| `memory_access` | array | Access enforcement rules | `[{"read-access": ["*"], "write-access": ["x"]}]` |
| `dependency_logic` | string | "AND" or "OR" (required when deps exist) | `"OR"` |

### Build Instructions

```bash
cd klee/build
cmake -DENABLE_CONDITIONAL_POLICY=ON ..
make -j4
```

If permission errors occur: `sudo chown -R $USER:$USER klee/build`

### Breaking Change

⚠️ **Legacy `memory` field format is no longer supported.** All policies must use the new format with separate `memory_conditions` and `memory_access` fields.

---

## 2. Quick Reference: Policy Changes

### TL;DR

**What Changed**: Separated conditions (guards) from actions (enforcement) in conditional policies.

**Why**: Clearer semantics, better research story, aligns with formal verification best practices.

**Impact**: Breaking change – old `memory` format no longer supported. Migrate to new format.

### New vs Old Format

**Old Format (Still Supported):**  
Single policy with `memory` containing `conditions`, `read-access`, `write-access`.

**New Format (Recommended):**

- **Intermediate/Leaf (conditions):** `memory_conditions` only.
- **Root (actions):** `dependency`, `dependency_logic`, `memory_access`, etc.

### Node Types

| Type | Dependencies | Contains | Purpose |
|------|--------------|----------|---------|
| Leaf | 0 | `memory_conditions` | Base predicates |
| Intermediate | Yes, and is a dep | `memory_conditions` | Derived predicates |
| Root | Yes/No, not a dep | `memory_access`, `map_access`, `allowed_helpers` | Enforcement |

### Evaluation Flow

1. Start at root node  
2. Recursively check dependencies (bottom-up)  
3. Check memory conditions (if any)  
4. If all satisfied → enforce actions  
5. If violated → terminate state  

### Dependency Logic (MANDATORY)

`dependency_logic` is **required** for all policies with dependencies. Use `"AND"` or `"OR"`.

### Quick Migration

1. **Identify root nodes** (policies that no other policy depends on).
2. **Split fields**: Non-roots → `memory_conditions` only; roots → `memory_access` (and remove conditions).
3. **Test**: `make verify CONSTRAINTS=your_new_file.json` and check validation warnings.

### New Features

- **Validation**: Warnings for root with conditions, non-root with actions.
- **Statistics**: End-of-execution coverage/violation summary.
- **Dead policy detection**: Policies that never triggered.

### Common Patterns

- **Conditional enforcement**: "If X, then enforce Y" → condition node + root with `dependency_logic: "AND"`.
- **Multi-condition**: "If X AND Y, then Z" → two condition nodes, one root with `dependency_logic: "AND"`.
- **Alternative conditions**: "If X OR Y, then Z" → two condition nodes, one root with `dependency_logic: "OR"`.
- **Cascading**: "If X, then if Y, then Z" → chain of condition nodes and one root.

---

## 3. Mandatory Fields Guide

### Rule

**If a policy has dependencies, `dependency_logic` MUST be specified.** The parser will fail with an error if this field is missing.

### Why No Default?

- **Original design**: OR logic by default (plan line 230).
- **Decision**: Explicit and mandatory to avoid ambiguity, prevent errors, and keep configs self-documenting.

### Validation Behavior

- **Leaf (no dependencies):** No `dependency_logic` needed.
- **Node with dependencies:** Must have `"dependency_logic": "AND"` or `"OR"`.
- **Invalid value (e.g. "XOR"):** Parser error.

### Error Messages

- Missing: `ERROR: Policy 'X' has dependencies but missing 'dependency_logic' field. Must specify either 'AND' or 'OR'`
- Invalid: `ERROR: Policy 'X' has invalid dependency_logic: 'Y'. Must be either 'AND' or 'OR'`

### Quick Checklist

1. Does the policy have dependencies? NO → skip `dependency_logic`. YES → continue.
2. Should ALL dependencies be satisfied? YES → `"dependency_logic": "AND"`.
3. Should AT LEAST ONE be satisfied? YES → `"dependency_logic": "OR"`.

### Summary Table

| Scenario | dependency_logic required? | Value |
|----------|----------------------------|-------|
| No dependencies | No | N/A |
| Single dependency | Yes | "AND" |
| Multiple (all required) | Yes | "AND" |
| Multiple (any one) | Yes | "OR" |

---

## 4. Comparison: Old vs New Format

### JSON Format

| Aspect | Old Format | New Format |
|--------|------------|------------|
| Conditions | Inside `memory[].conditions` | Separate `memory_conditions` array |
| Actions | Inside `memory[]` read/write | Separate `memory_access` array |
| Structure | Mixed in same block | Separated by purpose |
| Semantics | Ambiguous | Clear (match-action) |
| Node types | Not distinguished | Explicit (leaf/intermediate/root) |

### Feature Comparison

| Feature | Old | New |
|---------|-----|-----|
| Condition-action separation | ✗ Mixed | ✓ Separated |
| OR logic | ✗ | ✓ |
| Validation warnings | ✗ | ✓ |
| Statistics | ✗ | ✓ |
| Dead policy detection | ✗ | ✓ |
| Tree evaluation | ✗ Flat (buggy) | ✓ Proper tree traversal |
| Backward compatible | N/A | ✓ Yes |

### Code Structure

- **Old**: Single `MemoryConstraint` with valueConditions, readRanges, writeRanges.
- **New**: `MemoryCondition` (offset, size, expectedValue) and `MemoryAccessRule` (readRanges, writeRanges); evaluation uses AND/OR and separate condition vs action checks.

### Memory Hooks

- **Old (buggy):** Iterated all policies flat; ignored tree.
- **New (correct):** Iterate only root policies; tree evaluation and then enforce memory access rules.

### Use Cases

- **Simple conditional**: Old = one policy with mixed block; new = condition node + action node with dependency.
- **Multiple conditions**: Old = one policy with multiple conditions; new = chain of condition nodes + one root.
- **Alternative conditions (OR)**: Old = not possible without duplication; new = multiple condition nodes + one root with `dependency_logic: "OR"`.

### Performance

- Policy checks: N (all) → R (roots only). Evaluation correctness: buggy flat → correct tree.

### Migration Required

All policies must use the new format. The legacy `memory` field is no longer supported.

---

## 5. Architecture Diagrams

### Before vs After: Data Structure

**Before (mixed semantics):**  
`MemoryConstraint { valueConditions[], readRanges[], writeRanges[] }` → ambiguous.

**After:**  
`MemoryCondition { offset, size, expectedValue[] }` → CONDITIONS (guards).  
`MemoryAccessRule { readRanges[], writeRanges[] }` → ACTIONS (enforcement).  
Clear separation of concerns.

### Policy Tree Structure

- **Root**: enforce_policy (actions only) ← depends on  
- **Intermediate**: check_specific_ip (conditions only) ← depends on  
- **Leaf**: check_ipv4 (conditions only)

**Evaluation:** Start at root → check dependencies recursively (bottom-up) → check conditions → enforce actions at root → pass/fail.

### AND vs OR

- **AND**: Policy applies if A AND B AND C.
- **OR**: Policy applies if A OR B OR C.

### Memory Operation Flow

- **Before**: Iterate all policies, check each; ignored tree.
- **After**: Iterate root policies only → evaluate tree (recursive) → if applicable, check memory_access → if violated, terminate state.

### Example Multi-Level Tree (JSON sketch)

- `base_read` (leaf) → `check_ipv4` → `check_ip_10_0_0_1` → `enforce_no_write` (root with memory_access).

### Statistics Output

Example table: Policy Name | Applicable | Violated | Not Applic. | Coverage %. Plus optional WARNING for dead policies.

### Validation Workflow

Parse JSON → identify leaf/intermediate/root → validate (roots = actions only, non-roots = conditions only) → warnings or "✓".

### Code Organization

- **Data**: ExecutionState.h (MemoryCondition, MemoryAccessRule, PolicyNode, PolicyStatistics, DependencyLogic).
- **Parsing**: main.cpp `parseConditionalPolicies()` (memory_conditions, memory_access, dependency_logic, roots, validation).
- **Evaluation**: Executor.cpp (checkMemoryConditions, checkMemoryAccessRule, evaluateConditionalPolicy, updatePolicyStatistics, printPolicyStatistics).
- **Enforcement**: handlePacketDataStore/Load – only check root policies.

### Design Patterns

1. **Guard–invariant separation**: Conditions determine applicability; actions enforce constraints.
2. **Bottom-up evaluation**: Leaf → intermediate → root.
3. **Short-circuit**: OR stops at first true; AND stops at first false.

### Research / Performance

- Aligns with guards = preconditions, invariants = postconditions; match-action paradigm; coverage analysis.
- Short-circuit and root-only checking improve performance. No caching: policies are re-evaluated on each check for correctness.

### Critical Fixes (February 22, 2026)

1. **Return value violations now terminate states** (was only warning before) — calls `terminateStateOnProgramError`
2. **Memory range boundary fix**: Ranges use inclusive notation (e.g., "0-54" means bytes 0-54 inclusive) — check is `accessEnd <= range.second + 1`
3. **Cycle detection**: Parser now detects circular dependencies and undefined policy references — fails parsing with error
4. **Map access enforcement**: Maps without rules in `map_access` are now forbidden (no rule = no access) — any accessed map must have a rule
5. **Legacy support removed**: Old `memory` field format no longer supported — all code and data structures removed
6. **nullptr ObjectState bug fixed**: `terminateStateOnExit` now retrieves packet ObjectState so `memory_conditions` are properly evaluated for return value policies

### Design Limitations & Trade-offs

**Delayed Policy Evaluation (By Design)**

Policy evaluation occurs at specific checkpoints, not after every operation:

**When policies are checked:**
1. During packet memory operations (`handlePacketDataStore/Load`)
2. At program exit (`terminateStateOnExit`)

**What this means:**
- Helper function violations are not detected immediately when called
- Map access violations are not detected immediately when accessed
- Violations are accumulated and checked at the next checkpoint

**Example scenario:**
```c
// Program calls unauthorized helper
bpf_trace_printk("debug");  // ← Not checked immediately

// Later, program reads packet
int proto = packet[23];     // ← Policy evaluated here, helper violation detected
```

**Impact:**
- States with violations continue executing until a checkpoint
- All violations are eventually caught (verification is sound)
- States aren't pruned as early as possible (performance impact)

**Rationale:**
- **Performance**: Checking policies after every operation is expensive
- **Correctness**: Violations are always caught before state completes
- **Simplicity**: Centralized checking at memory operations and exit

**Alternative design (not implemented):**
- Hook every `addHelperFunctionCall()` and `addMapRead/Write()` to trigger immediate policy evaluation
- Would catch violations earlier but significantly impact performance
- Trade-off: early pruning vs. execution overhead

**Recommendation**: This design is acceptable for verification purposes. If early pruning is critical for performance on large programs, consider implementing eager checking as an optional mode.

---

## 6. Policy Node Design

### Core Principle

**Any node (leaf, intermediate, or root) can have `memory_access` actions.**  
**Only leaf and intermediate nodes should have `memory_conditions` guards.**  
**Root nodes should have only actions, no conditions.**

### Rationale

**Why Any Node Can Have memory_access**

Memory access enforcement can happen at any level in the policy tree:

1. **Leaf nodes**: Base conditions with access restrictions — e.g. "If packet is readable, only allow reads to header (bytes 0-54)"
2. **Intermediate nodes**: Conditional access based on earlier checks — e.g. "If packet is IPv4 (condition), then MAC addresses are read-only (action)"
3. **Root nodes**: Final enforcement without additional conditions — e.g. "Enforce helper whitelist"

**Why Root Nodes Should Not Have memory_conditions**

Root nodes represent final policies to enforce. Conditions should be in their dependencies.

**Bad (condition at root):**
```json
{
  "enforce_policy": {
    "dependency": [],
    "memory_conditions": [{ "offset": 12, "size": 2, "value": "0x0800" }],
    "memory_access": [...]
  }
}
```

**Good (condition at intermediate, action at root):**
```json
{
  "check_ipv4": {
    "dependency": [],
    "memory_conditions": [{ "offset": 12, "size": 2, "value": "0x0800" }]
  },
  "enforce_policy": {
    "dependency": ["check_ipv4"],
    "dependency_logic": "AND",
    "memory_access": [...]
  }
}
```

### Node Type Summary

| Node Type | Can Have memory_conditions | Can Have memory_access | Can Have return_value_rules |
|-----------|---------------------------|------------------------|----------------------------|
| Leaf | Yes (recommended) | Yes | No |
| Intermediate | Yes (recommended) | Yes | No |
| Root | No (use deps instead) | Yes | Yes |

### Common Patterns

**Pattern 1: Condition → Action (Match-Action)**  
Leaf with `memory_conditions`, root with `dependency` and `memory_access`.

**Pattern 2: Progressive Restrictions (Intermediate with Actions)**  
Chain of nodes each with `memory_conditions` and `memory_access` (e.g. IPv4 → restrict MAC writes; HTTP → read-only).

**Pattern 3: Multiple Conditions, Single Action (OR Logic)**  
Two leaves (e.g. check_ipv4, check_ipv6), one root with `dependency_logic: "OR"` and `memory_access`.

### Validation

The parser warns if a root node has `memory_conditions` (should use intermediate nodes). Design encourages separation: conditions in dependencies, actions at roots.

### Benefits

1. **Flexibility**: Actions can be enforced at any level based on conditions  
2. **Composability**: Build complex policies from simple condition + action nodes  
3. **Clarity**: Clear separation between "when" (conditions) and "what" (actions)  
4. **Reusability**: Same condition node can be used by multiple action nodes  

---

## 7. Technical Spec: JSON Structure and Fields

### Top-Level Structure

```json
{
  "conditional_policies": {
    "<policy_name>": { <PolicyNode> },
    ...
  }
}
```

- **`conditional_policies`** (required): Object mapping policy names to policy nodes. Policy names are referenced in `dependency` arrays; names are case-sensitive.

### Policy Node Fields

| Field | Type | Required | Applies to | Description |
|-------|------|----------|------------|-------------|
| `dependency` | string[] | Yes | All | Policy names that must be evaluated first. Empty `[]` for leaves. |
| `dependency_logic` | `"AND"` \| `"OR"` | **Yes if `dependency` non-empty** | Nodes with deps | How to combine dependencies. No default; parser errors if missing. |
| `memory_conditions` | array | No | All | Value checks (guards) for tree traversal. Determines if policy applies. |
| `memory_access` | array | No | All | Access enforcement (read/write ranges) on packet memory. Checked during memory operations. |
| `map_access` | array | No | All | Map name + allowed access. Checked during policy evaluation. |
| `allowed_helpers` | string[] | No | All | Whitelist of helper names; `"*"` = all allowed. Checked during policy evaluation. |
| `return_value_rules` | object | No | Root only | Allowed/forbidden program return values (e.g. XDP_*). Checked at program exit. |

**Enforcement timing:**

- `memory_conditions`: Checked during policy evaluation to determine applicability.
- `memory_access`: Checked during actual memory read/write operations when the policy is applicable (at any node level).
- `map_access` / `allowed_helpers`: Checked during policy evaluation (at any node level).
- `return_value_rules`: Checked only at program exit for root policies.

### Field Formats

**memory_conditions** — Array of predicate objects:

```json
"memory_conditions": [
  { "offset": 12, "size": 2, "value": "0x0800" },
  { "offset": 26, "size": 4, "value": "0x0A000001" }
]
```

| Key | Type | Description |
|-----|------|-------------|
| `offset` | number | Byte offset into packet (e.g. 12 = EtherType, 26 = IPv4 src). |
| `size` | number | Length in bytes (1, 2, 4, etc.). |
| `value` | string | Expected value as hex string (e.g. `"0x0800"` for IPv4 EtherType). |

**memory_access** — Array of access rules:

```json
"memory_access": [
  { "read-access": ["*"], "write-access": ["x"] }
]
```

| Key | Values | Meaning |
|-----|--------|---------|
| `read-access` | `["*"]` or list of `"start-end"` | `"*"` = any read; ranges = allowed read intervals. |
| `write-access` | `["*"]` or `["x"]` | `"*"` = any write; `"x"` = no writes allowed. |

**map_access** — Array of map rules:

```json
"map_access": [
  { "name": "flow_ctx_table", "access": "Read" },
  { "name": "tx_port", "access": "ReadWrite" }
]
```

| Key | Values | Description |
|-----|--------|-------------|
| `name` | string | Map name (as in the eBPF program). |
| `access` | `"Read"` \| `"Write"` \| `"ReadWrite"` | Allowed operations on that map. |

**Important**: 
- If a policy has `map_access` rules (non-empty array), any map accessed by the program that is NOT in the rules will cause a violation.
- If `map_access` is an empty array `[]`, no map access restrictions are enforced (all maps allowed).
- To forbid all map access, omit maps from the rules or use an empty array with strict helper restrictions.

**allowed_helpers** — List of helper names, or `["*"]` to allow all.

**return_value_rules** — Object with optional `allowed` and/or `forbidden` arrays (integers). Checked at program exit for applicable root policies.

```json
"return_value_rules": {
  "allowed": [2],
  "forbidden": [0, 4]
}
```

- **`allowed`**: If non-empty, return value must be in this list (e.g. `[2]` = XDP_PASS only).
- **`forbidden`**: Return value must not be in this list.
- XDP reference: 0=ABORTED, 1=DROP, 2=PASS, 3=TX, 4=REDIRECT.

### Evaluation Semantics

- **Tree structure**: Dependencies form a DAG. Roots are policies that no other policy depends on.
- **Evaluation order**: For each root, bottom-up: (1) Recursively evaluate dependencies with `dependency_logic`; (2) Check `memory_conditions` at each node; (3) If applicable, check `memory_access`, `map_access`, `allowed_helpers` at that node.
- **No caching**: Policies are re-evaluated on each check to ensure correctness as runtime state changes.
- **Memory operations**: On packet load/store, root policies are evaluated with memory operation context (offset, bytes, read/write). During tree traversal, **each node** can check its `memory_access` rules against the current operation. Violation at any level terminates the state.
- **Return values**: Checked only at program exit for applicable root policies.

### Quick Reference (Packet Offsets)

| Offset | Content |
|--------|---------|
| 0–5 | dst MAC |
| 6–11 | src MAC |
| 12–13 | EtherType |
| 26–29 | IPv4 src |
| 30–33 | IPv4 dst |
| 34–35 | src port |
| 36–37 | dst port |

### Invocation

```bash
klee ... -enable-conditional-policy=true -config-file=conditional_constraints_06_match_action_minimal.json ...
```

From `examples/fw`:

```bash
make verify CONSTRAINTS=conditional_constraints_06_match_action_minimal.json
```

---

## 8. Intermediate Memory Access

### Summary

`memory_access` rules are allowed at **all node levels** (leaf, intermediate, and root). This enables conditional memory access policies like "if you accessed byte X, then accessing byte Y is forbidden."

### Use Cases

1. **Conditional access based on previous reads**: "If you read the EtherType field, you cannot modify MAC addresses" — intermediate node with `memory_conditions` (EtherType = IPv4) and `memory_access` (e.g. write only 12–1500).
2. **Progressive restrictions**: "If IPv4, restrict MAC writes; if also HTTP, make entire packet read-only" — chain of nodes with both conditions and access rules.
3. **Access-based policies**: "If you accessed IP header, you can only read (not write) TCP header."

### How It Works

1. On packet read/write, `handlePacketDataStore/Load()` is called.
2. For each root policy, `evaluateConditionalPolicy()` is called with memory operation context (offset, bytes, isWrite).
3. During tree traversal, dependencies are evaluated recursively; memory context is passed down; each node checks `memory_conditions` and `memory_access` against the current operation.
4. If any node's `memory_access` is violated, the state is terminated.

### Code Verification

- **Validation**: No warning for non-root nodes having `memory_access`; only root nodes with `memory_conditions` are warned.
- **Evaluation**: `Executor.cpp` checks `memory_access` for any node when memory operation context is provided; no type-based filtering.
- **Memory hooks**: Only root policies are iterated; tree is evaluated recursively with memory context passed to all levels.

### Backward Compatibility

✓ All existing constraint files continue to work. ✓ Root-only memory_access policies still function. ✓ No breaking changes to JSON format.

---

## 9. Return Value Constraints

### Overview

Return value constraints allow policies to enforce restrictions on eBPF program return values based on runtime conditions. They integrate with the existing conditional policy framework: applicability is determined by dependencies and memory conditions; when a root policy applies, return value rules are enforced at program exit.

### Implementation Summary

- **Templates**: `draco_template.j2`, `draco_cross_prog_template.j2` — added `__record_ebpf_return_value(val)` after each eBPF program execution.
- **Stub**: `verification_helpers.h` — `__record_ebpf_return_value(int val)` for KLEE interception.
- **Data structures**: `ExecutionState.h` — `ReturnValueRule` (allowedValues, forbiddenValues), `PolicyNode` extended with `returnValueRule` and `hasReturnValueRule`; `ExecutionState` with `ebpfReturnValue` and `ebpfReturnValueCaptured`.
- **Parsing**: `main.cpp` — `return_value_rules` (allowed/forbidden arrays).
- **Executor**: Interception of `__record_ebpf_return_value`; `checkReturnValueRule()`; in `terminateStateOnExit()`, iterate applicable root policies and check return value rules.

### JSON Schema

```json
"return_value_rules": {
  "allowed": [2],        // Whitelist (empty = all allowed)
  "forbidden": [0, 4]    // Blacklist
}
```

### Integration with Existing System

| Constraint Type | Purpose | When Checked |
|-----------------|---------|--------------|
| `memory_conditions` | Determine policy applicability | During policy evaluation |
| `memory_access` | Enforce read/write restrictions | During memory operations |
| `allowed_helpers` | Whitelist permitted helpers | During policy evaluation |
| `map_access` | Enforce map operation restrictions | During policy evaluation |
| **`return_value_rules`** | **Enforce return value restrictions** | **At program termination** |

### XDP Return Values Reference

| Constant | Value | Description |
|----------|-------|-------------|
| XDP_ABORTED | 0 | Error condition |
| XDP_DROP | 1 | Drop packet |
| XDP_PASS | 2 | Pass to network stack |
| XDP_TX | 3 | Transmit back out same interface |
| XDP_REDIRECT | 4 | Redirect to another interface |

### Design Decisions

1. **Root policies only**: Return value rules are checked on root policies at state termination.
2. **Enforcement at exit**: Checks happen in `terminateStateOnExit()` after the program has completed.
3. **Backward compatible**: Policies without return value constraints work unchanged; code under `#ifdef CONDITIONAL_POLICY`.

### Example Use Cases

**Enforce XDP_PASS for HTTP traffic:** Policy with `memory_conditions` (EtherType, port 80) and dependent root with `return_value_rules`: `{"allowed": [2]}`.

**Prevent XDP_ABORTED globally:** Root with no deps and `return_value_rules`: `{"forbidden": [0]}`.

**Restrict untrusted sources to DROP only:** Condition node (e.g. src IP), root with `return_value_rules`: `{"allowed": [1]}`.

### Testing

```bash
cd examples/fw
make verify CONSTRAINTS=return_value_01_simple.json
```

---

## 10. Implementation Summary

### Date

February 20, 2026.

### Changes Implemented

1. **Data structures (ExecutionState.h):** MemoryCondition, MemoryAccessRule, DependencyLogic, PolicyStatistics; PolicyNode with memoryConditions, memoryAccessRules, legacy memoryConstraints, dependencyLogic, useLegacyFormat; ReturnValueRule and related fields for return value constraints.
2. **JSON parsing (main.cpp):** memory_conditions, memory_access, dependency_logic, return_value_rules; validation warnings; backward compat for `memory`.
3. **Evaluation (Executor.cpp):** checkMemoryConditions(), checkMemoryAccessRule(), checkReturnValueRule(), updatePolicyStatistics(), printPolicyStatistics(); evaluateConditionalPolicy() with OR/AND, condition vs action separation, stats; legacy paths kept.
4. **Bug fix:** handlePacketDataStore/Load now iterate only roots and use tree evaluation + memory access rules at all node levels.
5. **Statistics:** Per-policy applicable/violated/not applicable, coverage %, dead policy detection, pretty-printed table.
6. **Dependency logic:** Mandatory "AND" or "OR" when dependencies exist; short-circuit; parser fails if missing.
7. **Return value constraints:** Template recording, interception, checking at exit for applicable root policies.
8. **Caching removed:** All caching removed from conditional policy evaluation; policies re-evaluated on each check for correctness (stale cache could cause bugs when helpers/maps/symbolic state changed).

### Code Verification (memory_access at All Levels)

- **Validation**: Removed incorrect warning for non-root nodes having memory_access; kept warning for root nodes with memory_conditions.
- **Evaluation**: No code restrictions on which nodes can have memory_access; checked at every node level when memory context is provided.
- **Memory hooks**: Root policies only as entry points; tree traversal passes memory context to all levels so leaf/intermediate nodes can enforce memory_access.

### New JSON Fields

- Required: `memory_conditions`, `memory_access`, `dependency_logic` (when deps exist), `return_value_rules` (optional).
- **Removed**: Legacy `memory` field no longer supported.

### Files Modified (Summary)

- **Core**: ExecutionState.h, ExecutionState.cpp, Executor.h, Executor.cpp, main.cpp, Interpreter.h.
- **Templates**: lifting_tools/draco_template.j2, draco_cross_prog_template.j2.
- **Verification**: verification_tools/verification_helpers.h.
- **Examples**: 06, 07, 08, 09 JSON; return_value_01/02/03 JSON.

### Known Issues

- Build dir permissions: `sudo chown -R $USER:$USER klee/build` or recreate build dir.
- IDE linter: false positives; compilation should succeed.

---

## 11. Final Implementation Notes

### Implementation Complete ✓

**Key design: mandatory dependency_logic**

- **No default – mandatory.** Must specify `"dependency_logic": "AND"` or `"OR"` for any policy with dependencies.
- **Rationale:** Avoid ambiguity, self-documenting configs, prevent errors, research clarity.

**Parser:** With deps → must have dependency_logic. Missing → ERROR. Invalid value → ERROR.

### Complete Feature List

1. Condition–action separation (memory_conditions / memory_access).
2. Mandatory dependency_logic with parser validation.
3. Tree evaluation fix (roots only; memory_access at all levels).
4. Statistics (coverage, violations, dead policies).
5. Validation warnings (root vs non-root).
6. Backward compatibility (old `memory`).
7. Return value constraints (root policies, at exit).
8. No caching (re-evaluate each check).

### Testing Checklist

Before running: 
- All policies with deps have `dependency_logic` ("AND" or "OR")
- Root nodes have actions only (no `memory_conditions`)
- Non-root nodes can have both conditions and actions
- No circular dependencies
- Map access rules defined for all accessed maps (no rule = no access)

---

## 12. Testing Plan

### Overview

Strategy for the new conditional policy format (condition–action separation).

### Test Cases (Summary)

1. **Backward compatibility:** conditional_constraints_05_full.json (legacy); expect legacy detection, same behavior, stats.
2. **Minimal match-action:** 06; leaf + root; validation ✓; stats as expected.
3. **Multi-level tree:** 07; tree printed; bottom-up evaluation; coverage per level.
4. **OR logic:** 08; "(OR logic)" in output; triggers for IPv4 or IPv6.
5. **Validation warnings:** Test file with root having conditions, non-root having actions; expect WARNINGs.
6. **Dead policy:** Test file with impossible condition; expect 0 applicable and dead-policy WARNING.
7. **Regression:** Compare legacy vs converted new format (same violations/termination).
8. **Memory hooks:** Only roots checked; tree evaluation; memory_access at all levels.
9. **Intermediate memory access:** 09; conditional access at intermediate nodes.
10. **Return value constraints:** return_value_01/02/03; enforcement at exit.
11. **Full firewall:** fw.c with new format.
12. **Map and helper:** map_access and allowed_helpers with memory conditions.
13. **Compile:** CONDITIONAL_POLICY=ON – no errors.
14. **Compile:** CONDITIONAL_POLICY=OFF – new code ifdef'd out.

### Commands (examples)

```bash
cd examples/fw
make verify CONSTRAINTS=conditional_constraints_06_match_action_minimal.json
```

```bash
cd klee/build
cmake -DENABLE_CONDITIONAL_POLICY=ON ..
make -j4
```

### Success Criteria

No compile errors; legacy works; new format parses and validates; statistics printed; tree evaluation (roots only); OR works; dead policies detected; intermediate memory_access and return value rules work; no crashes/leaks.

### Known Issues

- Build permissions: chown or recreate build dir.
- Missing deps: dependency names must match exactly (case-sensitive).

---

## 13. Full JSON Examples

### Minimal: one condition → one action (match-action)

If EtherType is IPv4 (offset 12, 2 bytes = 0x0800), then packet is read-only.

```json
{
  "conditional_policies": {
    "check_ethertype_is_ipv4": {
      "dependency": [],
      "memory_conditions": [
        { "offset": 12, "size": 2, "value": "0x0800" }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "enforce_no_write_if_ipv4": {
      "dependency": ["check_ethertype_is_ipv4"],
      "dependency_logic": "AND",
      "memory_access": [
        { "read-access": ["*"], "write-access": ["x"] }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    }
  }
}
```

### Multi-level tree

Chain: base → IPv4 → specific IP → enforce no write.

```json
{
  "conditional_policies": {
    "check_packet_readable": {
      "dependency": [],
      "memory_conditions": [],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "check_ipv4": {
      "dependency": ["check_packet_readable"],
      "dependency_logic": "AND",
      "memory_conditions": [
        { "offset": 12, "size": 2, "value": "0x0800" }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "check_specific_ip": {
      "dependency": ["check_ipv4"],
      "dependency_logic": "AND",
      "memory_conditions": [
        { "offset": 26, "size": 4, "value": "0x0A000001" }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "enforce_no_write_specific_ip": {
      "dependency": ["check_specific_ip"],
      "dependency_logic": "AND",
      "memory_access": [
        { "read-access": ["*"], "write-access": ["x"] }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    }
  }
}
```

### Conditional memory access (intermediate node with memory_access)

If EtherType is IPv4, then writes to MAC (0–11) forbidden; read-only for payload (12–1500).

```json
{
  "conditional_policies": {
    "check_read_ethertype": {
      "dependency": [],
      "memory_conditions": [
        { "offset": 12, "size": 2, "value": "0x0800" }
      ],
      "memory_access": [
        { "read-access": ["*"], "write-access": ["12-1500"] }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "enforce_policy": {
      "dependency": ["check_read_ethertype"],
      "dependency_logic": "AND",
      "map_access": [],
      "allowed_helpers": ["*"]
    }
  }
}
```

### OR logic and return values

If IPv4 or IPv6, enforce read-only. Trusted IP must return XDP_PASS; untrusted (IPv4, not trusted) must return DROP or PASS only.

```json
{
  "conditional_policies": {
    "check_ipv4": {
      "dependency": [],
      "memory_conditions": [{ "offset": 12, "size": 2, "value": "0x0800" }],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "check_ipv6": {
      "dependency": [],
      "memory_conditions": [{ "offset": 12, "size": 2, "value": "0x86DD" }],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "check_trusted_ip": {
      "dependency": ["check_ipv4"],
      "dependency_logic": "AND",
      "memory_conditions": [{ "offset": 26, "size": 4, "value": "0x0A000001" }],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "enforce_readonly_for_ip_packets": {
      "dependency": ["check_ipv4", "check_ipv6"],
      "dependency_logic": "OR",
      "memory_access": [{ "read-access": ["*"], "write-access": ["x"] }],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "trusted_can_pass": {
      "dependency": ["check_trusted_ip"],
      "dependency_logic": "AND",
      "return_value_rules": { "allowed": [2] },
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "untrusted_must_drop_or_pass": {
      "dependency": ["check_ipv4"],
      "dependency_logic": "AND",
      "return_value_rules": {
        "allowed": [1, 2],
        "forbidden": [0, 3, 4]
      },
      "map_access": [],
      "allowed_helpers": ["*"]
    }
  }
}
```

### Statistics output (example)

```
========== Conditional Policy Statistics ==========
Policy Name                    Applicable    Violated  Not Applic.  Coverage %
------------------------------------------------------------------------------
check_ipv4                            150           0          350        30.0%
enforce_no_write                      150          25          350        30.0%
------------------------------------------------------------------------------
TOTAL                                 300          25          700        30.0%
===================================================

WARNING: The following policies were never applicable (dead policies):
  - check_ipv6
```

---

*End of consolidated documentation. For development plan and design rationale, see DevPlan.md. For project overview, see README.md.*
