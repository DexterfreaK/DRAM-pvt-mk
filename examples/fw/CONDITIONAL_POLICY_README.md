# Conditional Policy - Match-Action Separation

## ⚠️ IMPORTANT: Mandatory Fields

**`dependency_logic` is REQUIRED for all policies with dependencies.**

The parser will fail with an error if this field is missing. You must explicitly specify either `"AND"` or `"OR"` - no defaults are assumed.

See `MANDATORY_FIELDS_GUIDE.md` for details.

## Overview

This document describes the new conditional policy format that separates **conditions** (guards/predicates) from **actions** (enforcement/invariants).

## Key Changes

### 1. Separation of Conditions and Actions

**Old Format (DEPRECATED):**
```json
{
  "memory": [{
    "conditions": [...],      // Mixed: conditions AND actions
    "read-access": [...],     // in the same block
    "write-access": [...]
  }]
}
```

**New Format (RECOMMENDED):**
```json
{
  "memory_conditions": [...],  // Conditions only (for tree traversal)
  "memory_access": [{          // Actions only (for enforcement)
    "read-access": [...],
    "write-access": [...]
  }]
}
```

### 2. Root Nodes Only Have Actions

- **Leaf/Intermediate nodes**: Use `memory_conditions` (predicates)
- **Root nodes**: Use `memory_access`, `map_access`, `allowed_helpers` (enforcement)

### 3. Dependency Logic Support (MANDATORY)

**IMPORTANT**: The `dependency_logic` field is **required** for all policies with dependencies.

**AND Logic:**
```json
{
  "dependency": ["policy1", "policy2"],
  "dependency_logic": "AND"  // REQUIRED
}
```
All dependencies must be satisfied.

**OR Logic:**
```json
{
  "dependency": ["policy1", "policy2"],
  "dependency_logic": "OR"  // REQUIRED
}
```
At least one dependency must be satisfied.

**Note**: If a policy has no dependencies (`"dependency": []`), the `dependency_logic` field is not required.

## Policy Structure

### Tree Evaluation Flow

```
Leaf Nodes (0 dependencies)
    ↓ Check memory_conditions
Intermediate Nodes (has deps, is a dep)
    ↓ Check memory_conditions
Root Nodes (not a dep of others)
    ↓ Enforce memory_access, map_access, allowed_helpers
```

### Node Types

1. **Leaf Nodes**: 
   - 0 dependencies
   - Contains `memory_conditions` only
   - Example: `check_ipv4`

2. **Intermediate Nodes**:
   - Has dependencies AND is a dependency of other policies
   - Contains `memory_conditions` only
   - Example: `check_specific_ip` (depends on `check_ipv4`, used by `enforce_policy`)

3. **Root Nodes**:
   - NOT a dependency of any other policy
   - Contains `memory_access`, `map_access`, `allowed_helpers` only
   - Example: `enforce_no_write_if_ipv4`

## Example Files

### Minimal Example (`conditional_constraints_06_match_action_minimal.json`)

Simple 2-level tree: condition → action

```json
{
  "conditional_policies": {
    "check_ethertype_is_ipv4": {
      "dependency": [],
      "memory_conditions": [
        {"offset": 12, "size": 2, "value": "0x0800"}
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "enforce_no_write_if_ipv4": {
      "dependency": ["check_ethertype_is_ipv4"],
      "memory_access": [
        {"read-access": ["*"], "write-access": ["x"]}
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    }
  }
}
```

**Semantics**: "If packet is IPv4, then enforce read-only access"

### Multi-Level Tree (`conditional_constraints_07_match_action_tree.json`)

Complex tree with multiple levels and branches.

**Tree Structure:**
```
check_packet_readable (leaf)
    ↓
check_ipv4 (intermediate)
    ↓                    ↓
check_specific_ip    check_specific_port (intermediate)
    ↓                    ↓
enforce_no_write    enforce_restricted_helpers (roots)
```

### OR Logic Example (`conditional_constraints_08_or_logic.json`)

Demonstrates OR composition of dependencies.

```json
{
  "enforce_readonly_for_ip_packets": {
    "dependency": ["check_ipv4", "check_ipv6"],
    "dependency_logic": "OR",
    "memory_access": [...]
  }
}
```

**Semantics**: "If packet is IPv4 OR IPv6, then enforce read-only"

## Field Reference

### Policy Fields

| Field | Type | Description | Used In |
|-------|------|-------------|---------|
| `dependency` | string[] | List of policy names this depends on | All nodes |
| `dependency_logic` | "AND"\|"OR" | How to combine dependencies (**REQUIRED** if dependencies exist) | Nodes with deps |
| `memory_conditions` | object[] | Value checks for tree traversal | Leaf/Intermediate |
| `memory_access` | object[] | Access enforcement rules | Root nodes |
| `map_access` | object[] | Map access enforcement | Root nodes |
| `allowed_helpers` | string[] | Helper function whitelist | Root nodes |

### memory_conditions Format

```json
{
  "offset": 12,      // Byte offset in packet
  "size": 2,         // Number of bytes
  "value": "0x0800"  // Expected hex value
}
```

### memory_access Format

```json
{
  "read-access": ["0-54", "100-200"],  // Allowed read ranges
  "write-access": ["x"]                 // "x" = no writes, "*" = all writes
}
```

### map_access Format

```json
{
  "name": "flow_ctx_table",
  "access": "Read"  // "Read", "Write", or "ReadWrite"
}
```

## Statistics Output

When execution completes, KLEE prints policy statistics:

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

**Columns:**
- **Applicable**: Number of states where policy was checked
- **Violated**: Number of states that violated the policy
- **Not Applic.**: Number of states where policy didn't apply (preconditions not met)
- **Coverage %**: Percentage of states where policy was applicable

## Validation Warnings

The parser validates policy structure and warns about common mistakes:

```
WARNING: Root node 'enforce_policy' has memory_conditions (should only have actions like memory_access)
WARNING: Non-root node 'check_ipv4' has memory_access (should only have conditions like memory_conditions)
```

## Backward Compatibility

The old `memory` field format is still supported:

```json
{
  "memory": [{
    "conditions": [...],
    "read-access": [...],
    "write-access": [...]
  }]
}
```

Policies using this format will have `useLegacyFormat = true` internally and will be processed using the old code path.

## Migration Guide

### Step 1: Identify Node Types

Look at your policy tree and classify each node:
- Leaf: 0 dependencies
- Intermediate: Has dependencies, is a dependency of others
- Root: Not a dependency of any other policy

### Step 2: Separate Conditions from Actions

**For Leaf/Intermediate Nodes:**
- Move `conditions` array to `memory_conditions`
- Remove `read-access` and `write-access` fields

**For Root Nodes:**
- Move `read-access` and `write-access` to `memory_access` array
- Remove `conditions` field

### Step 3: Test

Run KLEE with the new config and check:
1. Validation warnings (fix any structural issues)
2. Policy statistics (ensure policies are being triggered)
3. Verification results (compare with old format)

## Best Practices

1. **Keep root nodes simple**: Only enforcement, no conditions
2. **Use descriptive names**: `check_ipv4` vs `enforce_readonly`
3. **Leverage OR logic**: Combine similar conditions
4. **Monitor statistics**: Check for dead policies
5. **Start simple**: Test with 2-level trees before complex ones

## Research Benefits

1. **Clearer semantics**: Match-action paradigm is standard in networking
2. **Better formal verification**: Guards vs. invariants separation
3. **Easier to explain**: "If condition X, then enforce action Y"
4. **Extensibility**: Easy to add new condition or action types
5. **Coverage analysis**: Statistics show which policies are actually used

## Implementation Details

### Data Structures

- `MemoryCondition`: Single condition (offset, size, value)
- `MemoryAccessRule`: Access enforcement (read/write ranges)
- `PolicyNode`: Contains both for backward compatibility
- `PolicyStatistics`: Tracks coverage and violations

### Evaluation Algorithm

```cpp
bool evaluatePolicy(policyName):
  1. Check cache (avoid re-evaluation)
  2. Evaluate dependencies (recursive, with AND/OR logic)
     - If not satisfied → policy not applicable → return true
  3. Check memory_conditions
     - If not met → policy not applicable → return true
  4. Enforce actions (helper, map, memory access)
     - If violated → return false
  5. Cache and return result
```

### Memory Operation Hooks

When a memory read/write occurs:
1. Iterate through root policies only (not all policies)
2. For each root, evaluate the policy tree
3. If applicable, enforce memory_access rules
4. Terminate state if violation

## Troubleshooting

### Policy Never Triggered

**Symptom**: Statistics show 0 applicable states

**Causes:**
1. Condition values don't match any execution path
2. Dependencies are too restrictive
3. Policy is unreachable in the tree

**Solution**: Check condition values, simplify dependencies, or use OR logic

### Unexpected Violations

**Symptom**: States fail verification unexpectedly

**Causes:**
1. Root node has conditions instead of actions
2. Memory access ranges are too restrictive
3. Helper whitelist is too narrow

**Solution**: Check validation warnings, review access ranges

### Validation Warnings

**Symptom**: Parser prints warnings about structure

**Action**: Fix the policy structure according to the warning message

## Contact

For questions or issues, refer to the DRACO paper or check the DevPlan.md file.
