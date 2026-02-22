# Conditional Policy Node Design Principles

## Core Principle

**Any node (leaf, intermediate, or root) can have `memory_access` actions.**
**Only leaf and intermediate nodes should have `memory_conditions` guards.**
**Root nodes should have only actions, no conditions.**

## Rationale

### Why Any Node Can Have memory_access

Memory access enforcement can happen at any level in the policy tree:

1. **Leaf nodes**: Base conditions with access restrictions
   - Example: "If packet is readable, only allow reads to header (bytes 0-54)"

2. **Intermediate nodes**: Conditional access based on earlier checks
   - Example: "If packet is IPv4 (condition), then MAC addresses are read-only (action)"
   - Example: "If HTTP port (condition), then entire packet is read-only (action)"

3. **Root nodes**: Final enforcement without additional conditions
   - Example: "Enforce helper whitelist" (no conditions, just action)

### Why Root Nodes Should Not Have memory_conditions

Root nodes represent final policies to enforce. Conditions should be in their dependencies:

**Bad (condition at root):**
```json
{
  "enforce_policy": {
    "dependency": [],
    "memory_conditions": [
      { "offset": 12, "size": 2, "value": "0x0800" }
    ],
    "memory_access": [...]
  }
}
```

**Good (condition at intermediate, action at root):**
```json
{
  "check_ipv4": {
    "dependency": [],
    "memory_conditions": [
      { "offset": 12, "size": 2, "value": "0x0800" }
    ]
  },
  "enforce_policy": {
    "dependency": ["check_ipv4"],
    "dependency_logic": "AND",
    "memory_access": [...]
  }
}
```

## Node Type Summary

| Node Type | Can Have memory_conditions | Can Have memory_access | Can Have return_value_rules |
|-----------|---------------------------|------------------------|----------------------------|
| Leaf | Yes (recommended) | Yes | No |
| Intermediate | Yes (recommended) | Yes | No |
| Root | No (use deps instead) | Yes | Yes |

## Common Patterns

### Pattern 1: Condition → Action (Match-Action)
```json
{
  "check_ipv4": {
    "dependency": [],
    "memory_conditions": [{"offset": 12, "size": 2, "value": "0x0800"}]
  },
  "enforce_readonly": {
    "dependency": ["check_ipv4"],
    "dependency_logic": "AND",
    "memory_access": [{"read-access": ["*"], "write-access": ["x"]}]
  }
}
```

### Pattern 2: Progressive Restrictions (Intermediate with Actions)
```json
{
  "check_ipv4": {
    "dependency": [],
    "memory_conditions": [{"offset": 12, "size": 2, "value": "0x0800"}],
    "memory_access": [{"read-access": ["*"], "write-access": ["12-1500"]}]
  },
  "check_http": {
    "dependency": ["check_ipv4"],
    "dependency_logic": "AND",
    "memory_conditions": [{"offset": 36, "size": 2, "value": "0x0050"}],
    "memory_access": [{"read-access": ["*"], "write-access": ["x"]}]
  },
  "final_policy": {
    "dependency": ["check_http"],
    "dependency_logic": "AND",
    "allowed_helpers": ["bpf_map_lookup_elem"]
  }
}
```

### Pattern 3: Multiple Conditions, Single Action (OR Logic)
```json
{
  "check_ipv4": {
    "dependency": [],
    "memory_conditions": [{"offset": 12, "size": 2, "value": "0x0800"}]
  },
  "check_ipv6": {
    "dependency": [],
    "memory_conditions": [{"offset": 12, "size": 2, "value": "0x86DD"}]
  },
  "enforce_readonly": {
    "dependency": ["check_ipv4", "check_ipv6"],
    "dependency_logic": "OR",
    "memory_access": [{"read-access": ["*"], "write-access": ["x"]}]
  }
}
```

## Validation

The parser warns if:
- A root node has `memory_conditions` (should use intermediate nodes)
- Design encourages separation of concerns: conditions in dependencies, actions at roots

## Benefits

1. **Flexibility**: Actions can be enforced at any level based on conditions
2. **Composability**: Build complex policies from simple condition + action nodes
3. **Clarity**: Clear separation between "when" (conditions) and "what" (actions)
4. **Reusability**: Same condition node can be used by multiple action nodes

## See Also

- CONDITIONAL_POLICY_SPEC.md - Full technical specification
- conditional_constraints_09_intermediate_memory_access.json - Example with intermediate actions
- CONDITIONAL_POLICY_INTERMEDIATE_MEMORY_ACCESS.md - Implementation details
