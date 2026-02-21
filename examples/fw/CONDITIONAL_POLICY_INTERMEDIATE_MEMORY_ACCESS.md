# Conditional Policy: Memory Access at All Node Levels

## Summary

Fixed the implementation to allow `memory_access` rules at **all node levels** (leaf, intermediate, and root), not just at root nodes. This enables powerful conditional memory access policies like "if you accessed byte X, then accessing byte Y is forbidden."

## Changes Made

### 1. Code Changes

#### `klee/lib/Core/Executor.h`
- Updated `evaluateConditionalPolicy()` signature to accept optional memory operation context:
  - `ref<Expr> memoryOpOffset` (default: null)
  - `unsigned memoryOpBytes` (default: 0)
  - `bool memoryOpIsWrite` (default: false)
- Updated comments to reflect that `checkMemoryAccessRule()` is used for all nodes, not just roots

#### `klee/lib/Core/Executor.cpp`
- Modified `evaluateConditionalPolicy()` to:
  - Pass memory operation context down to dependencies during recursive evaluation
  - Check `memory_access` rules at **every node level** when memory context is provided
  - Record violations with node name for better debugging
- Simplified `handlePacketDataStore()` and `handlePacketDataLoad()`:
  - Removed duplicate memory access checking at root level
  - Now rely on `evaluateConditionalPolicy()` to check memory access at all levels during tree traversal
  - Pass memory operation context (offset, bytes, isWrite) to evaluation

### 2. Documentation Changes

#### `examples/fw/CONDITIONAL_POLICY_SPEC.md`
- **Policy Node Fields table**: Updated to show all fields can be used at all node levels (except `return_value_rules` which is root-only)
- **Node roles**: Clarified that leaf, intermediate, and root nodes can all have `memory_access`, `memory_conditions`, `map_access`, and `allowed_helpers`
- **Enforcement timing**: Added section explaining when each constraint type is checked
- **Evaluation Semantics**: Updated to explain that memory_access is checked at all levels during memory operations
- **Example 5.3**: Added new example demonstrating intermediate node with memory_access
- **Quick Reference**: Updated to clarify that memory_access is enforced at any node level

### 3. New Example File

#### `examples/fw/conditional_constraints_09_intermediate_memory_access.json`
Demonstrates a multi-level policy where:
1. `check_ipv4`: Leaf node checks if packet is IPv4
2. `restrict_mac_write_if_ipv4`: Intermediate node forbids writes to MAC addresses (bytes 0-11) if IPv4
3. `check_http_port`: Intermediate node checks for HTTP port and makes entire packet read-only
4. `enforce_final_policy`: Root node restricts allowed helpers

## Use Cases

### 1. Conditional Access Based on Previous Reads
"If you read the EtherType field, you cannot modify MAC addresses"

```json
{
  "check_read_ethertype": {
    "dependency": [],
    "memory_conditions": [
      { "offset": 12, "size": 2, "value": "0x0800" }
    ],
    "memory_access": [
      { "read-access": ["*"], "write-access": ["12-1500"] }
    ]
  }
}
```

### 2. Progressive Restrictions
"If IPv4, restrict MAC writes. If also HTTP, make entire packet read-only"

```json
{
  "check_ipv4": {
    "dependency": [],
    "memory_conditions": [
      { "offset": 12, "size": 2, "value": "0x0800" }
    ],
    "memory_access": [
      { "read-access": ["*"], "write-access": ["12-1500"] }
    ]
  },
  "check_http": {
    "dependency": ["check_ipv4"],
    "dependency_logic": "AND",
    "memory_conditions": [
      { "offset": 36, "size": 2, "value": "0x0050" }
    ],
    "memory_access": [
      { "read-access": ["*"], "write-access": ["x"] }
    ]
  }
}
```

### 3. Access-Based Policies
"If you accessed IP header, you can only read (not write) TCP header"

```json
{
  "accessed_ip_header": {
    "dependency": [],
    "memory_conditions": [],
    "memory_access": [
      { "read-access": ["*"], "write-access": ["0-33"] }
    ]
  }
}
```

## Implementation Details

### How It Works

1. **Memory Operation Occurs**: When the program reads/writes packet memory, `handlePacketDataStore/Load()` is called

2. **Root Policy Evaluation**: For each root policy, `evaluateConditionalPolicy()` is called with memory operation context (offset, bytes, isWrite)

3. **Tree Traversal**: During evaluation:
   - Dependencies are evaluated recursively (bottom-up)
   - Memory operation context is passed down to all dependencies
   - Each node checks its `memory_conditions` (applicability)
   - Each node checks its `memory_access` rules against the current operation
   - If any node's memory_access is violated, the entire tree evaluation fails

4. **Violation Handling**: If evaluation returns false, the state is terminated with a policy violation message

### Key Benefits

1. **More Expressive Policies**: Can express complex conditional access patterns
2. **Better Granularity**: Different restrictions at different levels of the tree
3. **Cleaner Semantics**: Each node can have both guards (conditions) and invariants (access rules)
4. **Research Value**: Aligns with formal verification concepts of preconditions and postconditions

## Testing

To test with the new example:

```bash
cd examples/fw
make verify CONSTRAINTS=conditional_constraints_09_intermediate_memory_access.json
```

Expected behavior:
- If packet is IPv4: writes to bytes 0-11 (MAC addresses) are forbidden
- If packet is IPv4 and HTTP (port 80): entire packet is read-only
- If packet is IPv4, HTTP, and policy applies: only `bpf_map_lookup_elem` and `bpf_map_update_elem` helpers allowed

## Backward Compatibility

✓ All existing constraint files continue to work
✓ Root-only memory_access policies still function correctly
✓ No breaking changes to JSON format
✓ Legacy `memory` block format still supported

## Files Modified

1. `klee/lib/Core/Executor.h` - Function signatures and comments
2. `klee/lib/Core/Executor.cpp` - Evaluation logic and memory hooks
3. `examples/fw/CONDITIONAL_POLICY_SPEC.md` - Documentation updates
4. `examples/fw/conditional_constraints_09_intermediate_memory_access.json` - New example (created)
5. `examples/fw/CONDITIONAL_POLICY_INTERMEDIATE_MEMORY_ACCESS.md` - This summary (created)
