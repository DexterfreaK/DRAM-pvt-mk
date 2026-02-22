# Conditional Policy Constraint File — Technical Spec

Concise reference for the JSON constraint file used when KLEE runs with `-enable-conditional-policy=true` and `-config-file=<path>`. Build with `-DENABLE_CONDITIONAL_POLICY=ON`.

---

## 1. Top-Level Structure

```json
{
  "conditional_policies": {
    "<policy_name>": { <PolicyNode> },
    ...
  }
}
```

- **`conditional_policies`** (required): Object mapping policy names to policy nodes. Policy names are referenced in `dependency` arrays; names are case-sensitive.

---

## 2. Policy Node Fields

| Field | Type | Required | Applies to | Description |
|-------|------|----------|------------|-------------|
| `dependency` | string[] | Yes | All | Policy names that must be evaluated first. Empty `[]` for leaves. |
| `dependency_logic` | `"AND"` \| `"OR"` | **Yes if `dependency` non-empty** | Nodes with deps | How to combine dependencies: all satisfied (AND) or at least one (OR). No default; parser errors if missing. |
| `memory_conditions` | array | No | All | Value checks (guards) for tree traversal. Determines if policy applies. |
| `memory_access` | array | No | All | Access enforcement (read/write ranges) on packet memory. Checked during memory operations. |
| `map_access` | array | No | All | Map name + allowed access. Checked during policy evaluation. |
| `allowed_helpers` | string[] | No | All | Whitelist of helper names; `"*"` = all allowed. Checked during policy evaluation. |
| `return_value_rules` | object | No | Root only | Allowed/forbidden program return values (e.g. XDP_*). Checked at program exit. |

**Node roles:**

- **Leaf**: `dependency: []`. Can have `memory_conditions`, `memory_access`, `map_access`, `allowed_helpers`.
- **Intermediate**: Has `dependency` and is referenced by others. Can have `memory_conditions`, `memory_access`, `map_access`, `allowed_helpers`.
- **Root**: Not a dependency of any other policy. Should have `memory_access`, `map_access`, `allowed_helpers`, and/or `return_value_rules`. Should NOT have `memory_conditions` (use intermediate nodes for conditions).

**Design principle:**
- **Conditions** (`memory_conditions`): Used in leaf/intermediate nodes to determine when policies apply (guards/predicates).
- **Actions** (`memory_access`, `map_access`, `allowed_helpers`, `return_value_rules`): Enforcement rules that can be at any level. Root nodes typically have only actions.

**Enforcement timing:**
- `memory_conditions`: Checked during policy evaluation to determine applicability.
- `memory_access`: Checked during actual memory read/write operations when the policy is applicable (at any node level).
- `map_access` / `allowed_helpers`: Checked during policy evaluation (at any node level).
- `return_value_rules`: Checked only at program exit for root policies.

Validation warns if a root has `memory_conditions` (conditions should be in intermediate nodes).

---

## 3. Field Formats

### 3.1 `memory_conditions`

Array of predicate objects. Each specifies an expected value at a fixed packet offset.

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

All conditions in the array must hold (AND) for the policy’s conditions to be satisfied.

### 3.2 `memory_access`

Array of access rules. Applied when the policy is applicable (after dependency and condition checks).

```json
"memory_access": [
  {
    "read-access": ["*"],
    "write-access": ["x"]
  }
]
```

| Key | Values | Meaning |
|-----|--------|--------|
| `read-access` | `["*"]` or list of `"start-end"` | `"*"` = any read; ranges = allowed read intervals (bytes). |
| `write-access` | `["*"]` or `["x"]` | `"*"` = any write; `"x"` = no writes allowed. |

Example: `"read-access": ["0-54", "100-200"]` allows only those byte ranges.

### 3.3 `map_access`

Array of map rules. Map names must match program map definitions.

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

### 3.4 `allowed_helpers`

List of helper function names, or `["*"]` to allow all. Any helper used in a state must appear in the list (or `"*"`) for each applicable root policy.

```json
"allowed_helpers": ["*"]
"allowed_helpers": ["bpf_map_lookup_elem", "bpf_map_update_elem"]
```

### 3.5 `return_value_rules`

Object with optional `allowed` and/or `forbidden` arrays of integer return values. Checked at program exit for root policies that are applicable.

```json
"return_value_rules": {
  "allowed": [2],
  "forbidden": [0, 4]
}
```

- **`allowed`**: If non-empty, return value must be in this list (e.g. `[2]` = XDP_PASS only).
- **`forbidden`**: Return value must not be in this list.
- If both present, `allowed` is applied and `forbidden` further restricts.
- XDP reference: 0=ABORTED, 1=DROP, 2=PASS, 3=TX, 4=REDIRECT.

---

## 4. Evaluation Semantics

- **Tree structure**: Dependencies form a DAG. Roots are policies that no other policy depends on.
- **Evaluation order**: For each root, evaluation is bottom-up: 
  1. Recursively evaluate dependencies (with `dependency_logic`)
  2. Check `memory_conditions` at each node (determines applicability)
  3. If applicable, check `memory_access`, `map_access`, `allowed_helpers` at that node
- **dependency_logic**: With `"AND"`, all listed dependencies must be satisfied. With `"OR"`, at least one must be satisfied.
- **No caching**: Policies are re-evaluated on each check to ensure correctness as runtime state changes (helpers called, maps accessed, memory values constrained).
- **Memory operations**: On packet load/store, root policies are evaluated with memory operation context (offset, bytes, read/write). During tree traversal, **each node** (leaf, intermediate, or root) can check its `memory_access` rules against the current operation. This enables conditional memory access policies like "if packet is IPv4 (condition at intermediate), then MAC addresses are read-only (action at intermediate)." Violation at any level terminates the state.
- **Return values**: Checked only at program exit for root policies that are applicable.
- **Design pattern**: Leaf/intermediate nodes use `memory_conditions` to determine when to apply their `memory_access` rules. Root nodes typically have only actions (no conditions), relying on their dependencies for conditional logic.

---

## 5. Examples

### 5.1 Minimal: one condition → one action (match-action)

If EtherType is IPv4 (offset 12, 2 bytes = 0x0800), then packet is read-only (no writes).

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

### 5.2 Multi-level tree

Chain: base → IPv4 → specific IP → enforce no write. Another branch: IPv4 → specific port → restricted helpers.

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

### 5.3 Conditional memory access (intermediate node with memory_access)

Demonstrates memory_access rules on intermediate nodes: if you read the EtherType field (bytes 12-13), then you cannot write to the MAC addresses (bytes 0-11).

```json
{
  "conditional_policies": {
    "check_read_ethertype": {
      "dependency": [],
      "memory_conditions": [
        { "offset": 12, "size": 2, "value": "0x0800" }
      ],
      "memory_access": [
        {
          "read-access": ["*"],
          "write-access": ["12-1500"]
        }
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

**Semantics**: The intermediate node `check_read_ethertype` has both `memory_conditions` (checks if EtherType is IPv4) and `memory_access` (forbids writes to bytes 0-11). When a memory operation occurs, if the EtherType is IPv4, writes to MAC addresses are blocked.

### 5.4 OR logic and return values

If IPv4 or IPv6, enforce read-only. Separate roots: trusted IP must return XDP_PASS; untrusted (IPv4, not trusted) must return DROP or PASS only.

```json
{
  "conditional_policies": {
    "check_ipv4": {
      "dependency": [],
      "memory_conditions": [
        { "offset": 12, "size": 2, "value": "0x0800" }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "check_ipv6": {
      "dependency": [],
      "memory_conditions": [
        { "offset": 12, "size": 2, "value": "0x86DD" }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "check_trusted_ip": {
      "dependency": ["check_ipv4"],
      "dependency_logic": "AND",
      "memory_conditions": [
        { "offset": 26, "size": 4, "value": "0x0A000001" }
      ],
      "map_access": [],
      "allowed_helpers": ["*"]
    },
    "enforce_readonly_for_ip_packets": {
      "dependency": ["check_ipv4", "check_ipv6"],
      "dependency_logic": "OR",
      "memory_access": [
        { "read-access": ["*"], "write-access": ["x"] }
      ],
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

---

## 6. Invocation

```bash
klee ... -enable-conditional-policy=true -config-file=conditional_constraints_06_match_action_minimal.json ...
```

Example from `examples/fw`:

```bash
make verify CONSTRAINTS=conditional_constraints_06_match_action_minimal.json
```

---

## 7. Quick Reference

| Concept | Detail |
|--------|--------|
| **Conditions** | `memory_conditions`: offset/size/value; determines if policy applies (guards). Used in leaf/intermediate nodes. |
| **Actions** | `memory_access`, `map_access`, `allowed_helpers`, `return_value_rules`: enforcement rules. Can be at **any node level**. |
| **Memory Access** | `memory_access`: read/write ranges; enforced during memory operations at any node level (leaf/intermediate/root). |
| **Return Values** | `return_value_rules`: enforced only at program exit for root policies. |
| **dependency_logic** | Mandatory when `dependency` is non-empty; `"AND"` or `"OR"`. |
| **Root nodes** | No other policy depends on them. Should have only actions (no `memory_conditions`). |
| **Leaf/Intermediate** | Can have both `memory_conditions` (guards) and `memory_access` (actions) for conditional policies. |
| **Packet offsets** | 0–5: dst MAC; 6–11: src MAC; 12–13: EtherType; 26–29: IPv4 src; 30–33: IPv4 dst; 34–35: src port; 36–37: dst port. |

See also: `CONDITIONAL_POLICY_README.md`, `DOCUMENTATION.md`, `RETURN_VALUE_IMPLEMENTATION_SUMMARY.md`, `DevPlan.md`.
