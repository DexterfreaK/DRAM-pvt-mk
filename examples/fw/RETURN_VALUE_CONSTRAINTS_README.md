# Return Value Constraints Examples

This directory contains example JSON configuration files demonstrating the return value constraint feature in DRACO.

## Overview

Return value constraints allow you to specify policies that enforce restrictions on the return values of eBPF programs based on runtime conditions. This integrates with the existing conditional policy system - policies apply based on their dependencies and memory conditions, and when they apply, the return value rules are enforced.

## XDP Return Value Reference

| Constant | Value | Description |
|----------|-------|-------------|
| XDP_ABORTED | 0 | Error condition, packet should be dropped |
| XDP_DROP | 1 | Drop the packet |
| XDP_PASS | 2 | Pass the packet to the network stack |
| XDP_TX | 3 | Transmit the packet back out the same interface |
| XDP_REDIRECT | 4 | Redirect the packet to another interface |

## Example Files

### 1. `return_value_01_simple.json` - Basic Return Value Enforcement

**Use Case**: Only allow XDP_PASS (2) for IPv4 packets, forbid XDP_ABORTED (0) and XDP_REDIRECT (4).

**Policies**:
- `check_ipv4`: Checks if EtherType is IPv4 (0x0800)
- `pass_only_for_ipv4`: When IPv4 is detected, only allows return value 2 (XDP_PASS)

**Key Features**:
- `return_value_rules.allowed`: Whitelist of allowed return values
- `return_value_rules.forbidden`: Blacklist of forbidden return values

### 2. `return_value_02_multiple_policies.json` - OR Logic with Return Values

**Use Case**: For IPv4 OR IPv6 packets, only allow DROP (1) or PASS (2), forbid ABORTED, TX, and REDIRECT.

**Policies**:
- `check_ipv4`: Checks if EtherType is IPv4
- `check_ipv6`: Checks if EtherType is IPv6
- `ip_packets_pass_or_drop`: Uses OR logic - applies if either IPv4 or IPv6, restricts return values

**Key Features**:
- `dependency_logic: "OR"`: Policy applies if ANY dependency is satisfied
- Demonstrates combining multiple conditions with return value enforcement

### 3. `return_value_03_trusted_untrusted.json` - Conditional Return Values

**Use Case**: Trusted IPs (10.0.0.1) can only return XDP_PASS, while untrusted IPs can return DROP or PASS but not ABORTED, TX, or REDIRECT.

**Policies**:
- `check_ipv4`: Checks if EtherType is IPv4
- `check_trusted_ip`: Checks if source IP is 10.0.0.1
- `trusted_can_pass`: For trusted IPs, only XDP_PASS (2) is allowed
- `untrusted_must_drop_or_pass`: For all IPv4 (including untrusted), only DROP (1) or PASS (2) allowed

**Key Features**:
- Multiple policies with different dependencies
- Demonstrates how to enforce different return value rules based on packet characteristics

## JSON Schema

### Return Value Rules

```json
"return_value_rules": {
  "allowed": [1, 2],      // Whitelist: only these values are allowed
  "forbidden": [0, 4]     // Blacklist: these values are forbidden
}
```

- If `allowed` is specified and non-empty, the return value MUST be in this list
- If `forbidden` is specified, the return value MUST NOT be in this list
- Both can be used together (forbidden is checked first)

## How It Works

1. **Policy Applicability**: Determined by existing mechanisms:
   - `dependency`: Other policies that must be satisfied
   - `dependency_logic`: "AND" or "OR" for combining dependencies
   - `memory_conditions`: Value checks on packet data

2. **Return Value Capture**: The return value is captured when the eBPF program returns via `__record_ebpf_return_value()`

3. **Enforcement**: At program termination, for each applicable root policy:
   - Check if return value is in `allowed` list (if specified)
   - Check if return value is NOT in `forbidden` list
   - Report violations

4. **Integration with Existing Constraints**: Return value rules work alongside:
   - `allowed_helpers`: Whitelist of permitted helper functions
   - `map_access`: Permitted map operations
   - `memory_access`: Permitted memory read/write ranges

## Usage

To use these examples with KLEE:

```bash
cd examples/fw
make verify CONSTRAINTS=return_value_01_simple.json
```

The verification will check that the eBPF program's return value satisfies the specified constraints.

## Example Use Cases

### Enforce XDP_PASS for specific traffic
```json
{
  "check_http_traffic": {
    "dependency": [],
    "memory_conditions": [
      {"offset": 12, "size": 2, "value": "0x0800"},
      {"offset": 36, "size": 2, "value": "0x0050"}
    ]
  },
  "http_must_pass": {
    "dependency": ["check_http_traffic"],
    "dependency_logic": "AND",
    "return_value_rules": {"allowed": [2]}
  }
}
```

### Prevent ABORTED returns
```json
{
  "no_aborted_ever": {
    "dependency": [],
    "return_value_rules": {"forbidden": [0]}
  }
}
```

### Restrict return values for untrusted sources
```json
{
  "check_untrusted_network": {
    "dependency": [],
    "memory_conditions": [
      {"offset": 26, "size": 4, "value": "0xC0A80000"}
    ]
  },
  "untrusted_drop_only": {
    "dependency": ["check_untrusted_network"],
    "dependency_logic": "AND",
    "return_value_rules": {"allowed": [1]}
  }
}
```

## Design Notes

- **Simplified Design**: Return value rules are enforcement-only, not used for policy tree traversal
- **Root Policies Only**: Return value rules are checked on root policies (policies that are not dependencies of other policies)
- **Backward Compatible**: All code wrapped in `#ifdef CONDITIONAL_POLICY`
- **Integrates with Existing System**: Works alongside existing `allowed_helpers`, `map_access`, and `memory_access` constraints
