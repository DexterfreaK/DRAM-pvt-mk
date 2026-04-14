| Spec | Baseline verdict | Pruned verdict | Match | Baseline IR | Pruned IR |
|---|---|---|---|---|---|
| policy_Q1_all_allowed | VALID | VALID | YES | 5152 | 2176 |
| policy_Q2_write_excludes_totlen | INVALID(pkt-write) | INVALID(pkt-write) | YES | 5152 | 2176 |
| policy_Q3_exact_totlen | INVALID(pkt-write) | INVALID(pkt-write) | YES | 5152 | 2176 |
| policy_Q4_read_too_narrow | INVALID(pkt-read) | INVALID(pkt-read) | YES | 5152 | 2176 |
| policy_Q5_no_writes_allowed | INVALID(pkt-write) | INVALID(pkt-write) | YES | 5152 | 2176 |
