| Spec | Baseline verdict | Pruned verdict | Match | Base IR | Pruned IR | Base paths | Pruned paths | Base insns | Pruned insns |
|---|---|---|---|---|---|---|---|---|---|
| constraints.empty | VALID | VALID | YES | 18538 | 15253 | 7 | 7 | 14943 | 14943 |
| constraints.helpers_only | VALID | VALID | YES | 18538 | 15461 | 7 | 7 | 14943 | 14943 |
| constraints.read_only_maps | INVALID | INVALID | YES | 18538 | 15253 | 11 | 11 | 13946415 | 14535810 |
| constraints.narrow_packet | VALID | VALID | YES | 18538 | 15253 | 6 | 6 | 21437 | 21437 |
| constraints.full | VALID | VALID | YES | 18538 | 15253 | 9 | 11 | 14485612 | 14467723 |
