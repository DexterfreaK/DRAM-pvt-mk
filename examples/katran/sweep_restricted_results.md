RESTRICTED policy: constraints.selective_sym.relaxed.json  (sIP=12345 pinned, outer cap=300s)

| Case | Verdict | IR lines | Completed | Partial | Instructions | Wall ms | Pass guard |
|---|---|---:|---:|---:|---:|---:|---|
| baseline:none | PKT-READ-PROHIBITED(x1) | 18538 | 0 | 7 | 15031 | 385 | - |
| protocol | PKT-READ-PROHIBITED(x1) | 18541 | 0 | 7 | 15040 | 387 | - |
| dPort | PKT-READ-PROHIBITED(x1) | 18541 | 0 | 7 | 15040 | 391 | - |
| dIP | PKT-READ-PROHIBITED(x1) | 18543 | 0 | 7 | 15046 | 388 | - |
| sIP (relevant->guard) | PKT-READ-PROHIBITED(x1) | 18538 | 0 | 7 | 15031 | 385 | GUARD-FIRED |
| sIP+dPort | PKT-READ-PROHIBITED(x1) | 18541 | 0 | 7 | 15040 | 389 | GUARD-FIRED |

_policy file: constraints.selective_sym.relaxed.json_
