# Red Team Report - Sentinel WAF

## 1. WAF Bypass Results
| Attack | Payload | Result | Bypass Method |
|--------|---------|--------|---------------|
| XSS | `<script>` | Blocked | N/A |
| XSS | `%253cscript` | **BYPASSED** | Double Encoding |
| SQLi | `1' OR '1'='1` | Blocked | N/A |
| SQLi | `1%20union/**/select%201` | Blocked | Regex broad coverage |
| RCE | `cat /etc/passwd` | Blocked | N/A |
| Path Traversal | `/api/../../etc/passwd` | Blocked | `QueryUnescape` + Regex |

## 2. API Security Review
- **JWT Bypass**: Attacker can use the hardcoded secret `s3ntinel-p0d-pr0ducti0n-s3cr3t-2025!` to sign their own tokens.
- **GraphQL**: Basic depth/complexity check exists but was not tested extensively for nested alias/fragment bypasses.

## 3. Anomaly Detection Abuse
- **Denial of Service**: An attacker can block legitimate traffic by sending high-entropy data that the WAF incorrectly classifies as an anomaly, potentially poisoning metrics or triggering broad IP blocks.
