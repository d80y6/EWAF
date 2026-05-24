# Attack Simulation Results - Sentinel WAF

## 1. Test Suite Results
- **SQLi**: 10/10 blocked.
- **XSS**: 9/10 blocked (Double encoding bypassed).
- **RCE**: 5/5 blocked.
- **Anomaly**: 8/10 benign high-entropy paths **INCORRECTLY BLOCKED**.

## 2. Evidence
- See `proxy.log` for 403 responses to attack payloads.
- See `RED_TEAM_REPORT.md` for specific bypass evidence.
