# Red Team Report - Sentinel WAF

## 1. Attack Simulations
- **SQL Injection**: Blocked. The regex-based engine caught standard payloads and even some URL-encoded variants.
- **XSS**: Blocked. Tag-based detection is effective for simple payloads.
- **RCE**: Blocked. Unix shell patterns are heavily weighted and trigger blocks.
- **Path Traversal**: Blocked.

## 2. Vulnerability Findings

### High: Aggressive Anomaly Detection DoS
The `DetectAnomaly` function is so aggressive that it blocks legitimate traffic (like `/health`) and even its own management traffic if it were to flow through the proxy. An attacker can trigger a permanent block for legitimate users by inducing "high entropy" in their requests.

### High: Request Body Memory Exhaustion
Sending a body larger than `MaxBodySize` (10MB) is blocked, but sending exactly 10MB repeatedly causes significant memory pressure because `io.ReadAll` is used. Multiple concurrent large requests can lead to OOM.

### Medium: Default Secret Exposure
The default JWT secret "sentinel-default-secret" is hardcoded in the Control Plane seeding logic. Any deployment that doesn't change this is vulnerable to full JWT bypass/forgery.

### Medium: Unicode/Encoding Evasions
While basic URL encoding was blocked by the broad regexes, more sophisticated evasions (e.g., specific Unicode homoglyphs or multi-byte sequences that decode to `/` or `.`) are likely to bypass the rudimentary normalization in `parser.go`.

## 3. Tool Results
- `scripts/test_waf.sh`: All tests returned 403 (Blocked), indicating high (perhaps too high) detection for these specific payloads.
