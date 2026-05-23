# System Risk Map - Sentinel WAF

## Critical Risks
1. **Single Point of Failure (SPOF)**:
   - **Control Plane**: Centralized for all configuration. If it fails, new rules cannot be deployed.
   - **Database**: Default uses SQLite, which is not suitable for distributed/high-availability production.
2. **Scalability Bottlenecks**:
   - **Stats Reporting**: Proxy performs an HTTP POST for every security event. At 100k+ RPS with many events, the Control Plane will likely collapse.
   - **Regex Engine**: Standard Go `regexp` is used. This can be a bottleneck compared to specialized engines like Hyperscan.
3. **Security Risks**:
   - **Bypassable Normalization**: Path normalization in `parser.go` is rudimentary (recursive `//` collapse but lacks comprehensive Unicode/encoding handling).
   - **XDP Block List Limits**: The hash map has a fixed size of 10,240 entries. A large-scale botnet could easily overflow this.
4. **Operational Risks**:
   - **Rule Update Latency**: 30-second poll interval for rules means a "kill switch" or emergency block takes up to 30 seconds to propagate.
   - **Memory Pressure**: `io.ReadAll` with `MaxBodySize` (10MB) per request can lead to OOM under high concurrency.
