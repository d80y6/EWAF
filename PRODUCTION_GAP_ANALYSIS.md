# Production Gap Analysis - Sentinel WAF

## 1. Reliability & Scalability
- **Gap**: Control Plane uses SQLite as default, which is a single point of failure (SPOF) and cannot be scaled horizontally.
- **Gap**: Proxy uses synchronous `io.ReadAll` for up to 10MB bodies, risking OOM under high concurrency.
- **Requirement**: Use Postgres/RDS for CP and streaming/sync.Pool for Proxy request handling.

## 2. Observability
- **Gap**: Lacks structured logging (e.g., Zap, Zerolog).
- **Gap**: Custom HTTP POST for telemetry lacks buffering, retries, and backpressure.
- **Requirement**: Integrate Prometheus/Grafana and use a robust logging framework.

## 3. Performance
- **Gap**: overhead of ~83% for 1MB POST requests.
- **Gap**: Regex matching is a significant bottleneck.
- **Requirement**: Optimize hot paths and consider specialized regex engines like Hyperscan.
