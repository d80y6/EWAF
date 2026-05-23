# Technical Debt Report - Sentinel WAF

## 1. Lack of Structured Logging
- The entire project uses the standard `log` package.
- No log levels (Debug, Info, Warn, Error).
- No correlation IDs in logs (making it hard to trace a request across Proxy and Control Plane).

## 2. Rudimentary Regex Management
- `Engine.LoadRules` re-compiles all regexes every time rules are updated.
- For a large rule set, this could cause significant latency spikes in the proxy every 30 seconds.

## 3. SQLite for Persistence
- The default configuration uses SQLite. While it supports GORM, it is not suitable for a distributed WAF where multiple Control Plane instances might need to share state.

## 4. Manual Metric Aggregation
- `ControlPlane.incrementStat` uses SQL `OnConflict` to increment counters.
- Under high load, this will put immense pressure on the database. Standard practice is to use a TSDB (Prometheus) or an in-memory aggregator (Redis/StatsD).

## 5. Protocol Support
- No support for HTTP/2 or gRPC inspection.
- No support for IPv6 in the eBPF layer.

## 6. Testing Gaps
- `engine_test.go` exists but `fuzz_test.go` and `benchmark.go` appear to be placeholders or minimal.
- No integration tests that span Proxy + Control Plane + DB.
