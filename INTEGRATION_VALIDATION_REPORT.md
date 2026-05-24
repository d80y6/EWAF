# Integration Validation Report - Sentinel WAF

## 1. Connectivity
- **Proxy <-> Control Plane**: Verified. Polling works, rules and policies are fetched every 30s.
- **Proxy <-> Target**: Verified. Successful forwarding confirmed for benign traffic.
- **Control Plane <-> DB**: Verified. GORM/SQLite creates tables and seeds rules on startup.

## 2. Telemetry Flow
- **Verification**: Stats increments confirmed in Control Plane `/api/stats` after security events.
- **Risk**: Synchronous HTTP reporting in background goroutines lacks buffering/batching.

## 3. Anomaly Detection Runtime
- **Verification**: `DetectAnomaly` is active and triggers blocks.
- **Finding**: Verified that high-entropy paths (UUIDs) and binary payloads are incorrectly blocked.

## 4. Health Check Masking
- **Finding**: The Proxy's `ServeHTTP` handles ALL requests including `/health`, making the application-level health check defined in `cmd/proxy/main.go` unreachable (404/403).
