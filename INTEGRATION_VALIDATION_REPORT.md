# Integration Validation Report - Sentinel WAF

## Component Connectivity
- **Proxy to Control Plane**: Verified. Proxy fetches rules and policies at startup and reports stats via HTTP.
- **Proxy to Target**: Verified. Proxy forwards traffic to `TARGET_URL` (although in tests it mostly blocked due to aggressive anomaly detection).
- **Control Plane to DB**: Verified. CP uses GORM with SQLite (or Postgres) to persist rules, stats, and security events.

## Real-time Rule Updates
- **Status**: **WORKING (POLLING)**
- **Verification**: Proxy log shows "Successfully updated X rules from control plane". Updates occur every 30 seconds.

## Telemetry Flow
- **Status**: **PARTIALLY WORKING / FRAGILE**
- **Verification**: Stats increments are visible in the Control Plane API after Proxy requests.
- **Issues**:
  - The proxy blocks its OWN `/health` endpoint because `DetectAnomaly` is too aggressive (entropy of "/health" + empty body score).
  - Telemetry reporting is done in a background goroutine via HTTP POST, which lacks backpressure and retry logic.

## Event Propagation
- **Status**: **VERIFIED**
- **Verification**: `SecurityEvent` records are created in the database when a request is blocked or an anomaly is detected.
