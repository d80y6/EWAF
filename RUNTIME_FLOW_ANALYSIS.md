# Runtime Flow Analysis - Sentinel WAF

## 1. Request Lifecycle
1. **Kernel (XDP)**: Packet checked against `block_list` map. IPv4 and IPv6 supported.
2. **Proxy (ServeHTTP)**: Request body fully read into memory (`io.ReadAll`).
3. **Engine (InspectRequest)**:
   - Normalization (Incomplete: single pass decoding).
   - Anomaly Detection (Aggressive: entropy/binary ratio).
   - API Security (JWT validation with hardcoded secret).
   - Signature Matching (Iterates through ALL rules regardless of tenant).
4. **Proxy (Forward)**: If allowed, request is forwarded to `TARGET_URL`.
5. **Telemetry (Async)**: Background goroutine sends HTTP POST to Control Plane.

## 2. Failure Modes
- **CP Down**: Proxy starts with cached rules if available, but telemetry and updates fail.
- **OOM**: Multiple concurrent 10MB requests exhaust Proxy RAM.
- **False Positive**: Legitimate high-entropy data (tokens/files) triggers 403 Forbidden.
