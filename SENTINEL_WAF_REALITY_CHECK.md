# Sentinel WAF: Engineering Reality Check

**Assessment Date:** May 2026
**Status:** Hardened Production Candidate (Self-Claimed) | **Actual Status:** High-Quality Prototype / MVP

## Executive Summary
Sentinel WAF is a well-structured project with a solid foundation in Go, but it currently suffers from "feature-completeness inflation." While the core proxy and regex-based WAF engine are functional and performant, the advanced features (ML, eBPF, WASM) are either mocked, non-functional in standard environments, or partially integrated.

---

## Subsystem Classification

| Subsystem | Classification | Reason |
| :--- | :--- | :--- |
| **Core Proxy / Forwarding** | **Production Ready** | Stable, uses `sync.Pool`, handles 2800+ RPS on localhost with minimal overhead. |
| **Regex WAF Engine** | **Production Ready** | Functional, passes security unit tests, correctly blocks SQLi/XSS. |
| **Rule Synchronization** | **Production Ready** | Reliable polling mechanism from Control Plane to Edge Proxy. |
| **API Security (JWT)** | **Mostly Functional** | Blocks invalid tokens correctly, but relies on insecure fallbacks if env vars are missing. |
| **Anomaly Detection** | **Prototype Quality** | Uses basic entropy/binary heuristics. Not "true" ML in its current runtime state. |
| **Persistence (Control Plane)**| **Mostly Functional** | GORM/SQLite works for small scale but is a scalability bottleneck. |
| **GraphQL Protection** | **Partial Implementation**| Logic exists in `pkg/engine/graphql.go` but failed to trigger during nested attack simulation. |
| **Isolation Forest** | **Skeleton / Placeholder**| Math is implemented, but no training, loading, or persistence logic exists. |
| **ONNX Inference** | **Skeleton / Placeholder**| `onnx.go` is a hardcoded stub returning `0.5`. No actual model loading. |
| **WASM Sandbox** | **Skeleton / Placeholder**| Library (`wazero`) is initialized but **NOT** integrated into the proxy request flow. |
| **eBPF / XDP Firewall** | **Non-Functional** | Fails to load without `CAP_NET_ADMIN`. No graceful fallback or user-space parity. |
| **Distributed Sync** | **Non-Functional** | Architecture assumes a single CP/DB. No cross-region or cluster-wide sync found. |

---

## Detailed Engineering Assessment

### 1. What components genuinely work end-to-end?
*   **Request Proxying:** The core `httputil.ReverseProxy` integration is solid.
*   **Signature-based WAF:** Regex rules are correctly loaded and enforced.
*   **Telemetry Reporting:** Proxy asynchronously (mostly) reports stats to the Control Plane.
*   **JWT Enforcement:** Successfully blocks unauthorized access to `/api` paths.

### 2. What components only appear implemented but are superficial?
*   **ML-based Anomaly Detection:** Marketed as advanced ML, but actually relies on `CalculateEntropy` and `binaryRatio` (heuristics).
*   **API Inspector:** Currently limited to simple path prefix matching and JWT checks; lacks deep schema validation.

### 3. Which features are mocked, simulated, stubbed, or incomplete?
*   **ONNX Engine:** `Predict` is a hardcoded `return 0.5`.
*   **Isolation Forest:** A "dead" algorithm with no data pipeline to feed it.
*   **WASM Plugins:** The infrastructure exists in `pkg/`, but the `Proxy` never calls it.

### 4. Which integrations are not truly operational?
*   **eBPF/XDP:** Requires host-level privileges that break in standard Docker/K8s deployments. It is currently "code-complete" but "runtime-broken."
*   **GeoIP:** Hardcoded to "Unknown" if the external database file is missing (which it is by default).

### 5. Which parts would fail under real production traffic?
*   **Control Plane Database:** SQLite will lock under high-concurrency writes from multiple proxies reporting stats.
*   **Telemetry Batching:** The flusher is simple and lacks robust retry/backoff logic; a CP outage could pressure proxy memory if the queue grows.

### 6. Which parts are unsafe from a security perspective?
*   **JWT Secret Fallback:** Reverting to a hardcoded secret if `SENTINEL_JWT_SECRET` is missing is a critical vulnerability.
*   **Regex Bypass:** Signature-only WAFs are notoriously easy to bypass with novel encodings that exceed the 3-pass normalization.

### 7. Which components are not scalable yet?
*   **The Control Plane:** It is a single point of failure and a performance bottleneck for distributed proxies.
*   **Rule Engine:** Linear regex matching against all rules for every request will scale poorly as the rule-set grows to thousands.

### 8. Which claims in the architecture or reports are exaggerated?
*   **"AI-Powered Protection":** There is no AI in the hot-path. It is a regex engine with entropy counters.
*   **"Kernel-level Security":** eBPF is an optional, privileged component that is likely disabled in 90% of real-world deployments.

### 9. Which subsystems are enterprise-grade today?
*   **None.** The system lacks the observability (OpenTelemetry is partially present but not robust), auditing, and multi-cluster management required for enterprise use.

### 10. What would break first in a real-world deployment?
*   **The Telemetry Pipe.** High traffic will flood the `/api/stats/report` endpoint, causing the Control Plane to OOM or the SQLite DB to lock, eventually causing backpressure on the Edge Proxies.

---

## Top Risks
1.  **Architectural Risk:** SQLite dependency in the Control Plane.
2.  **Security Risk:** False sense of security from mocked ML features.
3.  **Scalability Risk:** Centralized telemetry reporting without a message broker (Kafka/Redis).

## Final Verdict
**Is Sentinel WAF ready for real-world production today?**
**NO.** It is an excellent starting point for an engineering team to build upon, but it should be treated as a **Beta/MVP**. Deploying it as-is in front of enterprise traffic would result in either a scalability collapse (telemetry) or a security bypass (mocked ML).

**What would survive:** The Edge Proxy forwarding and basic regex blocking.
**What would fail:** The ML claims, the eBPF blocking, and the Control Plane under load.
