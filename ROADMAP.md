# Sentinel WAF: ISP-Grade Production Roadmap

This roadmap outlines the necessary steps to transform the Sentinel WAF prototype into a carrier-grade security appliance suitable for ISP and high-scale enterprise environments.

## Phase 1: Security Hardening & Remediation (Immediate)
*   **Fix Normalization Pipeline**: Implement multi-pass URL decoding and recursive path traversal resolution to prevent bypasses.
*   **Eliminate Hardcoded Secrets**: Move JWT secrets, DB credentials, and API keys to an external Vault or Environment Variables.
*   **Buffer Safety**: Replace `io.ReadAll` with a streaming body processor and `sync.Pool` for memory efficiency to prevent OOM attacks.
*   **Tenant Isolation**: Enforce `TenantID` filtering in the inspection engine to ensure strict data and rule segregation.

## Phase 2: Scalability & Infrastructure (Carrier-Grade)
*   **Database Migration**: Replace SQLite with a high-availability PostgreSQL cluster or CockroachDB for global rule consistency.
*   **Stateless Scaling**: Ensure the Edge Proxy is completely stateless to allow horizontal scaling behind BGP/Anycast.
*   **Message Bus Integration**: Use NATS JetStream or Kafka for reliable, high-volume telemetry and event reporting.
*   **K8s Hardening**: Update Helm charts with correct eBPF capabilities (`CAP_NET_ADMIN`, `CAP_BPF`) and Seccomp profiles.

## Phase 3: Intelligent Detection (Real ML)
*   **Authentic ML Models**: Replace stubs with trained Isolation Forest models and a real ONNX-based classification engine.
*   **Model Lifecycle (MLOps)**: Implement automated model retraining and distribution from the Control Plane to Edge Proxies.
*   **Behavioral Baselining**: Add time-series analysis for per-IP/per-Tenant traffic patterns to detect low-and-slow DDoS.

## Phase 4: ISP/Network Integration
*   **BGP/Flowspec Integration**: Implement automatic BGP Flowspec advertisements to drop massive DDoS attacks at the ISP edge before they reach the WAF.
*   **VLAN/QinQ Support**: Add 802.1Q support to the eBPF/XDP engine for multi-tenant ISP backbone visibility.
*   **Hardware Offload**: Explore XDP hardware offload to compatible NICs (e.g., Netronome, Intel) for sub-microsecond latency.

## Phase 5: Observability & Compliance
*   **Full SIEM Integration**: Support Syslog, CEF, and direct exporters for Splunk, Elastic, and Datadog.
*   **Audit Logging**: Implement immutable audit trails for rule changes and administrative actions.
*   **Performance Profiling**: Add continuous profiling (pprof) and Prometheus metrics for every stage of the inspection pipeline.
