# Architecture Review - Sentinel WAF

## 1. Service Boundaries & Coupling
- **Edge Proxy**: Acting as both ingress and WAF engine host. Highly coupled to the Control Plane for rules and API policies via polling (30s interval).
- **Control Plane**: Central point of failure for configuration. Reliance on SQLite by default is a major production risk.
- **Data Flow**: High latency for large requests due to synchronous body buffering and multiple inspection passes (Signature, ML, API Security).

## 2. Multi-Tenancy Isolation
- **Finding**: **VIRTUALLY NON-EXISTENT**.
- While `model.Tenant` and `model.Rule.TenantID` exist, the `Engine.InspectRequest` function iterates over all rules in the `rules` slice, which are global. The `tenantRules` map is populated in `LoadRules` but NEVER used during inspection.
- **Risk**: Tenant A's rules will trigger for Tenant B's traffic.

## 3. Observability Architecture
- **Stats Reporting**: Proxy sends a background HTTP POST for EVERY anomaly or block. Under high load, this will overwhelm the Control Plane.
- **Logging**: Non-structured, basic Go logs. Difficult to aggregate in production.

## 4. Scalability
- **Request Buffering**: synchronous `io.ReadAll` of up to 10MB per request. 1000 concurrent requests could consume 10GB of RAM just for buffers.
- **Regex Bottleneck**: Uses Go's standard `regexp` library which is known for performance issues at scale compared to PCRE or Hyperscan.
