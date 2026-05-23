# Architecture Review - Sentinel WAF

## Service Boundaries
- **Edge Proxy**: Acts as the data plane. It handles TLS termination (not explicitly seen in code yet, mostly ListenAndServe :80), request inspection, and forwarding.
- **Control Plane**: Acts as the management plane. It manages rules, policies, and aggregates telemetry.
- **WAF Engine**: A library used by the Edge Proxy for deep packet inspection and anomaly detection.
- **eBPF/XDP**: Kernel-space component for high-speed packet filtering.

## Data Flow
1. **Request Ingress**: Packets hit the XDP program. If the source IP is in the `block_list` map, it's dropped.
2. **Proxy Processing**: `ServeHTTP` captures the request, reads the body, and passes it to the `Engine`.
3. **Engine Inspection**:
   - Threat Intel check.
   - ML Anomaly detection.
   - Signature-based rule matching.
   - API Security validation (JWT, etc.).
4. **Action**: If blocked, return 403. If allowed, forward to `TARGET_URL`.
5. **Telemetry**: Stats and events are reported asynchronously (via goroutine) to the Control Plane.

## Coupling
- **Tight Coupling**: The Proxy depends on the Control Plane for its initial rules and periodic updates. If the Control Plane is unreachable at startup, it might start with defaults (if any) or empty rules.
- **Telemetry Coupling**: The Proxy reports stats via HTTP POST to the Control Plane. While done in a goroutine, a slow Control Plane could lead to a large number of pending goroutines.

## Observability
- Integrated statistics reporting to a centralized database.
- Lacks structured logging (uses standard `log` package).
- Lacks distributed tracing (mentions it in README but not found in core logic yet).

## Multi-tenancy
- `model.Tenant` exists, but the `Engine` and `Proxy` logic for tenant isolation seems minimal or incomplete. `Engine` has `tenantRules` map but `InspectRequest` uses global `rules`.

## Deployment
- Docker Compose and Kubernetes manifests are provided.
- Kubernetes deployment uses a simple deployment for the proxy and control plane.
