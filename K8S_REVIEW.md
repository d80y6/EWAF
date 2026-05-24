# Kubernetes & SRE Review - Sentinel WAF

## 1. Deployment Risks
- **Privilege Gap**: eBPF/XDP requires elevated privileges (`CAP_NET_ADMIN`) which are not present in `deployments/k8s/`.
- **Resource Limits**: Inconsistent or missing resource limits for the Proxy, which is prone to OOM due to large body buffering.
- **SQLite SPOF**: Default deployment uses SQLite inside a pod, meaning data loss on pod restart and no multi-pod scaling for the Control Plane.

## 2. Resiliency
- **Fail-Open/Fail-Closed**: If the WAF engine panics, the proxy crashes (Fail-Closed/Outage).
- **Control Plane Outage**: Proxy continues with cached rules but loses new updates and telemetry persistence.

## 3. Scalability
- **Horizontal Scaling**: Edge Proxy can scale but Control Plane (with SQLite) CANNOT.
