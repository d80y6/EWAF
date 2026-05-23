# Sentinel WAF

Next-Generation Distributed Web Application Firewall platform.

## Architecture

- **Edge Proxy**: High-performance Go-based gateway with eBPF/XDP kernel acceleration.
- **Control Plane**: Centralized management with GORM/PostgreSQL persistence.
- **WAF Engine**: Hybrid signature (OWASP CRS) and ML-based anomaly detection.
- **Telemetry**: Distributed tracing and analytics via NATS, ClickHouse, and Prometheus.

## Features

- Kernel-level IP blocking via eBPF/XDP.
- ML Anomaly detection (Isolation Forest & Entropy).
- API Security (OpenAPI enforcement & GraphQL analysis).
- Bot Protection (Sliding window rate limiting).
- Multi-tenancy and RBAC support.
- WASM Plugin extensibility.

## Deployment

### Docker Compose
```bash
docker compose up -d
```

### Kubernetes
```bash
kubectl apply -f deployments/k8s/
```

## Security Lab

Use `scripts/test_waf.sh` to simulate various attacks (SQLi, XSS, RCE) and verify detection performance.
