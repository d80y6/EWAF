# Release Engineering Audit - Sentinel WAF

## 1. Artifacts
- Binary builds for Proxy and Control Plane.
- eBPF objects (`.o`) generated via `bpf2go`.

## 2. Vulnerabilities
- Hardcoded default secret in the source code.
- No dependency vulnerability scanning (e.g., Snyk, Trivy) seen in the pipeline.

## 3. Recommendation
- Automate eBPF object generation in CI.
- Implement secret injection via K8s Secrets/Vault instead of hardcoding.
