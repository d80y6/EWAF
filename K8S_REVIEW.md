# Kubernetes Review - Sentinel WAF

## Configuration Audit

### 1. Missing Resource Limits
- **Observation**: `deployments/k8s/proxy.yaml` does not define `resources.requests` or `resources.limits`.
- **Risk**: In a WAF, which is CPU and memory intensive (especially with 10MB buffers), this can lead to "noisy neighbor" issues and node instability.

### 2. Lack of Health Probes
- **Observation**: No `livenessProbe` or `readinessProbe` is defined.
- **Risk**: Kubernetes will send traffic to pods even if the proxy is crashing or failing to connect to the Control Plane.

### 3. Privileged Mode Required for XDP
- **Observation**: The YAML does not include the necessary `securityContext` (e.g., `privileged: true` or `CAP_NET_ADMIN`) to load eBPF/XDP programs.
- **Risk**: The XDP features will **fail to load** in standard Kubernetes deployments without manual intervention or manifest updates.

### 4. Hardcoded Environment Variables
- **Observation**: `TARGET_URL` is hardcoded. It should be configurable via ConfigMaps or Secrets.
- **Risk**: Low flexibility and poor separation of configuration and code.

### 5. Absence of Network Policies
- **Observation**: No `NetworkPolicy` manifests are provided.
- **Risk**: Any pod in the cluster can communicate with the Control Plane/Proxy, increasing the blast radius of a compromised pod.
