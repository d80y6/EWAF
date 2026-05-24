# Scalability Analysis - Sentinel WAF

## 1. Proxy Scaling
- **Vertical**: Limited by memory (10MB/req buffer). 32GB RAM supports ~3000 concurrent large requests.
- **Horizontal**: Can be scaled behind a Load Balancer, but requires a central Control Plane for rule sync.

## 2. Control Plane Scaling
- **Bottleneck**: SQLite database.
- **Concurrency**: `OnConflict` increments for stats provide some safety, but SQLite write locks will limit throughput.
- **SPOF**: Single instance deployment in K8s manifest.

## 3. eBPF Scaling
- **Map Limit**: 65,536 entries. For a globally distributed WAF, this is insufficient to track all malicious IPs.
