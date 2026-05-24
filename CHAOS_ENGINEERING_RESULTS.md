# Chaos Engineering Results - Sentinel WAF

## 1. Experiment: Memory Exhaustion
- **Method**: Send 50 concurrent 10MB POST requests.
- **Result**: Proxy memory usage spiked to 500MB+; latency increased by 300%.
- **Verdict**: High risk of OOM in resource-constrained pods.

## 2. Experiment: CP Outage
- **Method**: Kill Control Plane process.
- **Result**: Proxy continues to serve with last known rules but telemetry fails silently.
- **Verdict**: Acceptable for data plane, but loses observability.
