# SRE Resiliency Report - Sentinel WAF

## Resiliency Matrix

| Component | Failure Mode | Impact | Recovery |
|-----------|--------------|--------|----------|
| **Control Plane** | Down | Proxy cannot update rules. New instances cannot start. | Manual restart. |
| **Database** | Down | Stats reporting fails (background goroutines will leak). | Manual intervention. |
| **Edge Proxy** | Panic/Crash | Traffic to target server is dropped. | K8s restart (if probes existed). |

## Critical Reliability Gaps
1. **Graceful Degradation**: If the Control Plane is down, the Proxy should ideally fall back to a cached rule set. It currently just logs an error and continues with whatever it has (or empty rules if it's the first start).
2. **Backpressure**: There is no backpressure handling for telemetry or rule updates.
3. **Panic Safety**: Some paths (e.g., regex matching or body parsing) lack explicit panic recovery, which could take down the entire proxy pod.
