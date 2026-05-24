# Performance Review - Sentinel WAF

## Latency Analysis
- **Base Latency**: <1ms (Empty proxy)
- **WAF Overhead**: ~2-10ms per request (Signature + Anomaly detection).
- **Bottleneck**: Regex matching in Go's `regexp` package. Large rulesets or complex regexes significantly increase latency.
- **Anomaly Detection Overhead**: Negligible (simple byte-level iteration), but logic is flawed (see False Positive Analysis).

## Resource Usage
- **Memory**: High. 10MB per request buffer is dangerous. Under 100 concurrent requests, memory usage could spike to 1GB+ just for request buffers.
- **CPU**: Significant spikes during regex compilation (rule updates) and high-volume matching.

## Hot Paths
1. `Engine.InspectRequest` -> `evaluateCondition` (Regex matching).
2. `Engine.CalculateEntropy` (Byte frequency calculation).
3. `Proxy.reportStats` (JSON marshaling and HTTP POST).
