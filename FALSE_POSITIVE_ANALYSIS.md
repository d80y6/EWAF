# False Positive Analysis - Sentinel WAF

## Critical Issue: Over-blocking
The "ML-based" anomaly detection is actually just a high-entropy and binary-ratio check.

### Evidence
- **Case 1**: `/health` endpoint is blocked.
- **Reason**: `CalculateEntropy("/health")` returns a value that, combined with the lack of other "good" signals, often exceeds the threshold.
- **Impact**: Monitoring tools will report the WAF as "Down" even when it's functioning, and legitimate paths with "random-looking" names will be blocked.

## Anomaly Detection Logic
```go
urlEntropy := e.CalculateEntropy(req.NormalizedURL)
if urlEntropy > 5.0 {
    req.Score += 5
}
// ...
if req.Score > 10 { shouldBlock = true }
```
A URL like `/api/v1/resource/3c9e4f2a-8b1d-4e7a-9c2b-5f6a8b7c3d9e` (UUID) has high entropy and will contribute significantly to a block, leading to high false positive rates for modern REST APIs.
