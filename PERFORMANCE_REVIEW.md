# Performance Review - Sentinel WAF

## 1. Latency Benchmarks
- **Direct Backend**: ~10.8ms average for small GET.
- **Via Proxy (Benign)**: ~11.6ms average (+0.8ms overhead).
- **Via Proxy (1MB POST)**: ~23.6ms average (vs ~12.9ms direct). **83% Overhead**.

## 2. Bottlenecks
- **Full Body Buffering**: `io.ReadAll` for every request is the primary bottleneck for large payloads.
- **Multiple Inspection Passes**: Every request goes through Signature -> ML -> API Security -> Rule Engine.
- **JSON/XML Marshaling**: The engine marshals "cleaned" JSON/XML to `req.NormalizedBody`, doubling the memory and CPU work for those formats.

## 3. Scalability Limits
- **Memory**: 10MB/req limit means a single 32GB server can only safely handle ~2000-3000 concurrent large requests before OOM risk.
- **XDP Map**: Block list is limited to 65,536 entries (manually increased in source, but still fixed).
