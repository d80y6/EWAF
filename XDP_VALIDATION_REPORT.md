# Hotpath Profile Report - Sentinel WAF

## 1. Top CPU Consumers
1. `Engine.InspectRequest` -> Regex matching for all rules.
2. `Engine.CalculateEntropy` -> Byte-level frequency iteration.
3. `Proxy.reportStats` -> JSON marshaling of security events.

## 2. Top Memory Consumers
1. `io.ReadAll(r.Body)` -> Primary source of memory pressure.
2. `json.Marshal(data)` in `ParseBody` -> Re-marshaling normalized bodies.

## 3. Recommendations
- Move to specialized regex engine (Hyperscan).
- Implement request body streaming for WAF inspection.
- Batch telemetry events before sending to Control Plane.
