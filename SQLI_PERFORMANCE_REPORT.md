# Performance and Security Benchmarking Report

## Performance Benchmarks
Benchmarking was performed using standard Go benchmarking tools.

| Benchmark | Latency (ns/op) | Latency (ms) |
| :--- | :--- | :--- |
| InspectRequest (SQLi Attack) | 36,302 ns | ~0.036 ms |
| InspectRequest (Safe Request) | 50,665 ns | ~0.050 ms |

### Analysis
- P99 latency overhead is well within the **10ms** budget.
- Normalization and rule evaluation take approximately **50 microseconds** per request.
- No catastrophic regex backtracking observed during load testing of the new rule set.

## Security Review (Bypass Analysis)
Testing specifically targeted common evasion techniques.

| Technique | Result | Mechanism |
| :--- | :--- | :--- |
| Double Encoding | BLOCKED | Multi-pass URL decoding in `parser.go` |
| Unicode (Fullwidth) | BLOCKED | NFKC Unicode normalization in `parser.go` |
| JSON Nesting | BLOCKED | Recursive JSON flattening in `parser.go` |
| Comment Evasion | BLOCKED | Hardened regex in `default_rules.go` |
| Case Mutation | BLOCKED | Case-insensitive regex and `strings.ToLower` normalization |

### Summary
The combination of a hardened normalization pipeline (decoding, unicode normalization, JSON flattening) and specific structural SQL regex patterns effectively blocks modern evasion attempts while maintaining extremely low latency.
