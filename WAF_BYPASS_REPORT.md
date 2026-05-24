# WAF Bypass Report - Sentinel WAF

## Potential Bypasses Identified

### 1. HTTP Smuggling
The proxy uses `httputil.ReverseProxy` which is generally robust, but the WAF inspection happens *before* the reverse proxy logic. Discrepancies in how `io.ReadAll` and the subsequent `ReverseProxy` handle malformed `Transfer-Encoding` or `Content-Length` headers could lead to smuggling.

### 2. IPv6 Bypasses
The eBPF/XDP layer ONLY supports IPv4. All kernel-level blocking is ineffective against IPv6 traffic.

### 3. Normalization Inconsistency
`parser.go` performs very minimal normalization.
- It does not handle `\r\n` or other whitespace evasions in headers.
- It does not handle multi-part form data properly (just reads raw body).
- It does not decode HTML entities or other encodings that a backend might interpret.

### 4. GraphQL Depth/Complexity Limits
Although a `GraphQLAnalyzer` exists, it is **not used** in the main `InspectRequest` or `InspectAPI` flow. GraphQL attacks like deep nesting or batching will pass through uninspected.
