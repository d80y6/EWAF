# Security Code Audit - Sentinel WAF

## Critical Vulnerabilities

### 1. Incomplete Path Normalization (Bypass)
**File**: `pkg/engine/parser.go`
**Logic**:
```go
func (e *Engine) NormalizeRequest(req *model.RequestContext) {
    req.NormalizedURL = strings.ToLower(req.URL)
    for strings.Contains(req.NormalizedURL, "//") {
        req.NormalizedURL = strings.ReplaceAll(req.NormalizedURL, "//", "/")
    }
}
```
**Finding**: The normalization only handles multiple slashes. It does **not** handle:
- URL encoding (e.g., `%2e%2e%2f` for `../`).
- Multiple encodings.
- Unicode evasions.
- Path traversal via `.` or `..` directly (it just lowercases them).
**Impact**: Attackers can easily bypass regex-based rules using URL encoding.

### 2. Unsafe Memory Handling (DoS)
**File**: `internal/proxy/proxy.go`
**Logic**:
```go
body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))
```
**Finding**: While `MaxBodySize` is 10MB, reading the entire body into memory for every request can lead to rapid OOM if an attacker sends many concurrent 10MB requests. There is no streaming inspection.

### 3. Race Conditions in Rule/Policy Updates
**File**: `internal/proxy/updater.go` & `pkg/engine/engine.go`
**Finding**:
- `Engine.LoadRules` uses a mutex, but `Engine.InspectRequest` uses `RLock`. This is generally safe.
- **However**, `Proxy.apiPolicies` is updated in `updater.go` using `p.mu.Lock()`, and read in `ServeHTTP` using `RLock()`.
- The `Engine.regex` map is recreated in `LoadRules` but there might be a race if `InspectRequest` is using the map while it's being swapped (though it's behind `RLock`).

### 4. Weak JWT Validation
**File**: `pkg/engine/api_security.go`
**Finding**:
- The implementation uses `jwt.Parse` with a key function that checks the signing method.
- **Vulnerability**: If `policy.JWTSecret` is the default "sentinel-default-secret", it's trivial to forge tokens. The Control Plane seeds this default.

### 5. Insecure Engine Logic
**File**: `pkg/engine/engine.go`
**Finding**:
- `evaluateCondition` for `body` target:
```go
case "body":
    if req.NormalizedBody == "" && len(req.Body) > 0 {
        req.NormalizedBody = string(req.Body)
    }
    targetValue = req.NormalizedBody
```
- If the body is large and not JSON/XML, it's converted to a string every time if `NormalizedBody` isn't set. `ParseBody` only sets it for JSON/XML.

### 6. eBPF Verifier Risk
**File**: `pkg/ebpf/c/xdp_fw.c`
**Finding**:
- The packet boundary checks seem correct:
```c
if ((void *)(eth + 1) > data_end) return XDP_PASS;
if ((void *)(iph + 1) > data_end) return XDP_PASS;
```
- **Limitation**: Only handles IPv4. IPv6 packets will bypass the block list.
