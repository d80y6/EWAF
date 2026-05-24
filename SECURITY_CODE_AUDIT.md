# Security Code Audit - Sentinel WAF

## 1. Normalization & Bypass (Critical)
**File**: `pkg/engine/parser.go`
- **Vulnerability**: `NormalizeRequest` only calls `url.QueryUnescape` once.
- **Evidence**: Double encoding (e.g., `%253c` for `<`) bypasses rules because the first pass only decodes it to `%3c`.
- **Finding**: Verified via runtime testing: `http://localhost:8000/search?q=%253cscript` returns 404 (Passed), bypassing XSS rule.

## 2. Unsafe Body Handling (High)
**File**: `internal/proxy/proxy.go`
- **Logic**: `body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))`
- **Risk**: Memory exhaustion (DoS). Synchronous buffering of 10MB requests without streaming or pooling.

## 3. Hardcoded / Insecure Defaults (Medium)
**File**: `cmd/control-plane/main.go`
- **Finding**: Default JWT secret `s3ntinel-p0d-pr0ducti0n-s3cr3t-2025!` is hardcoded in the seed logic.
- **Risk**: If not changed, attackers can forge JWTs for any API protected by the WAF.

## 4. Panic Paths
- `Engine.LoadRules` returns an error on regex compile failure, which is handled in the updater. This is safe.
- However, the `Proxy` does not have a recover middleware, meaning a panic in any request processing goroutine will crash the entire proxy.

## 5. Weak Anomaly Detection
**File**: `pkg/engine/ml.go`
- **Entropy Logic**: Simple Shannon entropy is used. Verified that it blocks legitimate high-entropy URLs (random tokens, UUIDs) and large binary POSTs.
- **Risk**: Denial of Service for legitimate traffic (False Positives).
