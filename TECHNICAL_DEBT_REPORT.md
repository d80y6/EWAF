# Technical Debt Report - Sentinel WAF

## 1. Logic Gaps
- **Broken Multi-tenancy**: `TenantID` is present in the model but ignored in the engine's inspection logic.
- **Stubbed ML**: `onnx.go` and `ml_forest.go` are non-functional placeholders.
- **Incomplete Normalization**: URL decoding is only performed once, allowing double-encoding bypasses.

## 2. Architectural Debt
- **Health Check Shadowing**: The proxy middleware masks the application's own health endpoint.
- **Hardcoded Secrets**: Default JWT secret is hardcoded in the seed logic.

## 3. Code Quality
- **Lack of structured logging**.
- **Minimal unit test coverage** for critical path normalization and eBPF integration.
