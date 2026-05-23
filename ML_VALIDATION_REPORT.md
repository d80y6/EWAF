# ML Validation Report - Sentinel WAF

## 1. Feature Extraction
**Status**: **BASIC**
**Logic**: `CalculateEntropy` and a binary-to-string ratio check.
**Finding**: These are statistical heuristics, not machine learning feature engineering. There is no vectorization of request patterns.

## 2. Model Execution
**Status**: **FAKE**
**Finding**: `DetectAnomaly` calls `CalculateEntropy` but does **not** use the `IsolationForest` or `ONNXEngine`.
```go
func (e *Engine) DetectAnomaly(req *model.RequestContext) bool {
    urlEntropy := e.CalculateEntropy(req.NormalizedURL)
    // ...
    return req.Score > 10
}
```
The complex ML models implemented in other files are completely disconnected from the actual request processing flow.

## 3. Training & Inference
**Status**: **NON-EXISTENT**
**Finding**: There is no code to train models, update weights from real traffic, or perform real-time inference using the `ONNXEngine`.
