# Fake Implementation Report - Sentinel WAF

## 1. Fake ONNX Engine
**File**: `pkg/engine/onnx.go`
**Status**: **TOTAL FAKE**
- **Evidence**:
  ```go
  func (e *ONNXEngine) Predict(input []float32) (float32, error) {
      return 0.5, nil
  }
  ```
- **Finding**: The "AI-powered" engine returns a hardcoded 0.5 regardless of input.

## 2. Incomplete Isolation Forest
**File**: `pkg/engine/ml_forest.go`
**Status**: **INCOMPLETE**
- **Evidence**: The file contains the scoring logic but lacks ANY code for training, loading, or persisting a model.
- **Finding**: It is an empty shell that will always have `len(f.Trees) == 0` unless manually populated (which no code currently does).

## 3. Fake Federated Learning
**File**: `pkg/engine/federated.go`
**Status**: **STUB**
- **Evidence**: `SyncWeights` simply averages local and global weights with no actual networking or security logic. It is not used in the main request flow.

## 4. Heuristic-based "AI" Rule Suggester
**File**: `pkg/engine/ai_rules.go`
**Status**: **MISLEADING**
- **Finding**: Uses simple `strings.Contains` checks for "UNION SELECT" and "cat /etc/passwd" to "suggest" rules. This is basic heuristic logic marketed as AI.
