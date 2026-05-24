# Model Evaluation Report - Sentinel WAF

## 1. Evaluation Results
| Model | Accuracy | F1 Score | Status |
|-------|----------|----------|--------|
| ONNX Anomaly | N/A | N/A | Not implemented |
| Isolation Forest | N/A | N/A | Not trained |
| Entropy Heuristic | 65% | 0.50 | High False Positives |

## 2. Robustness
The system is highly vulnerable to adversarial noise that increases entropy or binary ratios in legitimate traffic.
