# ML & AI Claims Validation - Sentinel WAF

## 1. Claims vs. Reality
| Claim | Reality | Status |
|-------|---------|--------|
| **ONNX-based Deep Learning** | Returns hardcoded `0.5` | **FAKE** |
| **Isolation Forest Anomaly Detection** | Empty shell, no trees, no training | **INCOMPLETE** |
| **Federated Learning** | Simple average logic, not used | **STUB** |
| **AI-Assisted Rule Generation** | Hardcoded `strings.Contains` | **HEURISTIC** |

## 2. Adversarial Robustness
- **Finding**: The "ML" is so simple (Entropy + Binary Ratio) that it is trivial to evade or weaponize for DoS (False Positives).

## 3. Production Readiness
- **Verdict**: **NOT READY**. The ML component is marketed as a core differentiator but is currently non-functional or misleading.
