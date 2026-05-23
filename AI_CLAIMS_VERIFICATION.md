# AI Claims Verification - Sentinel WAF

## Claim: "ML-based anomaly detection (Isolation Forest & Entropy)"
- **Entropy**: **IMPLEMENTED** (but used as a simple threshold, not ML).
- **Isolation Forest**: **SKELETON ONLY**. Not integrated into the engine.

## Claim: "AI-assisted rule generation"
- **Status**: **FAKE**.
- **Reality**: A simple `strings.Contains` heuristic in `ai_rules.go` is marketed as "AI".

## Claim: "Federated Learning weight synchronization"
- **Status**: **FAKE**.
- **Reality**: A single averaging function exists in `federated.go` but is not connected to any network or model update logic.

## Conclusion
The AI/ML claims are largely misleading. The system uses basic statistical heuristics and markets them as advanced AI/ML.
