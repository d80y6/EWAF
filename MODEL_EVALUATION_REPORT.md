# Model Evaluation Report - Sentinel WAF

## Accuracy
- **Precision**: Very Low (due to high false positives on URLs like `/health` or UUIDs).
- **Recall**: Moderate (can catch some high-entropy random probes).
- **F1 Score**: Low.

## Performance
- **Inference Latency**: <1ms (since it's just a loop over bytes).
- **Adversarial Robustness**: Extremely Low. Attackers can easily craft low-entropy payloads or pad requests with "good" bytes to lower the average entropy and bypass the detection.
