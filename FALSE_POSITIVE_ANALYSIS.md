# False Positive Analysis - Sentinel WAF

## 1. Anomaly Detection
- **Entropy Threshold (6.5)**: Verified to block random-looking but legitimate path components (e.g., UUIDs, long API tokens).
- **Binary Ratio (0.3)**: Verified to block legitimate binary file uploads (images, PDFs) if the non-printable byte ratio exceeds 30%.

## 2. Context Blindness
- **Health Checks**: The suffix check for `/health` is too simple and may still be blocked if combined with other high-score signals.
- **Structured Data**: JSON/XML with many special characters might be misclassified as anomalous.
