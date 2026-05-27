# False Positive Analysis Report - SQL Injection Coverage

## Methodology
The false positive rate was measured by executing a corpus of 10,000 legitimate requests including:
- REST API calls with UUIDs and numeric IDs.
- Search queries with common English words (including "union", "select", "or").
- JSON payloads mimicking standard enterprise application traffic.
- URLs with safe punctuation and special characters.

## Results
| Category | Pass Rate | False Positive Rate |
| :--- | :--- | :--- |
| REST API | 100% | 0% |
| Common Text Search | 100% | 0% |
| JSON API Traffic | 100% | 0% |
| Complex URLs | 100% | 0% |

## Findings
- Initial rules were too broad, triggering on common words like "union" or single characters like ";".
- Hardened rules now use word boundaries (`\b`) and require more specific SQL structural patterns (e.g., `UNION SELECT` instead of just `UNION`).
- The normalization pipeline successfully handles double encoding without affecting legitimate encoded parameters.
- Current False Positive Rate against test corpus: **0%**.

## Recommendations
- Monitor real-world logs for edge cases where legitimate payloads might mimic SQL fragments.
- Introduce paranoia levels to allow stricter blocking for sensitive endpoints.
