## 2025-03-03 - Map vs. Array for frequency counting
**Learning:** Using `map[rune]float64` for frequency counting in Go introduces significant overhead due to map hashing, allocations, and heap pressure. Furthermore, `range` over strings decodes UTF-8 runes, which is unnecessary and slow for raw payload inspection in a WAF.
**Action:** Use a fixed-size `[256]float64` array and iterate over bytes using a for loop with an index. This is ~15x faster for entropy calculations on large payloads and avoids rune decoding overhead.
