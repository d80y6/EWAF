# WAF Bypass Report - Sentinel WAF

## 1. Verified Bypasses
- **Double Encoding**: `%253cscript` bypasses Rule 941100.
- **JWT Forgery**: Default secret `s3ntinel-p0d-pr0ducti0n-s3cr3t-2025!` can be used to sign arbitrary tokens.
- **Path Traversal**: Rudimentary normalization (only recursively collapses `//`) might be bypassable with specific Unicode or OS-specific path separators not covered in the regex.

## 2. Evasion Techniques
- **Protocol Evasion**: XDP block list lacks VLAN (802.1Q) support; tagged traffic bypasses kernel blocking.
- **Logic Evasion**: High-volume, low-entropy attacks might bypass `DetectAnomaly` while staying under signature thresholds.
