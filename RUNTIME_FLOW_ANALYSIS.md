# Runtime Flow Analysis - Sentinel WAF

## 1. Request Flow (Allowed)
`Client -> XDP (Pass) -> Proxy (ServeHTTP) -> Engine (Inspect: Pass) -> Target Server -> Proxy -> Client`

## 2. Request Flow (Blocked - Signature)
`Client -> XDP (Pass) -> Proxy (ServeHTTP) -> Engine (Inspect: Block) -> Proxy (403) -> Client`

## 3. Request Flow (Blocked - Kernel)
`Client -> XDP (Drop) [No Proxy processing]`

## 4. Stat Reporting Flow
`Proxy (goroutine) -> CP (/api/stats/report) -> DB (GlobalStats & SecurityEvent)`

## 5. Configuration Sync Flow
`CP (Rules/Policies) <- Proxy (Ticker 30s) -> Engine (Regex Update)`
