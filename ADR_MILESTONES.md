# Enterprise WAF Platform Documentation

## Section 1: Architecture Decision Records

ADR-001: Request inspection architecture
Status: ACCEPTED
Context: The WAF must inspect and potentially block incoming HTTP traffic before it reaches protected backend services. Deployment models like sidecars or SDKs were considered, but an inline proxy provides the most comprehensive control.
Decision: Implement as an inline reverse proxy using the Go `net/http/httputil` package, where all traffic is terminated and inspected before forwarding.
Consequences:
  Positive:
    - Zero modification required for backend applications.
    - Centralized point for TLS termination and security enforcement.
    - Full visibility into request and response headers and bodies.
  Negative:
    - Introduces a network hop, increasing p99 latency.
    - The proxy becomes a single point of failure for all protected traffic.
  Risks:
    - Connection handling bugs could lead to request smuggling or HTTP desync attacks.
    - High traffic volume may require significant resource scaling of the proxy layer.
Security implications:
  - Blocks direct network access to backend services by acting as a gateway.
  - Expands the attack surface to include the Go HTTP stack and proxy logic.
  - Relies on the assumption that the proxy is the sole ingress point to the backend network.

ADR-002: Rule engine model
Status: ACCEPTED
Context: The system needs a flexible way to define and evaluate security rules across multiple tenants. Rules must be easily updatable via the Control Plane without proxy restarts.
Decision: Use a declarative rule DSL where rules are defined as sets of conditions (Target, Operator, Key, Value) stored as JSON and evaluated sequentially with short-circuiting on the first "block" action.
Consequences:
  Positive:
    - Rules can be updated dynamically via REST API.
    - Decouples rule definition from the engine's core Go code.
    - Simple to audit and visualize in the admin dashboard.
  Negative:
    - Sequential evaluation performance scales linearly O(N) with the number of rules.
    - DSL is less expressive than native Go code or Lua-based scripting.
  Risks:
    - ReDoS (Regular Expression Denial of Service) if user-provided regex is not validated.
    - Complexity in managing priority and ordering for multi-tenant rule sets.
Security implications:
  - Closes hardcoded bypasses by allowing rapid deployment of new signatures.
  - Opens a risk of malicious rule injection if the rule management interface is compromised.
  - Relies on the assumption that the DSL interpreter correctly handles all normalization and encoding edge cases.

ADR-003: OWASP CRS integration strategy
Status: ACCEPTED
Context: Providing industry-standard protection requires alignment with the OWASP Core Rule Set (CRS). Integrating the full ModSecurity engine was deemed too heavy for this architecture.
Decision: Reimplement a critical subset of OWASP CRS (v3.x or v4.x) logic using the internal DSL, focusing on high-confidence patterns for SQLi, XSS, and RCE.
Consequences:
  Positive:
    - Significantly lower performance overhead compared to running a full ModSecurity engine.
    - Native integration with the Go-based engine's normalization pipeline.
  Negative:
    - Incomplete coverage of the full CRS feature set.
    - Manual effort required to port and verify rules from upstream updates.
  Risks:
    - Missing complex CRS logic (e.g., multi-rule chains) could lead to bypasses.
    - Paranoia levels are harder to implement consistently with simplified rules.
Security implications:
  - Provides a baseline of protection against well-known attack vectors.
  - Requires constant vigilance to ensure ported rules remain effective against new bypass techniques.
  - Relies on the assumption that the selected subset covers the vast majority of real-world threats.

ADR-004: ML anomaly detection model
Status: ACCEPTED
Context: Signature-based rules are insufficient for zero-day attacks and highly obfuscated payloads. Anomaly detection provides a second layer of defense.
Decision: Utilize a hybrid model combining heuristic entropy analysis with an Isolation Forest algorithm to score requests based on feature distributions (URL entropy, body entropy, binary ratio).
Consequences:
  Positive:
    - Capable of detecting unusual payloads that don't match existing signatures.
    - Provides a quantitative score that can be used for "Shadow Mode" monitoring.
  Negative:
    - Higher CPU and memory cost for ML inference on every request.
    - Potential for false positives on legitimate high-entropy traffic (e.g., encrypted blobs).
  Risks:
    - [NEEDS HUMAN SECURITY REVIEW] Decision on online vs offline learning is currently implemented as static/pre-trained; online learning could be susceptible to model poisoning.
    - Model unavailability or crash could lead to either "fail open" (missed detections) or "fail closed" (latency spikes).
Security implications:
  - Closes gaps left by traditional regex-based rules for polymorphic or unknown attacks.
  - Introduces a new vector for resource exhaustion if the ML engine is overwhelmed.
  - Relies on the assumption that malicious traffic is statistically anomalous compared to baseline legitimate traffic.

ADR-005: Rate limiting architecture
Status: ACCEPTED
Context: To prevent DDoS and brute-force attacks, the system must enforce request rate limits. In a distributed environment, local counters in the proxy are insufficient for aggregate enforcement.
Decision: Implement a distributed rate limiting architecture using Redis as a centralized counter store with sliding window logic.
Consequences:
  Positive:
    - Accurate global enforcement across multiple proxy instances.
    - Low latency lookups and increments via Redis atomic operations.
  Negative:
    - Introduces a dependency on an external Redis cluster.
    - Adds network latency to every request evaluation (mitigated by pipelining/caching).
  Risks:
    - Redis connectivity failure could disrupt security enforcement.
    - [NEEDS HUMAN SECURITY REVIEW] Decision to "fail open" (allow traffic) on Redis failure ensures availability but risks bypassing the rate limiter during an attack.
Security implications:
  - Protects backend services from resource exhaustion and brute-force attempts.
  - Fail-open strategy prioritizes availability over strict security during infrastructure failures.
  - Relies on the assumption that Redis remains highly available and low-latency.

ADR-006: Bot detection strategy
Status: ACCEPTED
Context: Automated crawlers and malicious bots can scrape data or exhaust resources. Distinguishing between legitimate users and automated scripts is critical.
Decision: Use a passive fingerprinting approach based on request signals (User-Agent, JA3 TLS fingerprint, header ordering, behavioral patterns).
Consequences:
  Positive:
    - Transparent to legitimate users (no CAPTCHAs or challenges).
    - Harder for simple bots to bypass than basic UA-string checks.
  Negative:
    - Passive signals can be spoofed by sophisticated attackers.
    - Risk of false positives for non-standard but legitimate clients.
  Risks:
    - Maintenance overhead to keep JA3 and UA signatures updated against new bot versions.
    - Privacy concerns around high-fidelity fingerprinting of users.
Security implications:
  - Closes holes left by traditional IP-based blocking for distributed botnets.
  - Relies on the assumption that bot traffic exhibit distinct behavioral or technical characteristics compared to human traffic.

ADR-007: IP reputation data pipeline
Status: ACCEPTED
Context: Many attacks originate from known malicious infrastructure (Tor exit nodes, open proxies, infected botnets). Pre-emptively blocking these IPs reduces overall engine load.
Decision: Integrate an external IP reputation feed that is updated periodically and stored in a high-performance in-memory map for O(1) lookups during the inspection phase.
Consequences:
  Positive:
    - Fast, low-latency rejection of known malicious actors.
    - Reduces CPU cycles spent on deep inspection of obviously bad traffic.
  Negative:
    - Requires reliable external data feeds.
    - Stale data may lead to blocking legitimate users (IP churn).
  Risks:
    - Failure to update the feed could leave the system vulnerable to new threats or cause persistent false positives.
    - Data feed corruption or poisoning could lead to widespread blocking of legitimate traffic.
Security implications:
  - Reduces the effective attack surface by filtering out known high-risk actors.
  - Relies on the assumption that IP reputation data is accurate and timely.

ADR-008: Multi-tenant rule isolation model
Status: ACCEPTED
Context: The WAF must support multiple tenants with their own specific security policies. A configuration error in one tenant's rules must never impact another tenant.
Decision: Enforce strict namespace isolation at the engine level using a `TenantID` field on all request contexts and rules; the engine only selects and evaluates rules matching the current request's tenant ID.
Consequences:
  Positive:
    - Guarantees that rules for Tenant A cannot block traffic for Tenant B.
    - Allows for granular, per-tenant security postures and custom rules.
  Negative:
    - Adds logic overhead to the engine's rule selection phase.
  Risks:
    - Bugs in the tenant ID resolution logic (e.g., from headers or IP) could lead to cross-tenant rule leakage.
    - [NEEDS HUMAN SECURITY REVIEW] Is the resolution of TenantID itself robust against spoofing or manipulation?
Security implications:
  - Prevents "noisy neighbor" or "hostile neighbor" scenarios where one tenant's misconfiguration creates a denial of service for others.
  - Relies on the assumption that the `TenantID` is correctly assigned by an upstream trusted component or the proxy itself.

ADR-009: TLS termination placement
Status: ACCEPTED
Context: To inspect encrypted traffic (HTTPS), the WAF must terminate TLS and decrypt requests before inspection. This exposes sensitive data within the proxy's memory.
Decision: Terminate TLS directly at the Edge Proxy layer using Go's `crypto/tls` library, enforcing TLS 1.2 and 1.3 with a restricted set of secure cipher suites.
Consequences:
  Positive:
    - Full visibility into request content for deep inspection.
    - Simplified backend infrastructure by offloading TLS processing.
  Negative:
    - The proxy becomes a high-value target as it handles private keys and plaintext data.
    - Increased CPU load due to cryptographic operations.
  Risks:
    - [NEEDS HUMAN SECURITY REVIEW] Management of private keys: where are they stored (KMS, HSM, or local file system)?
    - Weak TLS configurations could allow for downgrade attacks.
Security implications:
  - Ensures data in transit to the WAF is encrypted and authenticated.
  - Requires robust protection of the proxy environment to prevent plaintext data leaks.
  - Relies on the assumption that the Go TLS implementation is secure and correctly configured.

ADR-010: Logging and audit pipeline
Status: ACCEPTED
Context: For incident response and compliance, every security decision and rule change must be logged. Logs must be resistant to tampering.
Decision: Implement a centralized logging pipeline where security events are asynchronously reported from the proxy to the Control Plane for persistence in a relational database with audit logs for all administrative actions.
Consequences:
  Positive:
    - High-fidelity logs for security analysis and forensic investigations.
    - Separation of concerns between high-performance inspection and data persistence.
  Negative:
    - Potential for log loss if the connection to the Control Plane is interrupted.
    - Storage costs for high-volume traffic logs.
  Risks:
    - [NEEDS HUMAN SECURITY REVIEW] PII leakage: are request bodies or headers containing sensitive user data being logged without masking?
    - Logs themselves could be targets for deletion or tampering by an attacker with database access.
Security implications:
  - Enables detection of persistent attacks and provides evidence for post-mortem analysis.
  - Relies on the assumption that the Control Plane is secure and the database is properly hardened.

ADR-011: Fail mode — open vs closed
Status: ACCEPTED
Context: The WAF itself can fail due to software bugs, resource exhaustion, or component unavailability (e.g., rule store, ML engine). The system must decide how to handle traffic during these failures.
Decision: Implement a "Hybrid Fail Mode" where component failures (ML, Rate Limiting) fail OPEN to prioritize availability, while core engine crashes or unrecoverable proxy errors result in a fail CLOSED state at the infrastructure level (e.g., LB health check failure).
Consequences:
  Positive:
    - Partial functionality loss doesn't disrupt all legitimate traffic.
    - Prevents total outages for non-critical security failures.
  Negative:
    - During a "fail open" window, the system is vulnerable to attacks that would otherwise be blocked.
  Risks:
    - [NEEDS HUMAN SECURITY REVIEW] An attacker could deliberately trigger a component failure (e.g., DDoS the ML engine) to force the system into a fail-open state.
    - Inconsistent state across proxies if some are in fail-open and others are not.
Security implications:
  - Creates a tradeoff between security and availability that must be explicitly governed.
  - Relies on the assumption that core proxy components are highly resilient.

ADR-012: Admin API security model
Status: ACCEPTED
Context: The Control Plane API allows for rule modification and system configuration. Unauthorized access to this API would allow an attacker to disable security or redirect traffic.
Decision: Secure the Admin API using JWT-based authentication and Role-Based Access Control (RBAC), with mandatory audit logging for all write operations.
Consequences:
  Positive:
    - Prevents unauthorized changes to security policies.
    - Provides a clear audit trail of who changed what and when.
  Negative:
    - Adds complexity to the management and rotation of API credentials.
  Risks:
    - [NEEDS HUMAN SECURITY REVIEW] Hardcoded secrets or weak JWT verification could compromise the entire platform.
    - Cross-tenant rule modifications if authorization logic is flawed.
Security implications:
  - Protects the "brain" of the WAF from compromise.
  - Relies on the assumption that the authentication provider and the JWT secret management are robust.

## Section 2: Dependency-Ordered Milestone Map

MILESTONE-01: Infrastructure skeleton
Depends on: NONE
Scope:
  - Go-based reverse proxy capability.
  - Forwarding of HTTP traffic to a configurable target.
  - Health check endpoint (/health) operational.
Frozen interfaces:
  - RequestContext schema (pkg/model/model.go)
Gate condition:
  - Given a clean HTTP GET request to the proxy, it returns a 200 OK from the backend with zero modifications to headers or body. Verified by: cURL comparison between direct backend and proxy-passed request.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead ≤ 2ms
Rollback condition:
  - Proxy fails to forward traffic or introduces > 5ms latency in baseline.

MILESTONE-02: TLS termination
Depends on: MILESTONE-01
Scope:
  - TLS 1.2 and 1.3 termination at the proxy.
  - Enforcement of secure cipher suites.
  - Rejection of legacy SSL/TLS versions.
Frozen interfaces:
  - TLS configuration specification.
Gate condition:
  - Given a TLS 1.0 or 1.1 connection attempt, the proxy must reject the handshake. Verified by: `testssl.sh` or `nmap --script ssl-enum-ciphers`.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead ≤ 5ms (including handshake)
Rollback condition:
  - Successful handshake with TLS 1.1 or lower.

MILESTONE-03: Request inspection primitive
Depends on: MILESTONE-01
Scope:
  - Implementation of Rule Engine DSL (Conditions, Operators).
  - Basic block/allow logic.
  - Local logging of decisions.
Frozen interfaces:
  - Rule DSL syntax (pkg/model/db.go)
Gate condition:
  - Given a rule matching the string "attack" in the URL, a request to `/attack` is blocked with 403 Forbidden, while a request to `/safe` is passed to the backend. Verified by: Go integration test.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead ≤ 1ms for single rule.
Rollback condition:
  - Rule fails to block matching payload or blocks non-matching payload.

MILESTONE-04: OWASP CRS — SQLi only
Depends on: MILESTONE-03
Status: COMPLETED
Scope:
  - Reimplementation of OWASP CRS SQLi rules (942xxx class).
  - Multi-pass URL normalization logic.
  - Unicode (NFKC) normalization.
  - JSON and XML flattening for inspection.
  - Header and Cookie inspection support.
Gate condition:
  - Given the OWASP CRS SQLi test suite (942xxx rules), the engine blocks ≥90% of payloads. Verified by: automated run of GoTestWAF-aligned security suite (`pkg/engine/sqli_test.go`).
Definition of done:
  - Gate condition passes in CI (100% pass on internal suite)
  - No regressions in dependent milestones (M-01, M-02, M-03 passing)
  - All frozen interfaces unchanged
  - Security: 0% FP rate on legitimate corpus (10,000 requests)
  - Performance: p99 latency overhead < 0.1ms
Rollback condition:
  - SQLi block rate drops below 85% or FP rate > 1%.

MILESTONE-05: OWASP CRS — XSS only
Depends on: MILESTONE-03
Status: COMPLETED
Scope:
  - Reimplementation of OWASP CRS XSS rules (941xxx class).
  - NFKC normalization for fullwidth character evasion.
Gate condition:
  - Given the OWASP CRS XSS test suite (941xxx rules), the engine blocks ≥90% of payloads. Verified by: automated run of GoTestWAF-aligned security suite (`pkg/engine/xss_test.go`).
Definition of done:
  - Gate condition passes in CI (100% pass on internal suite)
  - No regressions in dependent milestones (M-01 through M-04 passing)
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead < 0.1ms
Rollback condition:
  - XSS block rate drops below 85% on standard payloads.

MILESTONE-06: OWASP CRS — remaining classes
Depends on: MILESTONE-04, MILESTONE-05
Status: COMPLETED
Scope:
  - Reimplementation of RCE (932xxx), LFI (930xxx), and PHP injection (933xxx) rules.
Gate condition:
  - For each class (RCE, LFI, PHP), the engine blocks ≥85% of relevant payloads from the OWASP CRS test corpus. Verified by: automated run of GoTestWAF-aligned security suite (`pkg/engine/m06_test.go`).
Definition of done:
  - Gate condition passes in CI (100% pass on internal suite)
  - No regressions in dependent milestones (M-01 through M-05 passing)
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead < 0.1ms
Rollback condition:
  - Any class falls below 80% detection rate.

MILESTONE-07: Rate limiting primitive
Depends on: MILESTONE-01
Status: COMPLETED
Scope:
  - Redis-backed distributed counter.
  - Sliding window algorithm.
  - Fail-open logic implementation.
Gate condition:
  - Given a limit of 10 requests/minute, the 11th request from the same IP within 60 seconds is blocked with 429 Too Many Requests. If Redis is unreachable, the request is allowed. Verified by: automated unit test `pkg/engine/ratelimit_test.go`.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: Fail-open verified via chaos test simulation
  - Performance: Redis overhead within budget
Rollback condition:
  - Redis failure causes proxy to drop all traffic (fail closed).

MILESTONE-08: IP reputation blocking
Depends on: MILESTONE-01
Status: COMPLETED
Scope:
  - Integration with external threat intelligence feed.
  - In-memory IP reputation map.
  - Periodic update background worker.
Gate condition:
  - Known-bad IP (added to mock feed) is blocked with 403 Forbidden within 30 seconds of the feed update. Verified by: automated unit test `pkg/engine/threat_intel_test.go`.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead < 0.1ms
Rollback condition:
  - Feed update failure causes proxy crash or stale data persistence > 24h without alert.

MILESTONE-09: Bot detection primitive
Depends on: MILESTONE-01
Status: COMPLETED
Scope:
  - JA3 fingerprinting implementation.
  - User-Agent behavioral analysis.
  - Fingerprint-based blocking.
Gate condition:
  - A request with a known "malicious bot" JA3 fingerprint is blocked, while a browser-like JA3 fingerprint is allowed. Verified by: automated unit test `pkg/engine/bot_test.go`.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead < 0.1ms
Rollback condition:
  - Standard browser traffic (Chrome/Firefox/Safari) is incorrectly identified as bot traffic.

MILESTONE-10: Multi-tenant rule isolation
Depends on: MILESTONE-03
Status: COMPLETED
Scope:
  - TenantID resolution logic.
  - Isolated rule evaluation logic.
Gate condition:
  - Rule "Block All" applied to Tenant A must NOT block traffic for Tenant B. Verified by: parallel requests to different virtual hosts mapped to different TenantIDs. Verified by: automated unit test `pkg/engine/tenant_test.go`.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead < 0.1ms
Rollback condition:
  - Any instance of cross-tenant rule bleed detected.

MILESTONE-11: ML anomaly detection
Depends on: MILESTONE-01
Status: COMPLETED
Scope:
  - Entropy calculation engine.
  - Isolation Forest scoring integration.
  - Fallback logic when ML is unavailable.
Gate condition:
  - The model must produce different scores for two inputs that share the same threshold boundary (e.g. same length, same method). Verified by: feeding the engine one legitimate request and one high-entropy attack payload (random binary) and observing distinct `MLAnomalyScore` values. Verified by: automated unit test `pkg/engine/ml_test.go`.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: p99 latency overhead < 0.1ms
Rollback condition:
  - ML inference time exceeds 50ms per request.

MILESTONE-12: Admin dashboard — rule management
Depends on: MILESTONE-03, MILESTONE-10
Scope:
  - CRUD operations for rules in Control Plane.
  - Audit logging for all rule changes.
  - RBAC enforcement on API.
Frozen interfaces:
  - Admin API contract.
Gate condition:
  - An unauthenticated rule change attempt returns 401 Unauthorized. A rule change attempt for Tenant B by a Tenant A admin returns 403 Forbidden. Verified by: Automated API security scan.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: Rule propagation from Control Plane to Proxy ≤ 30s.
Rollback condition:
  - Successful unauthorized rule modification.

MILESTONE-13: Logging + alerting pipeline
Depends on: MILESTONE-10
Scope:
  - Centralized security event logging.
  - Tamper-evident log structure.
  - Critical event alerting (Slack/Email).
Frozen interfaces:
  - Log schema.
Gate condition:
  - Every "block" decision results in a persistent log entry in the Control Plane database within 1 second. Verified by: Log latency monitoring during high-load simulation.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: Zero impact on request latency (asynchronous logging).
Rollback condition:
  - Logging failures block the request pipeline or logs are missing > 1% of block events.

MILESTONE-14: Full integration gate
Depends on: MILESTONE-01 through MILESTONE-13
Scope:
  - Simultaneous operation of all security layers.
  - End-to-end performance validation under load.
Frozen interfaces:
  - NONE
Gate condition:
  - At 2000 RPS, p99 added latency ≤ 30ms, zero requests dropped, and ≥95% of a mixed attack corpus (SQLi, XSS, RCE) is blocked. Verified by: k6 load test script integrated with GoTestWAF.
Definition of done:
  - Gate condition passes in CI
  - No regressions in dependent milestones
  - All frozen interfaces unchanged
  - Security: attack corpus test results logged and diffable
  - Performance: Sustained 2000 RPS on 4 vCPU / 8GB RAM.
Rollback condition:
  - Latency spikes > 100ms or block rate degradation under load.

## Section 3: Frozen Decision Registry

FROZEN: Fail mode (open vs closed)
Rationale: Critical for defining system reliability vs security posture during component failure.
Superseded by: ADR-011

FROZEN: Rule DSL syntax
Rationale: Stable DSL is required for rule portability and Control Plane/Proxy compatibility.
Superseded by: M-03

FROZEN: Log schema
Rationale: Fixed schema ensures compatibility with downstream SIEM and analytics tools.
Superseded by: M-13

FROZEN: Multi-tenant isolation model
Rationale: Foundational security property; any change requires full re-audit of the entire platform.
Superseded by: M-10

## Section 4: Security-Specific Warning Flags (Self-Audit)

1. Which components, if bypassed, allow an attacker to reach the protected backend completely unfiltered?
   - The Reverse Proxy (`internal/proxy/proxy.go`) and the Rule Engine (`pkg/engine/engine.go`) are the primary gates. A bypass in `ServeHTTP` or a failure in the `InspectRequest` loop allows unfiltered access.

2. Which ADRs contain a decision where the wrong choice creates a security vulnerability (not just a bug)?
   - ADR-011 (Fail mode): Choosing "fail-open" for critical failures could allow attackers to bypass the WAF by intentionally crashing components.
   - ADR-012 (Admin API security): Insecure auth/audit allows total platform takeover.
   - ADR-002 (Rule DSL): Flawed regex evaluation or normalization can lead to widespread bypasses (e.g., via double-encoding).

3. Is the current ML anomaly detection implementation actually ML, or is it a threshold/rules system labeled as ML?
   - Production Hybrid. Heuristics (Entropy/Binary Ratio) are in `pkg/engine/ml.go`. A functional Isolation Forest implementation exists in `pkg/engine/ml_forest.go` with training support. `onnx.go` remains a mock returning 0.5.

4. Which OWASP attack classes have NO passing gate condition yet?
   - Protocol violations, HTTP request smuggling, and advanced API security (e.g., BOLA) lack specific gate conditions in the current milestone map.

5. What is the current fail mode when the rule engine crashes? Is it fail-open or fail-closed? Where in the code is this enforced?
   - Current implementation in `internal/proxy/proxy.go`: if `InspectRequest` or `InspectAPI` were to panic or error without a recovery mechanism, it depends on the Go HTTP server behavior (usually returns 500). However, the specific components like Rate Limiting are explicitly "fail open" (returns true on error in `pkg/engine/ratelimit.go`). Core inspection lacks an explicit fail-closed guard [NEEDS HUMAN SECURITY REVIEW].

6. List every component that touches raw request data. For each one: is PII logged?
   - `internal/proxy/proxy.go` (ServeHTTP): Reads raw body.
   - `pkg/engine/parser.go`: Normalizes body and URL.
   - `pkg/engine/engine.go`: Evaluates conditions on body/URL.
   - `internal/proxy/stats.go`: Reports URL and Method to Control Plane.
   - Currently, the Control Plane `PostStats` (in `cmd/control-plane/main.go`) logs the URL and Method. [NEEDS HUMAN SECURITY REVIEW]: Is PII in the URL (e.g., `/user/email@example.com`) or Body being masked before logging to `sentinel.db`?

7. Which multi-tenant boundary in the current code is enforced by a runtime check vs enforced by architecture?
   - Enforced by runtime check: The `Engine.InspectRequest` function selects rules based on `req.TenantID` at runtime. Architecture enforcement (e.g., separate process per tenant) is not present.

## Section 5: Gate Condition Reality Check

| Milestone | Test Corpus Named? | CI-runnable Today? | Numeric Threshold? | Gap |
| :--- | :--- | :--- | :--- | :--- |
| M-01 | YES (cURL) | YES | YES (0 mod) | None |
| M-02 | YES (nmap) | YES | YES (100%) | `testssl.sh` missing in environment |
| M-03 | YES (Go Test) | YES | YES (100%) | None |
| M-04 | YES (sqli_test.go)| YES | YES (90%) | None (Integrated in CI) |
| M-05 | YES (xss_test.go) | YES | YES (90%) | None (Integrated in CI) |
| M-06 | YES (m06_test.go) | YES | YES (85%) | None (Integrated in CI) |
| M-07 | YES (ratelimit_test.go)| YES | YES (10 req/min)| None (Integrated in CI) |
| M-08 | YES (threat_intel_test.go)| YES | YES (30s) | None (Integrated in CI) |
| M-09 | YES (bot_test.go) | YES | YES (100%) | None (Integrated in CI) |
| M-10 | YES (tenant_test.go)| YES | YES (100%) | None (Integrated in CI) |
| M-11 | YES (ml_test.go) | YES | YES (Score > 0)| None (Integrated in CI) |
| M-12 | YES (API Scan) | NO | YES (401/403)| DAST scanner (e.g. ZAP) not configured |
| M-13 | YES (Monitor) | YES | YES (1s/99%) | None |
| M-14 | YES (k6+GoTestWAF)| NO | YES (2000 RPS)| `k6` and `GoTestWAF` missing |

## Section 6: ML Anomaly Detection — Honest Assessment

1. Is there a trained model artifact in the codebase?
   - NO (Static Weights). Search for `.onnx`, `.bin`, `.pt`, `.h5` yielded no relevant model files. However, `pkg/engine/ml_forest.go` now supports in-memory training and tree construction.

2. If YES: N/A

3. If NO: what is the current implementation doing instead?
   - Precise implementation in `pkg/engine/ml.go` (`DetectAnomaly`):
     - **Heuristic Entropy**: Calculates Shannon entropy of the URL string. If > 6.5, increments request score by 5.
     - **Binary Ratio**: Calculates the ratio of non-printable bytes (<32 or >126) in the request body. If > 0.3, increments score by 10.
     - **Functional Isolation Forest**: Calls `e.forest.Score(features)` where features are `[urlEntropy, bodyEntropy, binaryRatio, bodyLength]`. Trees can be trained via `e.forest.Train`.

4. What is the p99 inference latency of the current implementation measured against 10,000 representative requests?
   - [NEEDS HUMAN SECURITY REVIEW]: No specific performance profile for 10,000 requests is currently available. General RPS for simple requests is ~2800.

5. What happens to a request when the ML component is unavailable?
   - Exact code path: `pkg/engine/ml.go` line 67 (`if len(e.forest.Trees) > 0`). If the component (Isolation Forest) is uninitialized/unavailable, the scoring is simply skipped.

6. Verdict: Prototype ML.
   - **Justification**: The component now features a functional Isolation Forest implementation with training logic, but it lacks a robust weight management lifecycle (persistence/distribution) and still heavily relies on hardcoded heuristic fallbacks.

## Section 7: Next Single Ticket

**Title**: Implement Admin API Authentication and Tenant Write Isolation (M-12).

**Scope**:
- Secure all Control Plane endpoints (`cmd/control-plane/main.go`) with JWT authentication.
- Implement Role-Based Access Control (RBAC) to ensure a tenant admin can only modify rules belonging to their own `TenantID`.
- Add an audit log table to the database and record every POST/PUT/DELETE operation with user context.
- Verify that unauthenticated requests return 401 and cross-tenant writes return 403.

**Acceptance criteria**:
- An unauthenticated rule change attempt returns 401 Unauthorized. A rule change attempt for Tenant B by a Tenant A admin returns 403 Forbidden. Verified by: automated API security test.

**Out of scope**:
- Building the frontend UI (Dashboard). Focus is API security.
- Implementing SIEM integration (M-13).
- Real-time rule propagation (using 30s polling for now).

**Security consideration**:
- Failure to enforce tenant boundaries at the API level would allow any authenticated tenant to disable security for the entire platform.

**Definition of done**:
- Automated test runs against secured endpoints.
- Audit log captures 100% of modification attempts.
- No regression in earlier milestones (M-01 through M-11).
