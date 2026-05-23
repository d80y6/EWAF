# Scalability Analysis - Sentinel WAF

## 1. Proxy Scalability
- **Horizontal**: The Proxy is stateless and can be scaled horizontally using a Load Balancer.
- **Vertical**: Limited by Go's GC and regex engine performance.

## 2. Control Plane Scalability
- **SPOF**: The Control Plane is a bottleneck for stats reporting.
- **Database**: SQLite will fail under even moderate load (e.g., >100 RPS with stats reporting enabled).
- **Rule Propagation**: Polling (30s) does not scale well to thousands of proxy nodes. A push-based system (e.g., gRPC streaming or NATS) is required.

## 3. Telemetry Scalability
- The current design of reporting EVERY event via a separate HTTP POST to the Control Plane is not scalable. It needs batching and an asynchronous messaging layer (Kafka/NATS).
