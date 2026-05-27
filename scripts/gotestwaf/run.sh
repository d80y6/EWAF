#!/bin/bash
set -e

# 1. Start WAF and Target stack
docker compose up -d postgres redis nats clickhouse control-plane proxy echo

# 2. Wait for proxy to be healthy
echo "Waiting for WAF Proxy to be ready..."
until curl -s http://localhost:80/health; do
  sleep 2
done

# 3. Run GoTestWAF
echo "Running GoTestWAF..."
docker run --rm --network host \
  -v $(pwd)/reports:/app/reports \
  wallarm/gotestwaf --url=http://localhost:80 --verbose --no-color

# 4. Cleanup
# docker compose down
