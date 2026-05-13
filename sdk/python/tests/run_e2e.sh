#!/bin/bash
# Run full e2e test suite against live Docker stack.
# Waits for gateway, seeds tools, clears limits, runs tests.
set -uo pipefail

GATEWAY=${CLAMPD_GATEWAY_URL:-http://localhost:8080}
REDIS_PASS=clampd_trial
ORG="a0000000-0000-0000-0000-000000000001"
export JWT_SECRET=${JWT_SECRET:-$(grep JWT_SECRET /home/sakshi/Documents/clampd_dev/clampd/.env | cut -d= -f2)}
AGENT_A="b0000000-0000-0000-0000-000000000001"

echo "=== Clampd E2E Test Runner ==="

# 1. Wait for gateway
echo -n "Waiting for gateway..."
for i in $(seq 1 30); do
  if curl -sS "$GATEWAY/health" >/dev/null 2>&1; then
    echo " OK"
    break
  fi
  echo -n "."
  sleep 2
done

# 2. Seed tool scopes
echo "Seeding tool scopes..."
for entry in \
  "database.query|{\"scopes\":[\"db:query:read\",\"db:query:write\"],\"descriptor_hash\":\"demo\"}" \
  "shell.exec|{\"scopes\":[\"exec:code:eval\"],\"descriptor_hash\":\"demo\"}" \
  "filesystem.read|{\"scopes\":[\"fs:file:read\"],\"descriptor_hash\":\"demo\"}" \
  "http.fetch|{\"scopes\":[\"net:http:outbound\"],\"descriptor_hash\":\"demo\"}" \
  "http.respond|{\"scopes\":[\"net:http:outbound\"],\"descriptor_hash\":\"demo\"}" \
  "llm.completion|{\"scopes\":[\"llm:input:completion\"],\"descriptor_hash\":\"demo\"}" \
  "network.dns|{\"scopes\":[\"net:dns:resolve\"],\"descriptor_hash\":\"demo\"}" \
; do
  tool="${entry%%|*}"
  value="${entry#*|}"
  docker exec clampd-redis redis-cli -a $REDIS_PASS SET "ag:tool:scope:${ORG}:${tool}" "$value" >/dev/null 2>&1
done

# 3. Clear stale state (Redis + trigger ag-risk in-memory reset via revive command)
echo "Clearing stale state..."
docker exec clampd-redis redis-cli -a $REDIS_PASS KEYS "ag:session:create_count:*" 2>/dev/null | while read key; do
  docker exec clampd-redis redis-cli -a $REDIS_PASS DEL "$key" >/dev/null 2>&1
done
docker exec clampd-redis redis-cli -a $REDIS_PASS DEL \
  "ag:deny:$AGENT_A" \
  "ag:agent:suspended:$AGENT_A" \
  "ag:risk:suspicion:$AGENT_A" \
  "ag:enhanced_monitoring:$AGENT_A" \
  >/dev/null 2>&1
docker exec clampd-redis redis-cli -a $REDIS_PASS HDEL "ag:risk:scores" "$AGENT_A" >/dev/null 2>&1
# Clear old sessions so tests start fresh
docker exec clampd-redis redis-cli -a $REDIS_PASS KEYS "ag:session:*" 2>/dev/null | while read key; do
  docker exec clampd-redis redis-cli -a $REDIS_PASS DEL "$key" >/dev/null 2>&1
done
# Trigger revive via Postgres command so ag-risk resets in-memory EMA + gateway clears deny set
docker exec clampd-postgres psql -U clampd -d clampd -c "
INSERT INTO runtime_commands (org_id, type, payload)
VALUES ('$ORG', 'update_agent_state',
  '{\"agent_id\": \"$AGENT_A\", \"new_state\": \"active\", \"reason\": \"e2e test reset\"}'::jsonb)
ON CONFLICT DO NOTHING;
" >/dev/null 2>&1
echo -n "Waiting for revive to propagate..."
for i in $(seq 1 15); do
  result=$(JWT_SECRET=$JWT_SECRET python3 -c "
import sys; sys.path.insert(0,'.')
from clampd.client import ClampdClient
c = ClampdClient(gateway_url='$GATEWAY', agent_id='$AGENT_A', api_key='ag_test_demo_clampd_2026', secret='$JWT_SECRET', session_id='revive-check')
r = c.verify('database.query', {'sql': 'SELECT 1'})
print('ok' if r.allowed else 'blocked')
" 2>/dev/null)
  if [ "$result" = "ok" ]; then
    echo " OK (${i}s)"
    break
  fi
  echo -n "."
  sleep 1
done

# 4. Run tests
echo "Running e2e tests..."
cd /home/sakshi/Documents/clampd_dev/sdk/python

# Run feature tests EXCEPT kill switch (kill poisons subsequent tests)
python3 -m pytest tests/test_features_e2e.py -v --tb=short -k "not KillSwitch" "$@"
FEATURES_EXIT=$?
echo ""
echo "=== Feature E2E Complete (exit=$FEATURES_EXIT) ==="

# Run kill switch test separately (it kills and revives the agent)
python3 -m pytest tests/test_features_e2e.py -v --tb=short -k "KillSwitch" "$@"
KILL_EXIT=$?
echo ""
echo "=== Kill Switch E2E Complete (exit=$KILL_EXIT) ==="

# Re-seed after kill test (agent may be dead)
echo "Re-seeding after kill test..."
docker exec clampd-postgres psql -U clampd -d clampd -c "
INSERT INTO runtime_commands (org_id, type, payload)
VALUES ('$ORG', 'update_agent_state',
  '{\"agent_id\": \"b0000000-0000-0000-0000-000000000001\", \"new_state\": \"active\", \"reason\": \"post-kill-test revive\"}'::jsonb)
ON CONFLICT DO NOTHING;
" >/dev/null 2>&1
sleep 3

# Run full workflow tests (skip dashboard-dependent and kill tests)
python3 -m pytest tests/test_full_workflow_e2e.py -v --tb=short -k "not dashboard and not Kill and not Suspend and not Exemption" "$@"
WORKFLOW_EXIT=$?
echo ""
echo "=== Full Workflow E2E Complete (exit=$WORKFLOW_EXIT) ==="

exit $((FEATURES_EXIT + KILL_EXIT + WORKFLOW_EXIT))
