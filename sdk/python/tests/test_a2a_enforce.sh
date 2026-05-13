#!/usr/bin/env bash
# Live enforcement test — proves (a) direction is enforced when locked,
# (b) revoking an edge takes effect within sync window, (c) restores state.
#
# Operations:
#   - Admin actions  → Dashboard API (HTTP, via login token).
#   - A2A traffic    → Python SDK (no manual gateway curl).
#   - Optional Redis assertions → SSH into gateway host (only if
#     CLAMPD_REDIS_SSH_HOST is set; otherwise skipped).
#
# Required env:
#   CLAMPD_API_URL           dashboard API base, e.g. https://api.clampd.dev
#   CLAMPD_LOGIN_EMAIL       admin login email
#   CLAMPD_LOGIN_PASSWORD    admin login password
#   CLAMPD_GATEWAY_URL       e.g. https://gateway.clampd.dev (used by SDK)
#   CLAMPD_API_KEY           org API key (ag_test_... or ag_live_...)
#   CLAMPD_ORG_ID            org UUID
#   CLAMPD_ORCH_ID           parent agent UUID
#   CLAMPD_ORCH_SECRET       parent agent HMAC secret (ags_...)
#   CLAMPD_RESEARCH_ID       child agent UUID
#   CLAMPD_RESEARCH_SECRET   child agent HMAC secret (ags_...)
#   CLAMPD_AUTO_WF_ID        workflow UUID under test (orch+research members)
#
# Optional env (skipped when unset):
#   CLAMPD_REDIS_SSH_HOST     e.g. root@gateway-box.example.com
#   CLAMPD_REDIS_PASSWORD     redis CLI password used inside ssh exec
#   CLAMPD_REDIS_CONTAINER    docker container name (default: clampd-redis-1)

set -uo pipefail

req() {
  local v="${!1:-}"
  if [[ -z "$v" ]]; then
    echo "SKIP: set $1 to run this test" >&2
    exit 0
  fi
  echo "$v"
}

API=$(req CLAMPD_API_URL)
LOGIN_EMAIL=$(req CLAMPD_LOGIN_EMAIL)
LOGIN_PASSWORD=$(req CLAMPD_LOGIN_PASSWORD)
GATEWAY_URL=$(req CLAMPD_GATEWAY_URL)
API_KEY=$(req CLAMPD_API_KEY)
ORG=$(req CLAMPD_ORG_ID)
ORCH=$(req CLAMPD_ORCH_ID)
ORCH_SEC=$(req CLAMPD_ORCH_SECRET)
RESEARCH=$(req CLAMPD_RESEARCH_ID)
RESEARCH_SEC=$(req CLAMPD_RESEARCH_SECRET)
AUTO_WF_ID=$(req CLAMPD_AUTO_WF_ID)

REDIS_SSH_HOST="${CLAMPD_REDIS_SSH_HOST:-}"
REDIS_PASSWORD="${CLAMPD_REDIS_PASSWORD:-}"
REDIS_CONTAINER="${CLAMPD_REDIS_CONTAINER:-clampd-redis-1}"

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
FAIL=0
pass() { echo "${GREEN}PASS${NC} $1${2:+ — $2}"; }
fail() { echo "${RED}FAIL${NC} $1${2:+ — $2}"; FAIL=$((FAIL+1)); }

login() {
  curl -sS -m 10 -k -X POST "$API/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "$(python3 -c "import json,os; print(json.dumps({'email': os.environ['CLAMPD_LOGIN_EMAIL'], 'password': os.environ['CLAMPD_LOGIN_PASSWORD']}))")" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])"
}

api() {
  local method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -sS -m 15 -k -X "$method" "$API$path" \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d "$body"
  else
    curl -sS -m 15 -k -X "$method" "$API$path" \
      -H "Authorization: Bearer $TOKEN"
  fi
}

run_sdk_chain() {
  # Returns 0 if SUCCESS, 1 if blocked. Prints the denial reason on stderr.
  CLAMPD_GATEWAY_URL="$GATEWAY_URL" \
  CLAMPD_API_KEY="$API_KEY" \
  CLAMPD_ORCH_ID="$ORCH" \
  CLAMPD_ORCH_SECRET="$ORCH_SEC" \
  CLAMPD_RESEARCH_ID="$RESEARCH" \
  CLAMPD_RESEARCH_SECRET="$RESEARCH_SEC" \
  python3 - "$1" <<'PY'
import os, sys
import clampd
from clampd.taxonomy import Category, Subcategory, Operation
from clampd.client import ClampdBlockedError

direction = sys.argv[1]  # "fwd" (orch→research) or "rev" (research→orch)
ORCH = os.environ["CLAMPD_ORCH_ID"]
ORCH_SEC = os.environ["CLAMPD_ORCH_SECRET"]
RESEARCH = os.environ["CLAMPD_RESEARCH_ID"]
RESEARCH_SEC = os.environ["CLAMPD_RESEARCH_SECRET"]

clampd.init(agent_id=ORCH,
            gateway_url=os.environ["CLAMPD_GATEWAY_URL"],
            api_key=os.environ["CLAMPD_API_KEY"],
            secret=ORCH_SEC,
            agents={ORCH: ORCH_SEC, RESEARCH: RESEARCH_SEC})
clampd.register_tool("data.analyze", category=Category.DB,
                     subcategory=Subcategory.QUERY, operation=Operation.READ)

if direction == "fwd":
    @clampd.guard("data.analyze", agent_id=RESEARCH)
    def go(q: str) -> dict: return {"ok": True}
    parent = ORCH
else:
    @clampd.guard("data.analyze", agent_id=ORCH)
    def go(q: str) -> dict: return {"ok": True}
    parent = RESEARCH

try:
    with clampd.agent(parent):
        r = go("enforce-test")
    print("SUCCESS")
    sys.exit(0)
except ClampdBlockedError as e:
    resp = getattr(e, "response", None)
    reason = (resp.denial_reason if resp and getattr(resp, "denial_reason", None) else str(e))
    print(f"BLOCKED: {reason[:200]}")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
    sys.exit(2)
PY
}

redis_get() {
  if [[ -z "$REDIS_SSH_HOST" ]]; then
    echo "(redis check skipped: CLAMPD_REDIS_SSH_HOST not set)"
    return
  fi
  ssh -o BatchMode=yes "$REDIS_SSH_HOST" \
    "docker exec $REDIS_CONTAINER redis-cli ${REDIS_PASSWORD:+--pass $REDIS_PASSWORD} GET \"$1\""
}

echo "═══ Stage 0: login ═══"
TOKEN=$(login)
echo "✓ token len=${#TOKEN}"

echo
echo "═══ Stage 1: baseline (BEFORE any change) ═══"
echo "Redis enforcement key: $(redis_get ag:delegation:enforcement:$ORG)"
echo
echo "Workflow $AUTO_WF_ID enforcement_mode:"
api GET "/v1/orgs/$ORG/workflows" | python3 -c "
import sys, json
for w in json.load(sys.stdin):
    if w['id']=='$AUTO_WF_ID':
        print(f'  {w[\"name\"]} → enforcement_mode={w[\"enforcement_mode\"]}')"

echo
echo "═══ Stage 2: enable enforcement via API ═══"
echo "→ PUT workflow with enforcement_mode=true"
api PUT "/v1/orgs/$ORG/workflows/$AUTO_WF_ID" '{"enforcementMode":true}' | python3 -m json.tool 2>&1 | head -5
echo
echo "→ POST /delegation/lock-graph (approve all observed edges)"
api POST "/v1/orgs/$ORG/delegation/lock-graph" '{}' | python3 -m json.tool

echo
echo "Waiting 18s for ag-control delegation_redis_sync (15s tick) + slack..."
sleep 18
echo "Redis enforcement key now: $(redis_get ag:delegation:enforcement:$ORG)"
echo "Approved Redis edge $ORCH→$RESEARCH: $(redis_get ag:delegation:approved:$ORCH:$RESEARCH | head -c 120)"
echo "Approved Redis edge $RESEARCH→$ORCH: $(redis_get ag:delegation:approved:$RESEARCH:$ORCH | head -c 120) (expected: empty)"

echo
echo "═══ Stage 3: SDK A→B (should SUCCEED — approved edge) ═══"
OUT=$(run_sdk_chain fwd)
echo "  result: $OUT"
case "$OUT" in
  SUCCESS*) pass "T1 forward direction works (approved edge)" ;;
  *)        fail "T1 forward direction" "$OUT" ;;
esac

echo
echo "═══ Stage 4: SDK B→A (should FAIL — no reverse-direction edge) ═══"
OUT=$(run_sdk_chain rev)
echo "  result: $OUT"
case "$OUT" in
  *delegation_not_approved*) pass "T2 reverse direction blocked" "delegation_not_approved as expected" ;;
  *BLOCKED*)                 pass "T2 reverse direction blocked" "denied: $OUT" ;;
  SUCCESS*)                  fail "T2 reverse direction" "request succeeded but reverse edge was never approved" ;;
  *)                         fail "T2 reverse direction" "$OUT" ;;
esac

echo
echo "═══ Stage 5: revoke A→B via API ═══"
echo "→ POST /delegation/unlink"
api POST "/v1/orgs/$ORG/delegation/unlink" \
  "{\"parent_agent_id\":\"$ORCH\",\"child_agent_id\":\"$RESEARCH\"}" \
  | python3 -m json.tool

echo
echo "Waiting 22s for sync (15s sync + 5s L1 + slack)..."
sleep 22
echo "Approved Redis edge $ORCH→$RESEARCH after revoke: $(redis_get ag:delegation:approved:$ORCH:$RESEARCH | head -c 120) (expected: empty)"

echo
echo "═══ Stage 6: SDK A→B (should FAIL — edge revoked) ═══"
OUT=$(run_sdk_chain fwd)
echo "  result: $OUT"
case "$OUT" in
  *delegation_not_approved*) pass "T3 revocation enforced" "delegation_not_approved" ;;
  *BLOCKED*)                 pass "T3 revocation enforced" "$OUT" ;;
  SUCCESS*)                  fail "T3 revocation enforced" "edge revoked but call still succeeded" ;;
  *)                         fail "T3 revocation enforced" "$OUT" ;;
esac

echo
echo "═══ Stage 7: RESTORE baseline ═══"
echo "→ PUT workflow enforcement_mode back to false"
api PUT "/v1/orgs/$ORG/workflows/$AUTO_WF_ID" '{"enforcementMode":false}' >/dev/null && echo "✓ enforcement disabled"
echo "→ POST /delegation/link to re-establish $ORCH→$RESEARCH as observed"
api POST "/v1/orgs/$ORG/delegation/link" \
  "{\"parent_agent_id\":\"$ORCH\",\"child_agent_id\":\"$RESEARCH\",\"status\":\"observed\",\"confidence\":\"declared\",\"allowed_tools\":[],\"max_delegation_depth\":5}" \
  >/dev/null && echo "✓ baseline relationship restored"

sleep 4
echo "Final Redis enforcement key: $(redis_get ag:delegation:enforcement:$ORG)"

echo
echo "═══════════════════════════════════════"
if [ "$FAIL" -eq 0 ]; then
  echo "${GREEN}ALL PASSED${NC} — direction enforced + revocation propagates"
  exit 0
else
  echo "${RED}FAILED: $FAIL check(s)${NC}"
  exit 1
fi
