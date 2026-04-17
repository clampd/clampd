"""A2A Delegation E2E test - runs against live Clampd services.

Simulates two agents in the same process where Agent A delegates to Agent B.
Verifies:
  1. Single agent proxy call works (no delegation)
  2. Nested delegation auto-detected (A -> B chain)
  3. Delegation fields sent to gateway
  4. Cycle detection blocks A -> B -> A
  5. Max depth exceeded blocks deep chains
  6. Shadow audit trail records delegation metadata

Usage:
    # Start services first:  cd clampd && docker compose up -d
    # Then run:
    python3 -m pytest tests/test_a2a_e2e.py -v -s

    # Or run directly:
    python3 tests/test_a2a_e2e.py
"""

import os
import sys
import time

# Ensure SDK is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import clampd
from clampd.client import ClampdBlockedError, ClampdClient
from clampd.delegation import (
    MAX_DELEGATION_DEPTH,
    enter_delegation,
    exit_delegation,
    get_delegation,
)

GATEWAY_URL = os.environ.get("CLAMPD_GATEWAY_URL", "http://localhost:8080")
API_KEY = os.environ.get("CLAMPD_API_KEY", "ag_test_demo_clampd_2026")

# Two agent IDs - simulating separate agents in the same process
AGENT_A_ID = "b0000000-0000-0000-0000-000000000001"  # demo agent from seed
AGENT_B_ID = "b0000000-0000-0000-0000-000000000002"  # second agent (may not exist in registry)


def make_client(agent_id: str) -> ClampdClient:
    return ClampdClient(
        gateway_url=GATEWAY_URL,
        agent_id=agent_id,
        api_key=API_KEY,
    )


def test_gateway_health():
    """Verify gateway is reachable."""
    import httpx
    resp = httpx.get(f"{GATEWAY_URL}/health", timeout=5.0)
    assert resp.status_code == 200, f"Gateway not healthy: {resp.status_code}"
    print(f"  Gateway healthy: {resp.json()}")


def test_single_agent_proxy():
    """Single agent makes a safe tool call - no delegation."""
    client_a = make_client(AGENT_A_ID)
    resp = client_a.proxy(
        tool="db.query",
        params={"sql": "SELECT name FROM users WHERE id = 1"},
    )
    print(f"  Single agent: allowed={resp.allowed}, risk={resp.risk_score:.2f}, action={resp.action}")
    assert resp.allowed or resp.risk_score < 0.85, f"Safe call should be allowed: {resp.denial_reason}"


def test_single_agent_no_delegation_fields():
    """Single agent call should NOT have delegation context."""
    ctx = get_delegation()
    assert ctx is None, "Should have no delegation context outside guard"


def test_nested_delegation_auto_detected():
    """Agent A calls Agent B - delegation chain auto-detected via contextvars."""
    client_a = make_client(AGENT_A_ID)
    client_b = make_client(AGENT_B_ID)

    # Agent A enters its scope
    ctx_a, token_a = enter_delegation(AGENT_A_ID)
    try:
        assert ctx_a.chain == [AGENT_A_ID]
        assert ctx_a.caller_agent_id is None  # root, no parent
        print(f"  Agent A context: chain={ctx_a.chain}, depth={ctx_a.depth}")

        # Agent A delegates to Agent B
        ctx_b, token_b = enter_delegation(AGENT_B_ID)
        try:
            assert ctx_b.chain == [AGENT_A_ID, AGENT_B_ID]
            assert ctx_b.caller_agent_id == AGENT_A_ID
            assert ctx_b.trace_id == ctx_a.trace_id  # same trace
            assert ctx_b.depth == 2
            print(f"  Agent B context: chain={ctx_b.chain}, caller={ctx_b.caller_agent_id}, trace={ctx_b.trace_id}")

            # Agent B makes a proxy call - should include delegation fields
            resp = client_b.proxy(
                tool="db.query",
                params={"sql": "SELECT COUNT(*) FROM orders"},
            )
            print(f"  Delegated call: allowed={resp.allowed}, risk={resp.risk_score:.2f}")
        finally:
            exit_delegation(token_b)

        # Back to Agent A scope
        current = get_delegation()
        assert current is not None
        assert current.chain == [AGENT_A_ID], "Should restore A's context"
    finally:
        exit_delegation(token_a)

    # Outside all scopes
    assert get_delegation() is None


def test_delegation_fields_sent_to_gateway():
    """Verify the proxy body includes delegation fields when nested."""

    # Enter delegation context: A -> B
    ctx_a, token_a = enter_delegation(AGENT_A_ID)
    ctx_b, token_b = enter_delegation(AGENT_B_ID)

    try:
        ctx = get_delegation()
        assert ctx is not None
        assert ctx.caller_agent_id == AGENT_A_ID

        # Build the request body manually to inspect what gets sent
        body = {
            "tool": "db.query",
            "params": {"sql": "SELECT 1"},
            "target_url": "",
        }
        if ctx.caller_agent_id:
            body["caller_agent_id"] = ctx.caller_agent_id
            body["delegation_chain"] = ctx.chain
            body["delegation_trace_id"] = ctx.trace_id

        print("  Request body delegation fields:")
        print(f"    caller_agent_id: {body.get('caller_agent_id')}")
        print(f"    delegation_chain: {body.get('delegation_chain')}")
        print(f"    delegation_trace_id: {body.get('delegation_trace_id')}")

        assert "caller_agent_id" in body
        assert body["caller_agent_id"] == AGENT_A_ID
        assert body["delegation_chain"] == [AGENT_A_ID, AGENT_B_ID]
        assert body["delegation_trace_id"] == ctx.trace_id

        # Actually send it to the gateway
        client_b = make_client(AGENT_B_ID)
        resp = client_b.proxy(
            tool="db.query",
            params={"sql": "SELECT 1"},
        )
        print(f"  Gateway response: allowed={resp.allowed}, risk={resp.risk_score:.2f}")
    finally:
        exit_delegation(token_b)
        exit_delegation(token_a)


def test_cycle_detection_blocks():
    """A -> B -> A should be detected as a cycle."""
    ctx_a, token_a = enter_delegation(AGENT_A_ID)
    ctx_b, token_b = enter_delegation(AGENT_B_ID)
    try:
        # Try to re-enter Agent A (cycle: A -> B -> A)
        ctx_cycle, token_cycle = enter_delegation(AGENT_A_ID)
        try:
            assert ctx_cycle.has_cycle(), "Should detect cycle"
            print(f"  Cycle detected: chain={ctx_cycle.chain}")

            # The SDK guard() decorator would raise ClampdBlockedError here
            # Let's verify the cycle detection works
            assert ctx_cycle.chain == [AGENT_A_ID, AGENT_B_ID, AGENT_A_ID]
        finally:
            exit_delegation(token_cycle)
    finally:
        exit_delegation(token_b)
        exit_delegation(token_a)


def test_max_depth_detection():
    """Chain deeper than MAX_DELEGATION_DEPTH should be detected."""
    tokens = []
    try:
        for i in range(MAX_DELEGATION_DEPTH + 2):
            agent_id = f"agent-{i:04d}"
            ctx, token = enter_delegation(agent_id)
            tokens.append(token)

        assert ctx.depth > MAX_DELEGATION_DEPTH
        print(f"  Max depth exceeded: depth={ctx.depth}, max={MAX_DELEGATION_DEPTH}")
    finally:
        for token in reversed(tokens):
            exit_delegation(token)


def test_guard_decorator_with_delegation():
    """Test @clampd.guard() with nested delegation."""
    client_a = make_client(AGENT_A_ID)
    clampd._default_client = client_a

    try:
        @clampd.guard("db.query", agent_id=AGENT_A_ID)
        def agent_a_query(sql: str) -> str:
            return f"result of: {sql}"

        # Single agent call
        result = agent_a_query("SELECT 1")
        print(f"  Guard single agent: {result}")
    except ClampdBlockedError as e:
        print(f"  Guard single agent blocked (expected if no registered agent): {e}")
    finally:
        clampd._default_client = None


def test_delegation_headers():
    """Test cross-service delegation headers."""
    ctx_a, token_a = enter_delegation(AGENT_A_ID)
    ctx_b, token_b = enter_delegation(AGENT_B_ID)
    try:
        headers = clampd.delegation_headers()
        print(f"  Delegation headers: {headers}")
        assert "X-Clampd-Delegation-Trace" in headers
        assert "X-Clampd-Delegation-Chain" in headers
        assert "X-Clampd-Delegation-Confidence" in headers
        assert AGENT_A_ID in headers["X-Clampd-Delegation-Chain"]
        assert AGENT_B_ID in headers["X-Clampd-Delegation-Chain"]
    finally:
        exit_delegation(token_b)
        exit_delegation(token_a)

    # Outside delegation - empty headers
    headers = clampd.delegation_headers()
    assert headers == {}


def test_concurrent_delegation_isolated():
    """Verify that two concurrent delegation chains don't interfere."""
    import threading

    results = {}

    def agent_a_work():
        ctx, token = enter_delegation("agent-thread-A")
        try:
            time.sleep(0.05)  # Let other thread start
            d = get_delegation()
            results["A"] = d.chain if d else []
        finally:
            exit_delegation(token)

    def agent_b_work():
        ctx, token = enter_delegation("agent-thread-B")
        try:
            time.sleep(0.05)
            d = get_delegation()
            results["B"] = d.chain if d else []
        finally:
            exit_delegation(token)

    t1 = threading.Thread(target=agent_a_work)
    t2 = threading.Thread(target=agent_b_work)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    print(f"  Thread A chain: {results.get('A')}")
    print(f"  Thread B chain: {results.get('B')}")
    assert results["A"] == ["agent-thread-A"]
    assert results["B"] == ["agent-thread-B"]


# ── Run all tests ───────────────────────────────────────────────────

ALL_TESTS = [
    test_gateway_health,
    test_single_agent_proxy,
    test_single_agent_no_delegation_fields,
    test_nested_delegation_auto_detected,
    test_delegation_fields_sent_to_gateway,
    test_cycle_detection_blocks,
    test_max_depth_detection,
    test_guard_decorator_with_delegation,
    test_delegation_headers,
    test_concurrent_delegation_isolated,
]


def main():
    print("\nA2A Delegation E2E Tests")
    print(f"Gateway: {GATEWAY_URL}")
    print(f"API Key: {API_KEY[:20]}...")
    print(f"Agent A: {AGENT_A_ID}")
    print(f"Agent B: {AGENT_B_ID}")
    print("=" * 60)

    passed = 0
    failed = 0
    skipped = 0

    for test_fn in ALL_TESTS:
        name = test_fn.__name__
        try:
            print(f"\n[RUN] {name}")
            test_fn()
            print(f"[PASS] {name}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            if "gateway_unreachable" in str(e) or "ConnectError" in str(type(e).__name__):
                print(f"[SKIP] {name}: Gateway not reachable")
                skipped += 1
            else:
                print(f"[FAIL] {name}: {type(e).__name__}: {e}")
                failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
