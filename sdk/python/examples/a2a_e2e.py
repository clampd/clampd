"""
End-to-end A2A scenario example driven entirely through the Clampd Python SDK
against a real gateway (no direct HTTP, no manual JWT minting).

Scenarios exercised:
  S1  Normal depth-2 (orchestrator -> research)         -> expect SUCCESS
  S2  Depth-3 chain  (orch -> research -> writer)       -> expect SUCCESS + cross_boundary_delegation event
  S3  Chain too deep (depth-6)                          -> expect ClampdBlockedError invalid_delegation_chain
  S4  Cycle in chain (orch -> research -> orch)         -> expect ClampdBlockedError invalid_delegation_chain
  S5  Task replay (same call twice in <60s)             -> second call expect task_replay_detected
  S6  Cross-boundary delegation audit row               -> assert via Postgres after depth-3 (out of band)

Required environment (set these before running):
  CLAMPD_GATEWAY_URL   e.g. https://gateway.your-deployment
  CLAMPD_API_KEY       org-level API key (ag_test_... or ag_live_...)
  CLAMPD_ORG_ID        org UUID (optional, kept for reference)
  For each of 6 agents (ORCH, RESEARCH, WRITER, LINK2, LINK3, LINK4):
    CLAMPD_<NAME>_ID       agent UUID
    CLAMPD_<NAME>_SECRET   HMAC signing secret (ags_...)

Run:
  python3 examples/a2a_e2e.py
"""
import os
import sys

import clampd
from clampd.taxonomy import Category, Subcategory, Operation
from clampd.client import ClampdBlockedError

GREEN, RED, YELLOW, NC = "\033[92m", "\033[91m", "\033[93m", "\033[0m"


def _required_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        print(f"SKIP: set {name} to run this example", file=sys.stderr)
        sys.exit(0)
    return val


# Credentials (env vars only — no hardcoded fallbacks).
GW = _required_env("CLAMPD_GATEWAY_URL")
API_KEY = _required_env("CLAMPD_API_KEY")
ORG = os.environ.get("CLAMPD_ORG_ID", "")  # optional, used in audit lookups

# 6 agents: 3 base (orch/research/writer) + 3 link agents for the depth-6 chain.
AGENTS = {
    _required_env("CLAMPD_ORCH_ID"):     _required_env("CLAMPD_ORCH_SECRET"),
    _required_env("CLAMPD_RESEARCH_ID"): _required_env("CLAMPD_RESEARCH_SECRET"),
    _required_env("CLAMPD_WRITER_ID"):   _required_env("CLAMPD_WRITER_SECRET"),
    _required_env("CLAMPD_LINK2_ID"):    _required_env("CLAMPD_LINK2_SECRET"),
    _required_env("CLAMPD_LINK3_ID"):    _required_env("CLAMPD_LINK3_SECRET"),
    _required_env("CLAMPD_LINK4_ID"):    _required_env("CLAMPD_LINK4_SECRET"),
}
ORCH, RESEARCH, WRITER, LINK2, LINK3, LINK4 = list(AGENTS.keys())

results: list[tuple[str, bool, str]] = []


def pass_(name: str, detail: str = "") -> None:
    print(f"{GREEN}PASS{NC} {name}" + (f" — {detail}" if detail else ""))
    results.append((name, True, detail))


def fail_(name: str, detail: str = "") -> None:
    print(f"{RED}FAIL{NC} {name}" + (f" — {detail}" if detail else ""))
    results.append((name, False, detail))


def blocked_reason(e: "ClampdBlockedError") -> str:
    """Extract a human-readable reason from ClampdBlockedError regardless of
    whether the block originated server-side (e.response.denial_reason)
    or client-side (e.args[0] from the SDK's own depth/cycle guard).
    """
    resp = getattr(e, "response", None)
    if resp is not None and getattr(resp, "denial_reason", None):
        return resp.denial_reason
    return str(e)


def setup_sdk() -> None:
    """Init SDK + register descriptors. Must run BEFORE any @clampd.guard
    decoration because guard's decorator-time logic looks up the client.
    """
    clampd.init(
        agent_id=ORCH,
        gateway_url=GW,
        api_key=API_KEY,
        secret=AGENTS[ORCH],
        agents=AGENTS,
    )
    # Register tools without descriptions on either side so register-time and
    # guard-time descriptor_hashes match.
    clampd.register_tool("web.search",    category=Category.NET,   subcategory=Subcategory.HTTP,         operation=Operation.READ)
    clampd.register_tool("data.analyze",  category=Category.DB,    subcategory=Subcategory.QUERY,        operation=Operation.READ)
    clampd.register_tool("report.notify", category=Category.COMMS, subcategory=Subcategory.NOTIFICATION, operation=Operation.SEND)


# Guarded function placeholders — populated by build_guards() after init.
search_web = analyze_only = notify_report = deep_target = cycle_target = None  # type: ignore[assignment]


def build_guards() -> None:
    """Apply @clampd.guard decorators AFTER init has set up the client."""
    global search_web, analyze_only, notify_report, deep_target, cycle_target

    @clampd.guard("report.notify", agent_id=WRITER)
    def _notify(title: str, body: str) -> str:
        return "queued"

    @clampd.guard("web.search", agent_id=RESEARCH)
    def _search(query: str) -> dict:
        _notify(title="r", body=f"q={query!r}")  # depth-3 via nested guard
        return {"hits": ["r1", "r2", "r3"]}

    @clampd.guard("data.analyze", agent_id=RESEARCH)
    def _analyze(query: str) -> dict:
        return {"hits": ["x", "y"]}

    @clampd.guard("data.analyze", agent_id=LINK4)
    def _deep() -> str:
        return "should-never-reach-here"

    @clampd.guard("data.analyze", agent_id=ORCH)
    def _cycle() -> str:
        return "should-never-reach-here"

    search_web    = _search
    analyze_only  = _analyze
    notify_report = _notify
    deep_target   = _deep
    cycle_target  = _cycle


# ── S1: Normal depth-2 ────────────────────────────────────────────────
def s1_depth_2() -> None:
    print(f"\n{YELLOW}S1{NC}  depth-2 (orchestrator → research)")
    with clampd.agent(ORCH):
        try:
            r = analyze_only("baseline-2hop")
            pass_("S1 depth-2 chain", f"result={r}")
        except ClampdBlockedError as e:
            fail_("S1 depth-2 chain", f"unexpected block: {e.response.denial_reason}")
        except Exception as e:
            fail_("S1 depth-2 chain", f"{type(e).__name__}: {e}")


# ── S2: Depth-3 ──────────────────────────────────────────────────────
def s2_depth_3() -> None:
    print(f"\n{YELLOW}S2{NC}  depth-3 (orchestrator → research → writer)")
    with clampd.agent(ORCH):
        try:
            r = search_web("baseline-3hop")
            pass_("S2 depth-3 chain", f"result={r}")
        except ClampdBlockedError as e:
            fail_("S2 depth-3 chain", f"unexpected block: {e.response.denial_reason}")
        except Exception as e:
            fail_("S2 depth-3 chain", f"{type(e).__name__}: {e}")


# ── S3: Chain too deep (depth-6, MAX is 5) ───────────────────────────
# Builds a chain by nesting agent scopes so the SDK threads them onto
# the chain stack. The deepest guarded call sends chain.len()=6 which
# the gateway rejects.
def s3_too_deep() -> None:
    print(f"\n{YELLOW}S3{NC}  chain too deep (depth-6, MAX=5)")
    try:
        with clampd.agent(ORCH):
            with clampd.agent(RESEARCH):
                with clampd.agent(WRITER):
                    with clampd.agent(LINK2):
                        with clampd.agent(LINK3):
                            deep_target()  # 6th hop via @guard(agent_id=LINK4)
        fail_("S3 too-deep blocked", "request succeeded but should have been denied")
    except ClampdBlockedError as e:
        reason = blocked_reason(e)
        if ("invalid_delegation_chain" in reason or "exceeds maximum" in reason
                or "too deep" in reason.lower()):
            pass_("S3 too-deep blocked", f"denied as expected: {reason[:80]}")
        else:
            fail_("S3 too-deep blocked", f"blocked but wrong reason: {reason}")
    except Exception as e:
        fail_("S3 too-deep blocked", f"{type(e).__name__}: {e}")


# ── S4: Cycle in chain (orch → research → orch) ─────────────────────
def s4_cycle() -> None:
    print(f"\n{YELLOW}S4{NC}  cycle (orch → research → orch)")
    try:
        with clampd.agent(ORCH):
            with clampd.agent(RESEARCH):
                # @guard(agent_id=ORCH) makes orch the executor — chain becomes
                # [orch, research, orch] which is a self-cycle.
                cycle_target()
        fail_("S4 cycle blocked", "request succeeded but should have been denied")
    except ClampdBlockedError as e:
        reason = blocked_reason(e)
        if "invalid_delegation_chain" in reason or "Circular" in reason or "cycle" in reason.lower():
            pass_("S4 cycle blocked", f"denied as expected: {reason[:80]}")
        else:
            fail_("S4 cycle blocked", f"blocked but wrong reason: {reason}")
    except Exception as e:
        fail_("S4 cycle blocked", f"{type(e).__name__}: {e}")


# ── S5: Task replay (same call twice within 60s) ──────────────────────
def s5_task_replay() -> None:
    print(f"\n{YELLOW}S5{NC}  task replay (identical call twice within 60s)")
    # First call: should pass.
    with clampd.agent(ORCH):
        try:
            r1 = analyze_only("replay-probe")
            pass_("S5 first call allowed", f"result={r1}")
        except Exception as e:
            fail_("S5 first call allowed", f"{type(e).__name__}: {e}")
            return
    # Second call: identical (caller, target, tool, params, trace) tuple
    # gets blocked by `ag:replay:{sha256}` SETNX with 60s TTL. We need
    # to hold the SAME delegation context — the SDK auto-generates a
    # new trace_id per top-level `clampd.agent` scope. To exercise
    # this check we run BOTH calls inside the same scope so the
    # trace_id is shared.
    print("    (re-running both calls inside same agent scope to share trace_id)")
    try:
        with clampd.agent(ORCH):
            analyze_only("replay-probe-2")  # writes the replay key
            try:
                analyze_only("replay-probe-2")  # same params → same hash → replay
                fail_("S5 replay blocked", "second identical call should have been blocked")
            except ClampdBlockedError as e:
                reason = e.response.denial_reason or ""
                if "task_replay" in reason or "replay" in reason.lower():
                    pass_("S5 replay blocked", f"denied: {reason[:80]}")
                else:
                    fail_("S5 replay blocked", f"blocked but wrong reason: {reason}")
    except Exception as e:
        fail_("S5 replay blocked", f"{type(e).__name__}: {e}")


# ── S6: Cross-boundary delegation audit row (post-S2 verification) ───
# This isn't a separate request — it's verified by reading audit logs
# after S2 ran. ag-gateway publishes a shadow event with
# a2a_event_type='cross_boundary_delegation' for any chain.len() > 2.
# Verification is done out of band (e.g. a bash runner wrapping this).


def main() -> int:
    setup_sdk()
    build_guards()
    s1_depth_2()
    s2_depth_3()
    s3_too_deep()
    s4_cycle()
    s5_task_replay()

    print(f"\n{'═' * 60}")
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"  results: {passed}/{total} passed")
    if passed == total:
        print(f"  {GREEN}ALL PASSED{NC}")
        return 0
    print(f"  {RED}{total - passed} FAILED{NC}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
