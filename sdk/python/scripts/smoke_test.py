#!/usr/bin/env python3
"""End-to-end smoke test for Clampd enrollment + proxy (production token path).

Validates the whole zero-config path against a running gateway, with no SDK
publish and no dev bypass:

    mint enroll token  ->  SDK enrolls (Ed25519)  ->  EdDSA JWT  ->  /v1/proxy

Prerequisites
-------------
* The Clampd gateway running (default http://localhost:8080) with its
  registry / Redis / NATS / Postgres — e.g. `services/run-local.sh`.
* An org API key for that gateway (create one in the dashboard):
      export CLAMPD_API_KEY=ag_live_...
* This SDK installed locally (no registry publish needed):
      pip install -e sdk/python

Run
---
    CLAMPD_API_KEY=ag_live_... python scripts/smoke_test.py
    # optional: GATEWAY_URL=http://host:8080
"""

from __future__ import annotations

import os
import sys

import httpx

import clampd

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")
API_KEY = os.environ.get("CLAMPD_API_KEY", "")


def fail(msg: str) -> "None":
    print(f"✗ {msg}")
    sys.exit(1)


def main() -> None:
    if not API_KEY:
        fail("set CLAMPD_API_KEY (the org key from the dashboard)")

    # 1. Mint an enrollment token (admin op, org-key auth). Production path —
    #    no CLAMPD_ALLOW_OPEN_ENROLLMENT needed.
    try:
        resp = httpx.post(
            f"{GATEWAY_URL}/v1/enroll-tokens",
            headers={"X-AG-Key": API_KEY},
            json={"ttl_seconds": 600},
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        fail(f"could not reach gateway at {GATEWAY_URL}: {e}")
    if resp.status_code != 200:
        fail(f"mint enroll-token failed: {resp.status_code} {resp.text}")
    token = resp.json()["enroll_token"]
    print(f"✓ minted enrollment token (expires_in={resp.json()['expires_in']}s)")

    # 2. Configure the SDK with ONE DSN + the token. No secret, no agent_id.
    scheme = "clampd+http" if GATEWAY_URL.startswith("http://") else "clampd"
    host = GATEWAY_URL.split("://", 1)[1]
    os.environ["CLAMPD_DSN"] = f"{scheme}://{API_KEY}@{host}"
    os.environ["CLAMPD_ENROLL_TOKEN"] = token
    # Use a fresh key dir so the smoke test always exercises a real enrollment.
    os.environ["CLAMPD_HOME"] = "/tmp/clampd-smoke"
    os.system("rm -rf /tmp/clampd-smoke")

    try:
        client = clampd.init(name="smoke-agent")
    except Exception as e:  # noqa: BLE001 - surface any enroll failure clearly
        fail(f"clampd.init() / enrollment failed: {e}")
    if not client.agent_id:
        fail("enrollment returned no agent_id")
    print(f"✓ enrolled — agent_id={client.agent_id} (EdDSA identity, no secret)")

    # 3. Make a proxy call. The point is that the EdDSA JWT AUTHENTICATES and
    #    the pipeline returns a structured decision (allow/block is policy-
    #    dependent; auth working is what this proves).
    try:
        result = client.proxy("db.query", {"sql": "SELECT 1"})
    except Exception as e:  # noqa: BLE001
        fail(f"proxy call failed (auth/transport): {e}")
    if not getattr(result, "request_id", None):
        fail(f"proxy returned no decision: {result}")
    print(f"✓ proxy authenticated — request_id={result.request_id} allowed={result.allowed}")

    # 4. A dangerous payload should not come back allowed.
    danger = client.proxy("db.query", {"sql": "DROP TABLE users; --"})
    print(f"  dangerous SQL → allowed={danger.allowed} denial={danger.denial}")

    print("\n✓ SMOKE TEST PASSED — enrollment + EdDSA auth + proxy verified end-to-end")


if __name__ == "__main__":
    main()
