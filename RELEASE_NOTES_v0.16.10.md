## v0.16.10 - payment guardrails + AP2/x402 hardening

Bug-fix and hardening release. Brings the boundary-allowlist consolidation
(v0.16.1-.4), per-tx + per-hour payment caps (v0.16.5-.7), AP2/x402
replay/freshness/sig-verify (v0.16.6), and the type-mismatch fix that
finally activates payment caps in production (v0.16.9) into one stable
shipping image. Default for `setup.sh` bumped from `v0.13.2` → `v0.16.10`.

## Docker images

```
docker pull ghcr.io/clampd/ag-gateway:v0.16.10
docker pull ghcr.io/clampd/ag-policy:v0.16.10
docker pull ghcr.io/clampd/ag-registry:v0.16.10
docker pull ghcr.io/clampd/ag-intent:v0.16.10
docker pull ghcr.io/clampd/ag-risk:v0.16.10
docker pull ghcr.io/clampd/ag-shadow:v0.16.10
docker pull ghcr.io/clampd/ag-kill:v0.16.10
docker pull ghcr.io/clampd/ag-token:v0.16.10
docker pull ghcr.io/clampd/ag-control:v0.16.10
docker pull ghcr.io/clampd/ag-redteam:v0.16.10
docker pull ghcr.io/clampd/dashboard-api:v0.16.10
docker pull ghcr.io/clampd/dashboard-web:v0.16.10
```

## Update

```
export CLAMPD_VERSION=v0.16.10
docker compose -f docker-compose.proxy.yml pull
docker compose -f docker-compose.proxy.yml up -d --force-recreate
docker compose -f docker-compose.control.yml pull
docker compose -f docker-compose.control.yml up -d --force-recreate
```

Run dashboard migrations (037 + 038) after the dashboard-api container
restarts - they add `agent_boundary_allowlist` cleanup and the missing
`allowed_hours_timezone` / `allowed_days` / `auto_suspend_threshold`
columns on `agent_boundaries`.

## What's fixed

### Payment guardrails (now actually enforced)

- **B-PAYMENT-TX**: per-transaction amount cap. Reads
  `boundaries.max_payment_per_tx_cents` and denies any payment over the
  cap with a typed reason. Hard-deny - not bypassable by scope exemption.
  Closes the gap where SDK-direct `pay_*` tools silently bypassed the
  cap (only the HTTP 402 response-interception path enforced it before).
- **B-PAYMENT-HOUR**: per-hour cumulative spend cap, Redis-backed counter
  per agent per hour. Fail-closed on Redis error.
- Both fields were silently coming through as `0` due to a Rust
  `Option<i64>` vs PG `integer (i32)` decode mismatch that sqlx swallowed.
  Fixed in v0.16.9 - caps now actually apply.

### Vendor allowlist consolidation

- `BoundaryConfig.approved_vendors` (proto field 14) removed. Single
  source of truth is the unified `agent_boundary_allowlist` table with
  `(category="payment", subcategory="transaction")` rows.
- Allowlist match is now case-insensitive (mixed-case wallet addresses
  match lowercased extracted recipients).
- An explicit allowlist match promotes `TrustLevel::Trusted` (B-006),
  letting the policy engine bypass risk-based downscoping for admin-
  pre-approved destinations.

### AP2 + x402 protocol hardening

- **B-AP2-REPLAY** - Redis SET-NX-EX 24h on mandate id; reuse denied.
- **B-AP2-SCOPE** - mandate's `agent_id` binding must match the calling
  agent (stops stolen-mandate reuse by another agent in the same org).
- **B-AP2-REFUND** - IntentMandate must carry a `refund_policy` field.
- **B-X402-FRESH** - payload `validBefore` must be in `(now, now+5min]`
  and `validAfter ≤ now`.
- **B-X402-NONCE** - Redis SET-NX-EX 24h on payload nonce; replay denied.
- **B-X402-SIGVERIFY** - real EIP-3009 ECDSA signature verification.
  Recovers the signer from the EIP-712 typed-data hash and denies if
  it doesn't match the claimed `from`. Currently supports USDC on the
  seven canonical EVM chains (Ethereum, Base, Polygon, Arbitrum,
  Optimism, Avalanche, Base Sepolia). Non-EVM chains skip rather than
  deny.

### Operational boundaries (now backed by DB)

- Migration 038 adds `allowed_hours_timezone`, `allowed_days`,
  `auto_suspend_threshold` columns to `agent_boundaries`.
- Dashboard form gained an "Operational Boundaries" section.
- `B-002` (off-hours) and `B-003` (blocked-day) checks now read real
  per-agent values instead of the hardcoded UTC / 127 / 0.9 defaults.

### Misc

- `active_hours_start` / `active_hours_end` (`HH:MM` strings in the
  dashboard form) now correctly parse to `u32` hour for the boundary
  check. Floor on start, ceil on end so `"23:59"` maps to `24` and
  "all day" actually allows all day.
- Per-tx and per-hour denials short-circuit before scope exemption -
  scope exemption is for detection-rule labels, not for safety
  controls; this fix prevents the per-tx cap being silently overridden.

## Breaking changes

- Proto field 14 (`BoundaryConfig.approved_vendors`) is reserved.
  Any pre-v0.16.x SDK that set this field will see it ignored. Move
  payment vendor allowlists to `agent_boundary_allowlist` rows.

## Migrations to run

- Dashboard `037_drop_approved_vendors.sql` - drops the legacy column.
- Dashboard `038_boundary_missing_cols.sql` - adds the three missing
  operational-boundary columns.

Both run automatically when the dashboard-api container starts on a
clean compose `up -d`. Running on a clean DB on first install is a
no-op; on an existing DB they're additive (no data migration needed).

## Deferred to a future release

- Real AP2 ECDSA merchant-signature verification (needs merchant pubkey
  registry - not built until a real merchant integrates).
- Per-hour data-volume cap (`max_data_volume_mb_per_hour` is loaded
  from DB but no consumer yet - comparable Redis-counter follow-up).
- Per-agent `auto_suspend_threshold` consumed by ag-risk (currently
  ag-risk reads only the global config value).
