/**
 * JWT helper for Clampd agent authentication.
 *
 * Uses HMAC-SHA256 when `secret` is provided or `JWT_SECRET` env var is set.
 * Throws an error if no signing secret is available — unsigned JWTs
 * (alg: none) are NOT supported.
 */

import { createHmac, createHash } from "node:crypto";

function b64url(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
  return bytes.toString("base64url");
}

/**
 * Create a JWT with `sub` = agentId.
 *
 * @param agentId  Agent identifier (becomes the `sub` claim).
 * @param opts.secret  HMAC-SHA256 signing key. Falls back to
 *   `JWT_SECRET` env var. If unset, throws an error.
 * @param opts.scopes  Optional scopes to include in the token.
 * @param opts.ttlSeconds  Token TTL in seconds (default: 3600).
 */
export function makeAgentJwt(
  agentId: string,
  opts?: { secret?: string; scopes?: string[]; ttlSeconds?: number },
): string {
  const rawSecret = opts?.secret || process.env.JWT_SECRET || "";
  const ttl = opts?.ttlSeconds ?? 3600;
  const now = Math.floor(Date.now() / 1000);

  const payloadObj: Record<string, unknown> = {
    sub: agentId,
    iss: "clampd-sdk",
    iat: now,
    exp: now + ttl,
  };
  if (opts?.scopes?.length) {
    payloadObj.scopes = opts.scopes;
  }

  if (rawSecret) {
    // Derive signing key: if agent secret (ags_ prefix), hash with SHA-256
    // so the HMAC key matches the credential_hash stored server-side.
    // Otherwise use as-is (legacy global JWT_SECRET).
    const signingKey = rawSecret.startsWith("ags_")
      ? createHash("sha256").update(rawSecret).digest("hex")
      : rawSecret;

    const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payload = b64url(JSON.stringify(payloadObj));
    const signingInput = `${header}.${payload}`;
    const sig = createHmac("sha256", signingKey).update(signingInput).digest();
    const signature = Buffer.from(sig).toString("base64url");
    return `${header}.${payload}.${signature}`;
  }

  // Fail-closed: unsigned JWTs are not supported
  throw new Error(
    "[clampd] No signing secret available. " +
    "Set JWT_SECRET env var or pass { secret } to makeAgentJwt(). " +
    "Unsigned JWTs (alg: none) are not supported."
  );
}

/**
 * SHA-256 of lowercased agent IDs joined by ','. Mirrors
 * `ag-gateway::delegation::chain_hash` and
 * `sdk/python/clampd/auth.py::_delegation_chain_hash`. Bound to a
 * specific ancestry so a proof minted for [A, B, C] can't be replayed
 * for [A, B, X].
 */
export function delegationChainHash(chain: string[]): string {
  const joined = chain.map((a) => a.toLowerCase()).join(",");
  return createHash("sha256").update(joined).digest("hex");
}

/**
 * Mint a signed delegation proof for one cross-agent hop.
 *
 * The leaf agent (executor) signs a short-lived JWT binding (leaf,
 * chain) under its own credential hash. The gateway looks up the same
 * hash in `ag:agent:cred:{leaf}` and verifies. Identical bytes to the
 * Python SDK's `make_delegation_proof` — covered by parity test in
 * `delegation::tests::chain_hash_is_lowercased_comma_joined_sha256`.
 *
 * @param leafAgentId  Executor of the call (becomes `sub`).
 * @param chain        Full delegation chain including the leaf.
 * @param opts.secret  Raw `ags_` agent secret; hashed before signing.
 * @param opts.ttlSeconds  Proof TTL (default 30s).
 */
export function makeDelegationProof(
  leafAgentId: string,
  chain: string[],
  opts: { secret: string; ttlSeconds?: number },
): string {
  const rawSecret = opts.secret;
  if (!rawSecret) {
    throw new Error("makeDelegationProof requires the leaf agent's ags_ secret");
  }
  const signingKey = rawSecret.startsWith("ags_")
    ? createHash("sha256").update(rawSecret).digest("hex")
    : rawSecret;

  const now = Math.floor(Date.now() / 1000);
  const ttl = opts.ttlSeconds ?? 30;
  const payloadObj = {
    sub: leafAgentId,
    iss: "clampd-sdk",
    aud: "ag-gateway",
    iat: now,
    exp: now + ttl,
    chain_hash: delegationChainHash(chain),
  };
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify(payloadObj));
  const signingInput = `${header}.${payload}`;
  const sig = createHmac("sha256", signingKey).update(signingInput).digest();
  const signature = Buffer.from(sig).toString("base64url");
  return `${header}.${payload}.${signature}`;
}
