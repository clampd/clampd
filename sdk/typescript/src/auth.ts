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
