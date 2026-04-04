/**
 * Tool-side scope token verification (Ed25519).
 *
 * Lets tool developers verify that a Clampd-approved scope token is present
 * before executing sensitive operations. The gateway mints these tokens on
 * approved proxy() calls; this module validates them on the tool side.
 *
 * Scope tokens are signed with Ed25519 (asymmetric). The public key is fetched
 * from the gateway's JWKS endpoint (GET /.well-known/jwks.json) and cached
 * locally for 1 hour. No shared secret is needed.
 *
 * @example
 * ```ts
 * import { requireScope, verifyScopeToken, getCurrentScopeToken } from "@clampd/sdk";
 *
 * // Option A: Explicit verification
 * const claims = await verifyScopeToken(getCurrentScopeToken());
 * if (!claims.scope.split(" ").includes("data:pii:query")) {
 *   throw new Error("Insufficient scope");
 * }
 *
 * // Option B: Declarative (throws if scope missing)
 * await requireScope("data:pii:query");
 * ```
 */

import { verify, createPublicKey, KeyObject } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";

// ── Claims interface ──────────────────────────────────────────────────

export interface ScopeTokenClaims {
  /** Agent ID */
  sub: string;
  /** Space-separated granted scopes */
  scope: string;
  /** Tool name */
  tool: string;
  /** SHA-256(tool + params) binding */
  binding: string;
  /** Expiry unix timestamp */
  exp: number;
  /** Request ID */
  rid: string;
}

// ── Error class ───────────────────────────────────────────────────────

export class ScopeVerificationError extends Error {
  constructor(
    public readonly reason: string,
    public readonly claims?: ScopeTokenClaims,
  ) {
    super(`Scope verification failed: ${reason}`);
    this.name = "ScopeVerificationError";
  }
}

// ── Scope token storage (AsyncLocalStorage) ───────────────────────────

const scopeTokenStore = new AsyncLocalStorage<string>();

/**
 * Run a function with a scope token set in async context.
 * Used internally by guard()/openai()/anthropic() wrappers.
 */
export function withScopeToken<T>(token: string, fn: () => T): T {
  return scopeTokenStore.run(token, fn);
}

/**
 * Set the scope token for the current async context.
 * Falls back to module-level variable when not inside AsyncLocalStorage.
 */
let _fallbackScopeToken = "";

export function setScopeToken(token: string): void {
  _fallbackScopeToken = token;
}

// ── JWKS cache ───────────────────────────────────────────────────────

interface JwksKey {
  kty: string;
  crv: string;
  use?: string;
  kid: string;
  x: string;
}

interface JwksResponse {
  keys: JwksKey[];
}

let _cachedJwks: JwksResponse | null = null;
let _jwksFetchedAt = 0;
const _JWKS_CACHE_TTL = 3600 * 1000; // 1 hour in ms

function getGatewayUrl(): string {
  return (
    process.env.CLAMPD_GATEWAY_URL ||
    process.env.AG_GATEWAY_URL ||
    "http://localhost:8080"
  );
}

/**
 * Fetch JWKS from the gateway. Results are cached for 1 hour.
 */
export async function fetchJwks(gatewayUrl?: string): Promise<JwksResponse> {
  const now = Date.now();
  if (_cachedJwks && now - _jwksFetchedAt < _JWKS_CACHE_TTL) {
    return _cachedJwks;
  }

  const base = (gatewayUrl || getGatewayUrl()).replace(/\/$/, "");
  const url = `${base}/.well-known/jwks.json`;

  const resp = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!resp.ok) {
    throw new ScopeVerificationError(
      `JWKS fetch failed: ${resp.status} ${resp.statusText}`,
    );
  }

  const jwks = (await resp.json()) as JwksResponse;
  _cachedJwks = jwks;
  _jwksFetchedAt = now;
  return jwks;
}

/**
 * Invalidate the JWKS cache so the next verification re-fetches.
 */
export function invalidateJwksCache(): void {
  _cachedJwks = null;
  _jwksFetchedAt = 0;
}

/**
 * Extract the Ed25519 public key from JWKS as a Node.js KeyObject.
 */
async function getEd25519PublicKey(
  gatewayUrl?: string,
): Promise<KeyObject> {
  const jwks = await fetchJwks(gatewayUrl);
  const key = jwks.keys.find(
    (k) => k.crv === "Ed25519" && k.kid === "scope-v1",
  );
  if (!key) {
    throw new ScopeVerificationError("No Ed25519 scope key found in JWKS");
  }

  // Convert JWK to a Node.js KeyObject
  return createPublicKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: key.x,
    },
    format: "jwk",
  });
}

// ── Token verification ────────────────────────────────────────────────

/**
 * Verify a Clampd scope token and return its claims.
 *
 * @param token - The scope token (format: base64url_payload.base64url_signature)
 * @param publicKey - Optional Ed25519 public key (Node.js KeyObject). If not provided, fetches JWKS.
 * @param gatewayUrl - Gateway URL for JWKS fetch. Falls back to env vars.
 * @throws {ScopeVerificationError} On invalid/expired/missing token.
 */
export async function verifyScopeToken(
  token: string,
  publicKey?: KeyObject,
  gatewayUrl?: string,
): Promise<ScopeTokenClaims> {
  if (!token) {
    throw new ScopeVerificationError("No scope token provided");
  }

  // Split token: base64url_payload.base64url_signature
  const parts = token.split(".");
  if (parts.length !== 2) {
    throw new ScopeVerificationError(
      `Malformed token: expected 2 parts, got ${parts.length}`,
    );
  }

  const [payloadB64, sigB64] = parts;

  // Get public key
  const pubKey = publicKey || (await getEd25519PublicKey(gatewayUrl));

  // Decode signature
  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(sigB64, "base64url");
  } catch (e) {
    throw new ScopeVerificationError(`Signature decode error: ${e}`);
  }

  // Verify Ed25519 signature
  const isValid = verify(
    null,
    Buffer.from(payloadB64),
    pubKey,
    sigBytes,
  );
  if (!isValid) {
    invalidateJwksCache();
    throw new ScopeVerificationError("Invalid signature");
  }

  // Decode payload
  let payload: Record<string, unknown>;
  try {
    const payloadStr = Buffer.from(payloadB64, "base64url").toString("utf-8");
    payload = JSON.parse(payloadStr);
  } catch (e) {
    throw new ScopeVerificationError(`Invalid payload: ${e}`);
  }

  // Extract claims
  if (typeof payload.sub !== "string" || typeof payload.exp !== "number") {
    throw new ScopeVerificationError("Missing required claim: sub or exp");
  }

  const claims: ScopeTokenClaims = {
    sub: payload.sub as string,
    scope: (payload.scope as string) ?? "",
    tool: (payload.tool as string) ?? "",
    binding: (payload.binding as string) ?? "",
    exp: payload.exp as number,
    rid: (payload.rid as string) ?? "",
  };

  // Check expiry
  if (Date.now() / 1000 > claims.exp) {
    throw new ScopeVerificationError("Token expired", claims);
  }

  return claims;
}

// ── Context helpers ───────────────────────────────────────────────────

/**
 * Read the current scope token from async context.
 *
 * Returns the token set by the guard/openai/anthropic wrappers during the
 * current tool call, or empty string if no token is available.
 */
export function getCurrentScopeToken(): string {
  return scopeTokenStore.getStore() ?? _fallbackScopeToken ?? "";
}

// ── Convenience function ──────────────────────────────────────────────

/**
 * Verify scope token and check that a specific scope is granted.
 *
 * Combines getCurrentScopeToken(), verifyScopeToken(), and scope checking.
 *
 * @param requiredScope - The scope to check (e.g. "data:pii:query").
 * @param token - Optional explicit token. If not provided, reads from context.
 * @param publicKey - Optional Ed25519 public key.
 * @param gatewayUrl - Gateway URL for JWKS fetch.
 * @throws {ScopeVerificationError} If token is invalid or scope not granted.
 */
export async function requireScope(
  requiredScope: string,
  token?: string,
  publicKey?: KeyObject,
  gatewayUrl?: string,
): Promise<ScopeTokenClaims> {
  const resolvedToken = token || getCurrentScopeToken();
  if (!resolvedToken) {
    throw new ScopeVerificationError("No scope token available in context");
  }

  const claims = await verifyScopeToken(resolvedToken, publicKey, gatewayUrl);

  const grantedScopes = claims.scope.split(" ");
  if (!grantedScopes.includes(requiredScope)) {
    throw new ScopeVerificationError(
      `Scope '${requiredScope}' not granted (have: ${claims.scope})`,
      claims,
    );
  }

  return claims;
}
