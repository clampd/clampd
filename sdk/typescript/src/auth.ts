/**
 * Agent JWT signing (EdDSA) for Clampd.
 *
 * The agent signs JWTs with its enrolled Ed25519 private key; the gateway
 * verifies against the registered public key. No shared secret.
 */

import { createHash, sign as edSign, type KeyObject } from "node:crypto";

function b64url(data: Uint8Array | string): string {
  return Buffer.from(data).toString("base64url");
}

/** Create an EdDSA-signed JWT with `sub` = agentId. */
export function makeAgentJwtEd25519(
  agentId: string,
  privateKey: KeyObject,
  opts?: { scopes?: string[]; ttlSeconds?: number },
): string {
  const now = Math.floor(Date.now() / 1000);
  const ttl = opts?.ttlSeconds ?? 3600;
  const payloadObj: Record<string, unknown> = {
    sub: agentId,
    iss: "clampd-sdk",
    aud: "ag-gateway",
    iat: now,
    exp: now + ttl,
  };
  if (opts?.scopes?.length) {
    payloadObj.scopes = opts.scopes;
  }
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
  const payload = b64url(JSON.stringify(payloadObj));
  const signingInput = `${header}.${payload}`;
  const sig = edSign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${sig.toString("base64url")}`;
}

/**
 * SHA-256 of lowercased agent IDs joined by ','. Mirrors
 * `ag-gateway::delegation::chain_hash` and the Python SDK. Bound to a specific
 * ancestry so a proof minted for [A, B, C] can't be replayed for [A, B, X].
 */
export function delegationChainHash(chain: string[]): string {
  const joined = chain.map((a) => a.toLowerCase()).join(",");
  return createHash("sha256").update(joined).digest("hex");
}

/**
 * Mint an EdDSA-signed delegation proof for one cross-agent hop. The leaf agent
 * signs (leaf, chain_hash) with its Ed25519 private key; the gateway verifies
 * against the agent's public key in `ag:agent:cred:{leaf}`.
 */
export function makeDelegationProofEd25519(
  leafAgentId: string,
  chain: string[],
  privateKey: KeyObject,
  opts?: { ttlSeconds?: number },
): string {
  const now = Math.floor(Date.now() / 1000);
  const ttl = opts?.ttlSeconds ?? 30;
  const payloadObj = {
    sub: leafAgentId,
    iss: "clampd-sdk",
    aud: "ag-gateway",
    iat: now,
    exp: now + ttl,
    chain_hash: delegationChainHash(chain),
  };
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
  const payload = b64url(JSON.stringify(payloadObj));
  const signingInput = `${header}.${payload}`;
  const sig = edSign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${sig.toString("base64url")}`;
}
