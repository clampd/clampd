/**
 * Per-agent Ed25519 identity and gateway enrollment (mirrors clampd/enroll.py).
 *
 * The private key is generated on first run, persisted under CLAMPD_HOME
 * (default ~/.clampd), and never leaves the process. The gateway stores only
 * the public key as the agent credential and assigns the agent UUID, cached
 * alongside the key so later runs reuse the same identity.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const HOME = process.env.CLAMPD_HOME
  ? process.env.CLAMPD_HOME.replace(/^~(?=$|\/)/, homedir())
  : join(homedir(), ".clampd");

export interface Identity {
  privateKey: KeyObject;
  agentId: string | null;
}

function slot(orgKey: string, name: string): string {
  const org = createHash("sha256").update(orgKey).digest("hex").slice(0, 16);
  return join(HOME, "agents", org, `${name.replace(/\//g, "_")}.json`);
}

/** base64url raw 32-byte Ed25519 public key (matches the Python SDK). */
export function publicKeyB64(privateKey: KeyObject): string {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x?: string };
  return jwk.x ?? "";
}

function save(path: string, privateKey: KeyObject, agentId: string | null): void {
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify({ private_pem: pem, agent_id: agentId }), { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best effort */
  }
}

function loadOrCreate(orgKey: string, name: string): Identity {
  const path = slot(orgKey, name);
  if (existsSync(path)) {
    const data = JSON.parse(readFileSync(path, "utf8"));
    return { privateKey: createPrivateKey(data.private_pem), agentId: data.agent_id ?? null };
  }
  return generate(orgKey, name);
}

function gatherAttestation(): [string, string] {
  // A re-key token takes precedence: it re-binds a new keypair to an existing
  // agent (used after losing the local key). Minted in the dashboard.
  if (process.env.CLAMPD_REBIND_TOKEN) {
    return ["rekey_token", process.env.CLAMPD_REBIND_TOKEN];
  }
  // An explicit, admin-minted enroll token (org-wide) is the next choice.
  if (process.env.CLAMPD_ENROLL_TOKEN) {
    return ["enroll_token", process.env.CLAMPD_ENROLL_TOKEN];
  }
  // Workload OIDC attestation: a verified, STABLE per-workload identity
  // (k8s ServiceAccount / OIDC `sub`). The gateway verifies the projected
  // token against the org's trusted issuers and derives the agent's stable
  // attestation id from `sub` — enabling idempotent auto-recovery across pod
  // restarts and token rotation. Preferred when available.
  const token = workloadToken();
  if (token) {
    return ["oidc", token];
  }
  return ["none", ""];
}

/**
 * Locate a workload OIDC/k8s ServiceAccount token for attestation.
 *
 * Order: explicit raw token, explicit file, the recommended clampd-audience
 * projected token, then the default k8s ServiceAccount token as a fallback.
 * Returns "" when none is present (caller falls back to `none`).
 */
function workloadToken(): string {
  if (process.env.CLAMPD_WORKLOAD_TOKEN) {
    return process.env.CLAMPD_WORKLOAD_TOKEN.trim();
  }
  const candidates: string[] = [];
  if (process.env.CLAMPD_WORKLOAD_TOKEN_FILE) {
    candidates.push(process.env.CLAMPD_WORKLOAD_TOKEN_FILE);
  }
  candidates.push("/var/run/secrets/clampd.io/token");
  candidates.push("/var/run/secrets/kubernetes.io/serviceaccount/token");
  for (const path of candidates) {
    try {
      if (existsSync(path)) {
        const token = readFileSync(path, "utf8").trim();
        if (token) return token;
      }
    } catch {
      continue;
    }
  }
  return "";
}

/** Generate a fresh keypair, persist it (agentId unset), return the Identity. */
function generate(orgKey: string, name: string): Identity {
  const { privateKey } = generateKeyPairSync("ed25519");
  save(slot(orgKey, name), privateKey, null);
  return { privateKey, agentId: null };
}

/**
 * Return an enrolled Identity, enrolling with the gateway if needed.
 *
 * When `CLAMPD_REBIND_TOKEN` is set, a re-key is forced even if a cached
 * identity exists: a fresh keypair is generated and bound to the existing
 * agent (same UUID), then persisted locally.
 */
export async function enroll(host: string, orgKey: string, name: string): Promise<Identity> {
  const rebinding = Boolean(process.env.CLAMPD_REBIND_TOKEN);
  const ident = rebinding ? generate(orgKey, name) : loadOrCreate(orgKey, name);
  if (!rebinding && ident.agentId) return ident;

  const [attType, att] = gatherAttestation();
  let resp: Response;
  try {
    resp = await fetch(`${host}/v1/enroll`, {
      method: "POST",
      headers: { "X-AG-Key": orgKey, "Content-Type": "application/json" },
      body: JSON.stringify({
        public_key: publicKeyB64(ident.privateKey),
        attestation_type: attType,
        attestation: att,
        name,
      }),
    });
  } catch (e) {
    throw new Error(`[clampd] enrollment request failed: ${e}`);
  }
  if (resp.status !== 200 && resp.status !== 201) {
    throw new Error(`[clampd] enrollment rejected: ${resp.status} ${await resp.text()}`);
  }
  const body = (await resp.json()) as { agent_id?: string };
  if (!body.agent_id) {
    throw new Error("[clampd] enrollment response missing agent_id");
  }
  save(slot(orgKey, name), ident.privateKey, body.agent_id);
  ident.agentId = body.agent_id;
  return ident;
}
