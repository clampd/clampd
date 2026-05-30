/**
 * Clampd SDK global configuration, client management, and shared utilities.
 *
 * Extracted from index.ts to keep module boundaries clean.
 */

import { ClampdClient } from "./client.js";
import { parseDsn } from "./dsn.js";
import { enroll } from "./enroll.js";
import { hostname } from "node:os";
import { basename } from "node:path";

// ── Internal helpers ─────────────────────────────────────────────

/** Recursively sort object keys for deterministic JSON serialization (matches Python json.dumps(sort_keys=True)). */
export function sortedStringify(obj: unknown): string {
  if (obj === null || obj === undefined) return JSON.stringify(obj);
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(sortedStringify).join(",")}]`;
  const sorted = Object.keys(obj as Record<string, unknown>).sort();
  return `{${sorted.map((k) => `${JSON.stringify(k)}:${sortedStringify((obj as Record<string, unknown>)[k])}`).join(",")}}`;
}

// ── Global config ─────────────────────────────────────────────────

export let defaultClient: ClampdClient | null = null;
/** Per-agent client pool -- each agent gets its own JWT signed with its own secret. */
export const agentClients = new Map<string, ClampdClient>();
/** Shared config from init() -- gateway URL, API key. */
export let sharedConfig: { gatewayUrl?: string; apiKey?: string } = {};

// ── Option interfaces ────────────────────────────────────────────

export interface InitOptions {
  /** Connection string clampd://<org_key>@<host>. Falls back to CLAMPD_DSN. */
  dsn?: string;
  /** Logical agent name (the gateway assigns the UUID at enrollment).
   * Falls back to CLAMPD_AGENT_NAME, the hostname, or the process name. */
  name?: string;
}

export interface GuardOptions {
  agentId?: string;
  toolName: string;
  /**
   * Human-readable tool description. Required for stable, contract-based
   * descriptor hashing (shared with `registerTool()` and the dashboard).
   * When omitted, the SDK falls back to `""` — the tool still works but
   * its hash won't match a pre-registered descriptor, so rug-pull
   * detection degrades to "unknown, informational only" rather than
   * matching an approved entry.
   */
  description?: string;
  /**
   * JSON-Schema describing the tool's parameters. Required (along with
   * `description`) for the hash to match a registered descriptor. When
   * omitted, defaults to `{}` — same degradation as above.
   */
  paramSchema?: object;
  /**
   * Escape hatch: supply a precomputed descriptor hash. When set, the
   * SDK bypasses `description` + `paramSchema` and uses this value
   * verbatim. Useful if the caller already called `registerTool()` and
   * cached the returned hash.
   */
  descriptorHash?: string;
  targetUrl?: string;
  failOpen?: boolean;
  checkResponse?: boolean;
}

export interface WrapOptions {
  agentId?: string;
  targetUrl?: string;
  failOpen?: boolean;
  checkResponse?: boolean;
  scanInput?: boolean;
  scanOutput?: boolean;
  /** Enable stream interception for tool calls. When true, streaming tool call
   * chunks are buffered and guarded before release. Default: true.
   * Set to false to explicitly disable (a warning will be logged). */
  guardStream?: boolean;
}

// ── Client management ────────────────────────────────────────────

/**
 * Get or create a ClampdClient for the given agentId.
 *
 * Per-agent identity: if the agentId has a registered secret (via init({ agents })
 * or env var CLAMPD_SECRET_{agentId}), a dedicated client is created with its own
 * JWT. This means kill/rate-limit/EMA operate on THIS agent, not the init() agent.
 *
 * Fallback: if no per-agent secret exists, uses the default client from init().
 */
export function getClient(opts?: { agentId?: string }): ClampdClient {
  const agentId = opts?.agentId || "";
  if (agentId && agentClients.has(agentId)) {
    return agentClients.get(agentId)!;
  }
  if (defaultClient) return defaultClient;
  throw new Error(
    "clampd.init() must be awaited before making calls. For a named agent, " +
      "enroll it first.",
  );
}

/** Logical agent name: CLAMPD_AGENT_NAME -> hostname -> process name -> "agent". */
function deriveName(): string {
  const candidate = process.env.CLAMPD_AGENT_NAME || hostname();
  if (candidate) return candidate;
  try {
    const base = basename(process.argv[1] || "").replace(/\.[^.]+$/, "");
    if (base) return base;
  } catch {
    /* ignore */
  }
  return "agent";
}

// ── clampd.init() ─────────────────────────────────────────────────

export async function init(opts: InitOptions = {}): Promise<ClampdClient> {
  const dsn = opts.dsn || process.env.CLAMPD_DSN;
  if (!dsn) {
    throw new Error(
      "No CLAMPD_DSN. Set CLAMPD_DSN=clampd://<org_key>@<host> or pass { dsn }.",
    );
  }
  const { gatewayUrl, apiKey } = parseDsn(dsn);
  const name = opts.name || deriveName();
  const identity = await enroll(gatewayUrl, apiKey, name);

  sharedConfig = { gatewayUrl, apiKey };
  defaultClient = new ClampdClient({
    agentId: identity.agentId!,
    gatewayUrl,
    apiKey,
    signingKey: identity.privateKey,
  });
  agentClients.set(identity.agentId!, defaultClient);
  return defaultClient;
}

// ── clampd._reset() — clear global state (for testing) ─────────────

/**
 * Reset all global SDK state. Intended for test isolation.
 * @internal
 */
export function _reset(): void {
  defaultClient = null;
  agentClients.clear();
  sharedConfig = {};
}
