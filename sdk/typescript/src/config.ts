/**
 * Clampd SDK global configuration, client management, and shared utilities.
 *
 * Extracted from index.ts to keep module boundaries clean.
 */

import { ClampdClient } from "./client.js";

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
/** Per-agent secrets registered via init({ agents: {...} }) or env vars. */
export const agentSecrets = new Map<string, string>();
/** Shared config from init() -- gateway URL, API key. */
export let sharedConfig: { gatewayUrl?: string; apiKey?: string } = {};

// ── Option interfaces ────────────────────────────────────────────

export interface InitOptions {
  agentId: string;
  gatewayUrl?: string;
  apiKey?: string;
  secret?: string;
  /** Per-agent secrets for multi-agent setups.
   * Each agent gets its own JWT signed with its own ags_ secret.
   * Kill/rate-limit/EMA operate independently per agent.
   * @example
   * clampd.init({
   *   agentId: "orchestrator",
   *   agents: {
   *     "orchestrator": process.env.ORCHESTRATOR_SECRET,
   *     "research-agent": process.env.RESEARCHER_SECRET,
   *   }
   * });
   */
  agents?: Record<string, string | undefined>;
}

export interface GuardOptions {
  agentId?: string;
  toolName: string;
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
  schemaRegistry?: Record<string, string>;  // tool_name -> "sha256:..." hash
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
export function getClient(opts?: { agentId?: string; gatewayUrl?: string; apiKey?: string; secret?: string }): ClampdClient {
  const agentId = opts?.agentId || process.env.CLAMPD_AGENT_ID || "";

  // Check for per-agent client (already created)
  if (agentId && agentClients.has(agentId)) {
    return agentClients.get(agentId)!;
  }

  // Check for per-agent secret (create dedicated client)
  if (agentId) {
    const envKey = `CLAMPD_SECRET_${agentId.replace(/[^a-zA-Z0-9]/g, "_")}`;
    const secret = agentSecrets.get(agentId) || process.env[envKey];

    if (secret) {
      const client = new ClampdClient({
        agentId,
        gatewayUrl: opts?.gatewayUrl || sharedConfig.gatewayUrl || process.env.CLAMPD_GATEWAY_URL,
        apiKey: opts?.apiKey || sharedConfig.apiKey || process.env.CLAMPD_API_KEY,
        secret,
      });
      agentClients.set(agentId, client);
      return client;
    }
  }

  // Fallback to default client
  if (defaultClient) return defaultClient;

  if (!agentId) {
    throw new Error(
      "No agentId provided. Call clampd.init({ agentId }) first, " +
      "or pass agentId to each function, or set CLAMPD_AGENT_ID env var."
    );
  }

  return new ClampdClient({
    agentId,
    gatewayUrl: opts?.gatewayUrl || process.env.CLAMPD_GATEWAY_URL,
    apiKey: opts?.apiKey || process.env.CLAMPD_API_KEY,
    secret: opts?.secret,
  });
}

// ── clampd.init() ─────────────────────────────────────────────────

export function init(opts: InitOptions): ClampdClient {
  sharedConfig = { gatewayUrl: opts.gatewayUrl, apiKey: opts.apiKey };

  // Register per-agent secrets
  if (opts.agents) {
    for (const [id, secret] of Object.entries(opts.agents)) {
      if (secret) agentSecrets.set(id, secret);
    }
  }

  defaultClient = new ClampdClient({
    agentId: opts.agentId,
    gatewayUrl: opts.gatewayUrl,
    apiKey: opts.apiKey,
    secret: agentSecrets.get(opts.agentId) || opts.secret,
  });
  agentClients.set(opts.agentId, defaultClient);
  return defaultClient;
}

// ── clampd._reset() - clear global state (for testing) ─────────────

/**
 * Reset all global SDK state. Intended for test isolation.
 * @internal
 */
export function _reset(): void {
  defaultClient = null;
  agentClients.clear();
  agentSecrets.clear();
  sharedConfig = {};
}
