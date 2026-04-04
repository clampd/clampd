/**
 * Automatic delegation chain tracking via AsyncLocalStorage.
 * Propagates through async/await, Promises, and callbacks automatically.
 *
 * When Agent A's guarded tool calls Agent B's guarded tool in the same
 * process, the SDK auto-detects the cross-agent hop and includes
 * delegation metadata in proxy requests.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

export interface DelegationContext {
  traceId: string;
  chain: string[];
  confidence: "verified" | "inferred" | "declared";
}

const delegationStore = new AsyncLocalStorage<DelegationContext>();

export const MAX_DELEGATION_DEPTH = 5;

/**
 * Get the current delegation context, if any.
 */
export function getDelegation(): DelegationContext | undefined {
  return delegationStore.getStore();
}

/**
 * Get the caller (parent) agent ID from the delegation chain.
 * Returns undefined if there is no parent (single agent or no context).
 */
export function getCallerAgentId(): string | undefined {
  const ctx = delegationStore.getStore();
  if (!ctx || ctx.chain.length < 2) return undefined;
  return ctx.chain[ctx.chain.length - 2];
}

/**
 * Check whether a chain contains a cycle (duplicate agent ID).
 */
export function hasCycle(chain: string[]): boolean {
  return new Set(chain).size !== chain.length;
}

/**
 * Run a function within a delegation context.
 * If already inside a delegation, extends the chain.
 * If not, starts a new chain.
 */
export function withDelegation<T>(agentId: string, fn: () => T): T {
  const parent = delegationStore.getStore();

  let ctx: DelegationContext;
  if (parent) {
    ctx = {
      traceId: parent.traceId,
      chain: [...parent.chain, agentId],
      confidence: parent.confidence,
    };
  } else {
    ctx = {
      traceId: randomUUID().replace(/-/g, "").slice(0, 16),
      chain: [agentId],
      confidence: "verified",
    };
  }

  if (ctx.chain.length > MAX_DELEGATION_DEPTH) {
    throw new Error(
      `Delegation depth ${ctx.chain.length} exceeds maximum ${MAX_DELEGATION_DEPTH}. ` +
        `Chain: ${ctx.chain.join(" \u2192 ")}`,
    );
  }

  if (hasCycle(ctx.chain)) {
    throw new Error(
      `Circular delegation detected: ${ctx.chain.join(" \u2192 ")}`,
    );
  }

  return delegationStore.run(ctx, fn);
}

/**
 * Get delegation headers for cross-service HTTP propagation.
 * Returns an empty object when called outside a delegation context.
 */
export function delegationHeaders(): Record<string, string> {
  const ctx = delegationStore.getStore();
  if (!ctx || ctx.chain.length < 2) return {};
  return {
    "X-Clampd-Delegation-Trace": ctx.traceId,
    "X-Clampd-Delegation-Chain": ctx.chain.join(","),
    "X-Clampd-Delegation-Confidence": ctx.confidence,
  };
}
