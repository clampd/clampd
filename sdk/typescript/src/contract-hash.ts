/**
 * Canonical contract hash for a tool descriptor.
 *
 * Single source of truth: the hash is a SHA-256 over the
 * JSON-canonicalised tuple `{name, description, parameters}`. Must be
 * computed identically by:
 *
 *   - The SDK's `guard()` (when wrapping a tool call)
 *   - The SDK's `registerTool()` (when declaring a tool up-front)
 *   - dashboard-api's `/tool-descriptors/:org/register` endpoint
 *   - Any future admin tooling that writes to `tool_descriptors.descriptor_hash`
 *
 * Prior to SDK v0.13.0 the SDK used `sha256(toolName + ":" + fn.toString())`
 * and the server used `sha256(org_id + ":" + name + ":sdk")`. Neither
 * agreed with the other, so runtime rug-pull detection could not
 * distinguish "admin approved a different hash" from "caller produced a
 * different hash because `fn.toString()` happens to be different today".
 * Both routes now pass through this function so the hash is content-
 * addressed: anything that changes the external tool contract (name,
 * description, parameter schema) changes the hash; nothing else does.
 */
import { createHash } from "node:crypto";
import { sortedStringify } from "./config.js";

export interface ToolContract {
  /** Canonical tool name (e.g. "database.query"). */
  name: string;
  /** Human-readable description (shown to the LLM and in the dashboard). */
  description: string;
  /** JSON-Schema describing the tool's parameters. May be `{}` when unknown. */
  parameters: object;
}

/**
 * Compute the canonical descriptor hash for a tool contract.
 *
 * Deterministic: identical input always yields the same output. The
 * canonicalisation is key-sorted JSON with no whitespace — reordering
 * an object's fields does not change the hash.
 */
export function contractHash(contract: ToolContract): string {
  const canonical = sortedStringify({
    name: contract.name,
    description: contract.description ?? "",
    parameters: contract.parameters ?? {},
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Compute the per-call binding hash for a scope token.
 *
 * Wire-identical to `ag_common::contract_hash::call_binding` (Rust) and the
 * Python SDK's `call_binding`. Binds a scope token to the EXACT call it
 * authorized — the tool name plus the call params — so a token granted for one
 * call cannot be replayed for a different one. The tool side recomputes this
 * from the call it received and rejects the token on mismatch.
 *
 * `binding = sha256( canonical_json({ params, tool }) )` — key-sorted JSON,
 * no whitespace, raw UTF-8. `tool` is the name exactly as sent in the proxy
 * request (not re-canonicalised), so both ends agree without shared rules.
 */
export function callBinding(tool: string, params: unknown): string {
  const canonical = sortedStringify({ params: params ?? {}, tool });
  return createHash("sha256").update(canonical).digest("hex");
}
