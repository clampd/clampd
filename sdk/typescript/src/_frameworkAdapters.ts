/**
 * Framework tool-object adapters and the unregistered-tool detector.
 *
 * Mirrors `clampd._framework_adapters` in the Python SDK. Two
 * unrelated-but-thin concerns live here so we don't multiply tiny
 * helper modules:
 *
 *   1. {@link extractToolDescriptor} — duck-type a LangChain
 *      `BaseTool` / OpenAI tool def / Anthropic tool def into a
 *      plain `{ name, description, paramSchema }` triple. Used by
 *      the `registerTool(toolObject, opts)` overload so callers can
 *      pass their existing framework tool object instead of
 *      restating its name / description / schema.
 *
 *   2. {@link raiseIfUnregistered} — convert the gateway's
 *      `denial_reason` strings starting with `tool_not_registered:`
 *      or `tool_not_classified:` into a typed
 *      {@link ClampdUnregisteredToolError}. Centralised here so
 *      every wrapper that calls `client.proxy()` can short-circuit
 *      with the same exception, ahead of throwing the more general
 *      {@link ClampdBlockedError}.
 *
 * Pure TypeScript — no framework imports. Every shape check is duck
 * typing so loading the SDK does not require LangChain / OpenAI /
 * Anthropic SDKs to be installed.
 */

import type { ProxyResponse } from "./client.js";
import {
  ClampdDescriptorMismatchError,
  ClampdUnregisteredToolError,
} from "./errors.js";

// ── Tool-object descriptor extraction ───────────────────────────────

/**
 * Plain triple extracted from an arbitrary framework tool object.
 *
 * `paramSchema` is whatever the framework gave us (zod schema, JSON
 * Schema, ad-hoc dict). Downstream code that hashes it (`contractHash`)
 * tolerates anything serialisable; LangChain `zod` schemas are passed
 * through `_zodToJsonSchema` first so the hash stays stable across
 * runs.
 */
export interface ExtractedDescriptor {
  name: string;
  description: string;
  paramSchema: object;
}

import { createRequire } from "node:module";

const _moduleRequire = createRequire(import.meta.url);

/**
 * Best-effort conversion of a zod schema to a JSON Schema dict.
 *
 * zod 4 ships `z.toJSONSchema()`; we resolve it lazily because the SDK
 * lists zod as an optional peer dep. Returns `{}` if anything fails so
 * the caller still gets a stable (if less informative) descriptor.
 *
 * Sync resolution via `createRequire` is deliberate: `extractToolDescriptor`
 * runs inside `registerTool()` which is already async, but the rest of the
 * SDK (notably the LangChain callback fast-path) treats descriptor
 * extraction as a synchronous step. Dynamic `import()` would force every
 * caller to await, which would ripple through the whole adapter surface
 * for no real benefit — `node:module.createRequire` gives us the same
 * lazy-load semantics with a sync return.
 */
function zodToJsonSchema(schema: unknown): object {
  if (!schema || typeof schema !== "object") return {};
  // Heuristic: zod schemas have `_def` and `parse`.
  const maybeZod = schema as { _def?: unknown; parse?: unknown };
  if (!maybeZod._def || typeof maybeZod.parse !== "function") return {};
  try {
    const zodMod = _moduleRequire("zod") as {
      z?: { toJSONSchema?: (s: unknown) => unknown };
    };
    const z = zodMod.z;
    if (z?.toJSONSchema) {
      const out = z.toJSONSchema(schema);
      if (out && typeof out === "object") return out as object;
    }
  } catch {
    // Either zod isn't installed or it's an older version without
    // toJSONSchema — fall through to {}.
  }
  return {};
}

/**
 * Detect and extract `{ name, description, paramSchema }` from a
 * LangChain `BaseTool`, OpenAI tool def, Anthropic tool def, or
 * Vercel AI SDK tool def.
 *
 * Returns `null` when the value doesn't look like any known tool
 * shape — caller should fall through to the `(name, opts)` overload
 * or raise.
 *
 * Detection rules (duck typing — order matters, most specific first):
 *
 *   - OpenAI tool def: `{ type: 'function', function: { name, ... } }`
 *   - Anthropic tool def: `{ name, input_schema }` (no `function` key)
 *   - LangChain BaseTool: has `.name` plus either `.schema` (zod) or
 *     `.args_schema` (legacy)
 *   - Vercel AI SDK: has `.parameters` plus `.execute`/`.description`
 *     (handled via the LangChain branch since `.name` is keyed
 *     externally for Vercel; if `.name` is missing, returns `null`)
 */
export function extractToolDescriptor(value: unknown): ExtractedDescriptor | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;

  // OpenAI: { type: 'function', function: { name, description, parameters } }
  if (v.type === "function" && v.function && typeof v.function === "object") {
    const fn = v.function as Record<string, unknown>;
    if (typeof fn.name === "string") {
      return {
        name: fn.name,
        description: typeof fn.description === "string" ? fn.description : "",
        paramSchema: (fn.parameters as object | undefined) ?? {},
      };
    }
  }

  // Anthropic: { name, description, input_schema }
  if (typeof v.name === "string" && v.input_schema && typeof v.input_schema === "object") {
    return {
      name: v.name,
      description: typeof v.description === "string" ? v.description : "",
      paramSchema: v.input_schema as object,
    };
  }

  // LangChain BaseTool: .name + (.schema (zod) | .args_schema (legacy))
  if (typeof v.name === "string" && (v.schema !== undefined || v.args_schema !== undefined)) {
    const schema = v.schema ?? v.args_schema;
    let paramSchema: object;
    if (schema && typeof schema === "object") {
      // zod schema?
      const maybeZod = schema as { _def?: unknown; parse?: unknown };
      if (maybeZod._def && typeof maybeZod.parse === "function") {
        paramSchema = zodToJsonSchema(schema);
      } else {
        paramSchema = schema as object;
      }
    } else {
      paramSchema = {};
    }
    return {
      name: v.name,
      description: typeof v.description === "string" ? v.description : "",
      paramSchema,
    };
  }

  return null;
}

// ── Descriptor-error detection ──────────────────────────────────────

/** Regex matching the `with hash <hex>` fragment the gateway embeds in
 * `descriptor_hash_mismatch:` denial reasons. */
const DESCRIPTOR_HASH_RE = /with hash ([0-9a-fA-F]+)/;

/**
 * Inspect a {@link ProxyResponse} and throw a typed exception if the
 * gateway denied the call for a descriptor-related reason.
 *
 * Three prefixes on `denial_reason` are handled:
 *
 *   - `tool_not_registered:<name>` → {@link ClampdUnregisteredToolError}
 *     (descriptor missing entirely)
 *   - `tool_not_classified:<name>` → {@link ClampdUnregisteredToolError}
 *     (descriptor exists but rejected classification at registration time)
 *   - `descriptor_hash_mismatch:<...>` → {@link ClampdDescriptorMismatchError}
 *     (descriptor exists but the hash sent doesn't match any approved
 *     version — rug-pull-detection signal)
 *
 * For `descriptor_hash_mismatch`, the attempted hash is parsed from the
 * reason text (`"with hash <hex>"`) and attached to the error.
 *
 * No-op for any other denial reason — the caller is expected to throw
 * its own {@link ClampdBlockedError} downstream.
 *
 * Mirrors the prefix scheme used by the Python SDK's
 * `_raise_for_descriptor_errors`.
 */
export function raiseForDescriptorErrors(
  toolName: string,
  resp: ProxyResponse | undefined,
): void {
  if (!resp || resp.allowed) return;
  const reason = resp.denial_reason;
  if (typeof reason !== "string") return;
  if (
    reason.startsWith("tool_not_registered:") ||
    reason.startsWith("tool_not_classified:")
  ) {
    throw new ClampdUnregisteredToolError(toolName);
  }
  if (reason.startsWith("descriptor_hash_mismatch:")) {
    const match = DESCRIPTOR_HASH_RE.exec(reason);
    const attemptedHash = match ? match[1] : undefined;
    throw new ClampdDescriptorMismatchError(toolName, { attemptedHash });
  }
}

/**
 * Backward-compat alias for {@link raiseForDescriptorErrors}.
 *
 * Originally only handled `tool_not_registered:` / `tool_not_classified:`
 * prefixes. It now also throws {@link ClampdDescriptorMismatchError}
 * on `descriptor_hash_mismatch:` — kept under the old name so existing
 * call sites (interceptor, langchain, stream-guard, guardrails) keep
 * working without a rename touching every wrapper.
 */
export function raiseIfUnregistered(
  toolName: string,
  resp: ProxyResponse | undefined,
): void {
  raiseForDescriptorErrors(toolName, resp);
}

// ── Process-local descriptor cache ──────────────────────────────────

/**
 * Maps `toolName -> contractHash` for every successful
 * `registerTool()` call in this process. The OpenAI / Anthropic /
 * LangChain wrappers prefer this cached hash over computing one on
 * the fly — that way the hash sent to the gateway exactly matches
 * the hash that was registered, even when the wrapper has incomplete
 * information about the tool's parameter schema (e.g. LangChain
 * callbacks don't surface the pydantic schema through `serialized`).
 *
 * Mirrors `clampd._framework_adapters._registered_descriptors` in the
 * Python SDK.
 */
export const _registeredDescriptors: Map<string, string> = new Map();
