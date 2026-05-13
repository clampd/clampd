/**
 * `clampd.registerTool()` — explicit tool registration at import time.
 *
 * Problem this solves: the existing SDK discovers tools lazily via
 * guardrail wrappers, which means the backend sees a tool for the first
 * time when it's already in flight. That puts the tool in the default-deny
 * "unclassified" bucket until a dashboard operator approves it.
 *
 * `registerTool` flips the flow: the tool author classifies at import
 * time, the SDK POSTs the already-classified descriptor to the backend,
 * and the tool skips the dashboard approval queue entirely.
 *
 * API shape choice: the `classification` field is a single
 * `ToolClassification` discriminated-union object rather than three
 * independent string params. This lets the tsc compiler narrow the valid
 * `operation` values based on the (`category`, `subcategory`) pair the
 * caller selects — e.g. after writing `category: "db", subcategory:
 * "query"`, the only valid `operation` is `"read"`. That compile-time
 * narrowing is the whole point of the feature and would be lost if we
 * took three separate strings.
 *
 * Three call shapes are accepted (overloads):
 *
 *   1. `registerTool({ name, classification, ... })` — original options-bag
 *      form. Kept for backward compatibility with v0.15 callers.
 *   2. `registerTool(name, { category, subcategory, operation, ... })` —
 *      positional form, mirrors Python's `register_tool(name, *, ...)`.
 *   3. `registerTool(toolObject, { category, subcategory, operation })` —
 *      pass a LangChain `BaseTool`, OpenAI tool def, or Anthropic tool
 *      def directly. The SDK extracts name / description / paramSchema
 *      via duck typing in `_frameworkAdapters.extractToolDescriptor`.
 *
 * Forms 2 and 3 disallow passing both a tool object AND a `description`
 * / `paramSchema` override — the tool object is the source of truth,
 * mixing the two is almost always a mistake.
 */

import {
  computeScope,
  validateClassification,
  type ToolClassification,
} from "./taxonomy.js";
import { ClampdClassificationError } from "./errors.js";
import { sharedConfig } from "./config.js";
import { contractHash } from "./contract-hash.js";
import {
  extractToolDescriptor,
  _registeredDescriptors,
} from "./_frameworkAdapters.js";

// ── Options ─────────────────────────────────────────────────────────

/**
 * Options bag accepted by the original (v0.15) `registerTool(opts)`
 * call shape. Still exported for callers that use the bag form.
 */
export interface RegisterToolOptions {
  /** Tool name as it will appear in proxy requests (e.g. "db.query"). */
  name: string;
  /**
   * Pre-classified (category, subcategory, operation) triple. Using the
   * discriminated union here means mis-classification is a compile-time
   * error — `{ category: "comms", subcategory: "shell" }` will not
   * typecheck.
   */
  classification: ToolClassification;
  /** Optional human description surfaced in the dashboard. */
  description?: string;
  /**
   * JSON-Schema describing the tool's parameters. Participates in the
   * canonical contract hash, so it must match the schema supplied to
   * `guard()` for runtime rug-pull detection to be clean.
   */
  paramSchema?: object;
  /** API key for gateway auth. Falls back to `CLAMPD_API_KEY`. */
  apiKey?: string;
}

/**
 * Common backend-routing fields shared by the new overload shapes.
 * Mirrors the routing fields on {@link RegisterToolOptions} so the
 * three forms accept the same env-fallback semantics.
 *
 * Since v0.16 the SDK only contacts the gateway. The gateway resolves
 * the org from the `X-AG-Key` header — no `orgId` or `dashboardUrl`
 * needed.
 */
interface RegisterToolRouting {
  apiKey?: string;
}

/**
 * Classification triple plus optional description / paramSchema /
 * routing fields, accepted by the `registerTool(name, opts)` overload.
 *
 * Defined as `ToolClassification & {...}` so the discriminated union's
 * narrowing still applies — the compiler still rejects e.g.
 * `{ category: "db", subcategory: "query", operation: "write" }` at
 * the call site.
 */
export type RegisterToolClassificationOptions = ToolClassification &
  RegisterToolRouting & {
    description?: string;
    paramSchema?: object;
  };

/**
 * Same as {@link RegisterToolClassificationOptions} but without
 * `description` / `paramSchema` — the framework tool object passed as
 * the first arg is the source of truth for those, so accepting them
 * here too would just create ambiguity.
 */
export type RegisterToolClassificationOnly = ToolClassification &
  RegisterToolRouting;

// ── Implementation ──────────────────────────────────────────────────

/**
 * Register a classified tool descriptor with the Clampd backend.
 *
 * Behaviour:
 *   1. Runtime-validates the classification even though the type system
 *      already enforces it — callers who bypass `ToolClassification` via
 *      `as any` will get a `ClampdClassificationError`.
 *   2. POSTs `{ name, category, subcategory, operation, description,
 *      param_schema }` to `/v1/register` on the gateway. The gateway
 *      resolves the org from the `X-AG-Key` header, validates the
 *      taxonomy triple, publishes a ShadowEvent that ag-control mirrors
 *      to the `tool_descriptors` table.
 *   3. Records the resulting `(toolName, descriptorHash)` pair in a
 *      process-local map so framework callbacks can look up the
 *      authoritative hash later, instead of recomputing one from
 *      partial information.
 *   4. Never throws on network failure — logs a warning and returns.
 *      App startup must not be blocked by a gateway outage; tools will
 *      still be auto-captured on first runtime call.
 */
export async function registerTool(opts: RegisterToolOptions): Promise<void>;
export async function registerTool(
  name: string,
  opts: RegisterToolClassificationOptions,
): Promise<void>;
export async function registerTool(
  tool: object,
  opts: RegisterToolClassificationOnly,
): Promise<void>;
export async function registerTool(
  arg1: RegisterToolOptions | string | object,
  arg2?: RegisterToolClassificationOptions | RegisterToolClassificationOnly,
): Promise<void> {
  // Normalise the three call shapes into a single internal options bag.
  const opts = _normalizeArgs(arg1, arg2);

  const { name, classification, description } = opts;

  // Runtime validation — belt and suspenders for callers that bypass
  // the discriminated union via `as any` or dynamic values.
  if (
    !validateClassification(
      classification.category,
      classification.subcategory,
      classification.operation,
    )
  ) {
    throw new ClampdClassificationError(
      classification.category,
      classification.subcategory,
      classification.operation,
    );
  }

  // Compute the contract hash client-side first so we can record it in
  // `_registeredDescriptors` even when we skip the network call (e.g.
  // missing orgId in dev). The framework wrappers consult this map to
  // forward the canonical hash to the gateway, which is what makes
  // descriptor-hash checks survive without round-tripping through the
  // dashboard.
  const paramSchema = opts.paramSchema ?? {};
  const descriptorHash = contractHash({
    name,
    description: description ?? "",
    parameters: paramSchema,
  });
  _registeredDescriptors.set(name, descriptorHash);

  // ── POST to gateway /v1/register ─────────────────────────────────────
  //
  // The SDK only ever talks to the gateway. The gateway publishes a
  // ShadowEvent that ag-control consumes and upserts into Postgres; the
  // dashboard reads that table for display. CLAMPD_DASHBOARD_URL /
  // CLAMPD_ORG_ID are no longer used by registerTool — the gateway
  // resolves the org from the X-AG-Key.
  const apiKey = opts.apiKey ?? process.env.CLAMPD_API_KEY ?? "";
  if (!apiKey) {
    console.warn(
      "[clampd] registerTool: no apiKey provided (and CLAMPD_API_KEY is unset); skipping backend registration.",
    );
    return;
  }

  const gatewayUrl = (
    sharedConfig.gatewayUrl ??
    process.env.CLAMPD_GATEWAY_URL ??
    "http://localhost:8080"
  ).replace(/\/$/, "");

  const body = {
    name,
    category: classification.category,
    subcategory: classification.subcategory,
    operation: classification.operation,
    description,
    param_schema: paramSchema,
  };

  const url = `${gatewayUrl}/v1/register`;

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-AG-Key": apiKey,
      },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => `HTTP ${resp.status}`);
      console.warn(
        `[clampd] registerTool: gateway returned ${resp.status} for ${name}: ${text}`,
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(
      `[clampd] registerTool: failed to reach gateway for ${name}: ${msg}`,
    );
  }
}

// ── Internal: argument normalisation ────────────────────────────────

/**
 * Detect which of the three overload shapes the caller used and return
 * a single canonical {@link RegisterToolOptions}. Throws `TypeError`
 * for invalid combinations (notably: passing a tool object alongside a
 * `description`/`paramSchema` override).
 */
function _normalizeArgs(
  arg1: RegisterToolOptions | string | object,
  arg2?: RegisterToolClassificationOptions | RegisterToolClassificationOnly,
): RegisterToolOptions {
  // Form 1: registerTool({ name, classification, ... })
  if (
    arg2 === undefined &&
    typeof arg1 === "object" &&
    arg1 !== null &&
    "name" in arg1 &&
    "classification" in arg1
  ) {
    return arg1 as RegisterToolOptions;
  }

  if (arg2 === undefined) {
    throw new TypeError(
      "registerTool: expected either registerTool(opts), registerTool(name, opts), or registerTool(toolObject, opts).",
    );
  }

  const classification: ToolClassification = {
    category: arg2.category,
    subcategory: arg2.subcategory,
    operation: arg2.operation,
  } as ToolClassification;

  const routing: RegisterToolRouting = {
    apiKey: arg2.apiKey,
  };

  // Form 2: registerTool(name, opts)
  if (typeof arg1 === "string") {
    const o = arg2 as RegisterToolClassificationOptions;
    return {
      name: arg1,
      classification,
      description: o.description,
      paramSchema: o.paramSchema,
      ...routing,
    };
  }

  // Form 3: registerTool(toolObject, opts)
  if (typeof arg1 === "object" && arg1 !== null) {
    const o = arg2 as RegisterToolClassificationOptions;
    if (o.description !== undefined || o.paramSchema !== undefined) {
      throw new TypeError(
        "registerTool: pass description/paramSchema OR a tool object, not both. " +
          "The tool object's own metadata is the source of truth — drop the override " +
          "or call registerTool(name, opts) instead.",
      );
    }
    const extracted = extractToolDescriptor(arg1);
    if (!extracted) {
      throw new TypeError(
        "registerTool: first argument is not a recognised tool object. " +
          "Expected a LangChain BaseTool ({ name, schema/args_schema }), " +
          "an OpenAI tool def ({ type: 'function', function: { name, ... } }), " +
          "or an Anthropic tool def ({ name, input_schema }).",
      );
    }
    return {
      name: extracted.name,
      classification,
      description: extracted.description,
      paramSchema: extracted.paramSchema,
      ...routing,
    };
  }

  throw new TypeError(
    "registerTool: first argument must be an options object, a tool name string, or a framework tool object.",
  );
}
