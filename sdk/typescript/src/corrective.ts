/**
 * Structured denial + corrective-action types for the Clampd SDK.
 *
 * Mirrors the v0.20 gateway JSON wire shape (`denial: StructuredDenial`).
 * The gateway emits this on every Deny/Downscope response; the SDK parses
 * it into typed objects so callers can pattern-match on the corrective
 * variant instead of parsing a free-text string.
 *
 * LLM-facing rendering lives in `renderCorrectiveForLLM` — same template
 * set as the Python SDK so error messages are identical across languages.
 *
 * Wire field names are **snake_case** (Rust serde default). Internal TS
 * shapes use camelCase; parsers translate at the boundary.
 */

// ── Confidence + Source ─────────────────────────────────────────────

export type Confidence = "high" | "medium" | "low";

export type Source =
  | "rule"
  | "rule_dynamic"
  | "scope"
  | "boundary"
  | "cedar"
  | "sdk_override"
  | "bundle"
  | "gateway";

// ── Corrective action variants ──────────────────────────────────────

export interface SwitchTool {
  kind: "switchTool";
  tool: string;
  scope?: string;
}
export interface DownscopeTo {
  kind: "downscopeTo";
  scope: string;
}
export interface RenameField {
  kind: "renameField";
  from: string;
  to: string;
}
export interface RedactValue {
  kind: "redactValue";
  jsonPath: string;
  mask: string;
}
export interface SplitRequest {
  kind: "splitRequest";
  maxItemsPerBatch: number;
  currentItems: number;
}
export interface WaitAndRetry {
  kind: "waitAndRetry";
  retryAfterSeconds: number;
  windowLabel?: string;
}
export interface SwitchEndpoint {
  kind: "switchEndpoint";
  fromUrl: string;
  toUrl: string;
}
export interface NoCorrection {
  kind: "noCorrection";
}

export type CorrectiveActionVariant =
  | SwitchTool
  | DownscopeTo
  | RenameField
  | RedactValue
  | SplitRequest
  | WaitAndRetry
  | SwitchEndpoint
  | NoCorrection;

/** v0.23.1+: gateway-pre-rendered strings, so every consumer reads
 *  identical text without each maintaining its own template library. */
export interface RenderedCorrective {
  toolResult: string;
  shortLabel: string;
}

export interface CorrectiveAction {
  action: CorrectiveActionVariant;
  humanExplanation: string;
  confidence: Confidence;
  source: Source;
  /** Populated by gateway 0.23.1+. `null` when talking to an older
   *  gateway — callers should fall back to `renderCorrectiveForLLM`
   *  which mirrors the server templates. */
  rendered: RenderedCorrective | null;
}

// ── StructuredDenial ────────────────────────────────────────────────

export interface StructuredDenial {
  ruleId: string;
  violatedPredicate: string;
  offendingValue: string;
  corrective: CorrectiveAction | null;
  reasonCodes: string[];
  boundaryViolation: string | null;
  boundaryMatchedRule: string | null;
  idempotencyKey: string | null;
}

// ── Wire parsers (snake_case JSON → camelCase typed) ────────────────

function asString(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}
function asNumber(v: unknown, fallback = 0): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}

/** Build a variant from the gateway's `(kind, payload)` wire shape.
 *
 *  The wire format is flat — the discriminator string lives at the
 *  outer corrective's `.kind`, the variant-specific fields live in
 *  `.payload`. Matches `ag_common::denial::CorrectiveActionJson` on
 *  the Rust side and the dashboard's `CorrectiveAction` interface. */
function parseVariant(
  kind: unknown,
  payload: unknown,
): CorrectiveActionVariant | null {
  if (typeof kind !== "string") return null;
  const p =
    payload && typeof payload === "object"
      ? (payload as Record<string, unknown>)
      : {};
  switch (kind) {
    case "switch_tool":
      return {
        kind: "switchTool",
        tool: asString(p.tool),
        scope: typeof p.scope === "string" ? p.scope : undefined,
      };
    case "downscope_to":
      return { kind: "downscopeTo", scope: asString(p.scope) };
    case "rename_field":
      return {
        kind: "renameField",
        from: asString(p.from),
        to: asString(p.to),
      };
    case "redact_value":
      return {
        kind: "redactValue",
        jsonPath: asString(p.json_path),
        mask: asString(p.mask),
      };
    case "split_request":
      return {
        kind: "splitRequest",
        maxItemsPerBatch: asNumber(p.max_items_per_batch),
        currentItems: asNumber(p.current_items),
      };
    case "wait_and_retry":
      return {
        kind: "waitAndRetry",
        retryAfterSeconds: asNumber(p.retry_after_seconds),
        windowLabel:
          typeof p.window_label === "string" ? p.window_label : undefined,
      };
    case "switch_endpoint":
      return {
        kind: "switchEndpoint",
        fromUrl: asString(p.from_url),
        toUrl: asString(p.to_url),
      };
    case "no_correction":
      return { kind: "noCorrection" };
    default:
      return null;
  }
}

const VALID_CONFIDENCES: ReadonlySet<Confidence> = new Set([
  "high",
  "medium",
  "low",
]);
const VALID_SOURCES: ReadonlySet<Source> = new Set([
  "rule",
  "rule_dynamic",
  "scope",
  "boundary",
  "cedar",
  "sdk_override",
  "bundle",
  "gateway",
]);

export function parseCorrectiveAction(
  raw: unknown,
): CorrectiveAction | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  // Flat wire shape: `kind` at top, variant fields in `payload`.
  // Mirrors the Python SDK's `CorrectiveAction.from_json`.
  const variant = parseVariant(r.kind, r.payload);
  if (!variant) return null;
  const conf = r.confidence;
  const confidence: Confidence =
    typeof conf === "string" && VALID_CONFIDENCES.has(conf as Confidence)
      ? (conf as Confidence)
      : "medium";
  const src = r.source;
  const source: Source =
    typeof src === "string" && VALID_SOURCES.has(src as Source)
      ? (src as Source)
      : "rule";
  // v0.23.1: optional pre-rendered block.
  let rendered: RenderedCorrective | null = null;
  if (r.rendered && typeof r.rendered === "object") {
    const rr = r.rendered as Record<string, unknown>;
    rendered = {
      toolResult: asString(rr.tool_result),
      shortLabel: asString(rr.short_label),
    };
  }
  return {
    action: variant,
    humanExplanation: asString(r.human_explanation),
    confidence,
    source,
    rendered,
  };
}

export function parseStructuredDenial(raw: unknown): StructuredDenial | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (Object.keys(r).length === 0) return null;
  const reasonCodesRaw = Array.isArray(r.reason_codes) ? r.reason_codes : [];
  return {
    ruleId: asString(r.rule_id),
    violatedPredicate: asString(r.violated_predicate),
    offendingValue: asString(r.offending_value),
    corrective: parseCorrectiveAction(r.corrective),
    reasonCodes: reasonCodesRaw
      .filter((c): c is string => typeof c === "string"),
    boundaryViolation:
      typeof r.boundary_violation === "string" ? r.boundary_violation : null,
    boundaryMatchedRule:
      typeof r.boundary_matched_rule === "string"
        ? r.boundary_matched_rule
        : null,
    idempotencyKey:
      typeof r.idempotency_key === "string" ? r.idempotency_key : null,
  };
}

/**
 * Build a synthetic StructuredDenial for SDK-side error conditions
 * (gateway timeout, circuit breaker, network failure) where no gateway
 * denial was returned. Uses `SDK/...` rule IDs so observability can
 * distinguish these from real rule denials.
 */
export function syntheticDenial(
  ruleId: string,
  violatedPredicate: string,
  corrective: CorrectiveAction | null = null,
): StructuredDenial {
  return {
    ruleId,
    violatedPredicate,
    offendingValue: "",
    corrective,
    reasonCodes: [],
    boundaryViolation: null,
    boundaryMatchedRule: null,
    idempotencyKey: null,
  };
}

// ── LLM-facing render templates ─────────────────────────────────────

/**
 * Render a corrective into a tool_result-suitable string.
 *
 * Returns "" for low-confidence correctives (dashboard-only). LLM tool
 * loops use this string as the `tool_result.content` so the model can
 * pattern-match on the suggested action.
 *
 * Template set is shared with the Python SDK — keep in sync.
 */
export function renderCorrectiveForLLM(
  c: CorrectiveAction | null,
): string {
  if (!c) return "";
  // v0.23.1+: prefer the server-rendered string. The gateway pre-applies
  // the "low confidence = empty" rule, so we don't duplicate it.
  if (c.rendered !== null) return c.rendered.toolResult;
  // Fallback for pre-0.23.1 gateways.
  if (c.confidence === "low") return "";

  const explanation = c.humanExplanation || "denied";
  const a = c.action;
  switch (a.kind) {
    case "switchTool":
      return `Denied: ${explanation}\nTry the \`${a.tool}\` tool instead.`;
    case "downscopeTo":
      return `Denied: ${explanation}\nRetry under scope \`${a.scope}\`.`;
    case "renameField":
      return `Denied: ${explanation}\nRename \`${a.from}\` → \`${a.to}\` and retry.`;
    case "redactValue":
      return `Denied: ${explanation}\nRemove the value at \`${a.jsonPath}\` before retry.`;
    case "splitRequest":
      return `Denied: ${explanation}\nSplit into batches of ≤ ${a.maxItemsPerBatch}.`;
    case "waitAndRetry": {
      const suffix = a.windowLabel ? ` (${a.windowLabel})` : "";
      return `Denied: ${explanation}\nRetry after ${a.retryAfterSeconds}s${suffix}.`;
    }
    case "switchEndpoint":
      return `Denied: ${explanation}\nUse \`${a.toUrl}\` instead of \`${a.fromUrl}\`.`;
    case "noCorrection":
      return `Denied: ${explanation}`;
  }
}
