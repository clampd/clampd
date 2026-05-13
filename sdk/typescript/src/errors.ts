/**
 * Error classes exposed by the Clampd SDK that aren't tied to a specific
 * integration module.
 *
 * Notes:
 *   - `ClampdBlockedError` lives in `interceptor.ts` and is re-exported
 *     from `index.ts`. It belongs to the proxy path and stays there.
 *   - This module is for errors that are raised outside of a proxy call
 *     — classification errors, config errors, etc.
 */

/**
 * Thrown when a tool classification fails runtime validation.
 *
 * The primary defence against bad classifications is the
 * `ToolClassification` discriminated union in `taxonomy.ts` — the tsc
 * compiler rejects invalid triples at build time. This error exists for
 * the case where a caller deliberately bypasses the type system (e.g.
 * `as any`, JSON-over-the-wire, dynamic registration) and we still want
 * to reject unknown (category, subcategory, operation) combinations at
 * runtime rather than silently letting them land in the backend as
 * unclassified.
 */
export class ClampdClassificationError extends Error {
  public readonly category: string;
  public readonly subcategory: string;
  public readonly operation: string;

  constructor(category: string, subcategory: string, operation: string) {
    super(
      `Invalid tool classification: { category: "${category}", subcategory: "${subcategory}", operation: "${operation}" } ` +
        "is not present in the taxonomy. " +
        "Check services/crates/ag-common/src/categories.toml for valid triples, " +
        "or use the ToolClassification discriminated union so tsc enforces this at compile time.",
    );
    this.name = "ClampdClassificationError";
    this.category = category;
    this.subcategory = subcategory;
    this.operation = operation;
  }
}

/**
 * Thrown when a tool call is denied because the gateway has no descriptor
 * registered for that tool name (or the descriptor failed classification
 * and was rejected at registration time).
 *
 * Distinct from {@link import("./interceptor.js").ClampdBlockedError}
 * (which signals a policy / risk / scope decision against a *known*
 * tool) — this error means the tool is unknown to Clampd and the fix
 * is to register it at module load time, not to relax a policy.
 *
 * The SDK raises this when the gateway returns
 * `denial_reason` starting with `"tool_not_registered:"` or
 * `"tool_not_classified:"`. Mirrors
 * `clampd._errors.ClampdUnregisteredToolError` in the Python SDK so
 * cross-language docs / examples stay in lockstep.
 */
export class ClampdUnregisteredToolError extends Error {
  public readonly toolName: string;
  public readonly hint: string;

  constructor(toolName: string, opts?: { hint?: string }) {
    const hint =
      opts?.hint ??
      `Call clampd.registerTool('${toolName}', { category, subcategory, operation }) at module load time.`;
    super(`Tool '${toolName}' is not registered with Clampd. ${hint}`);
    this.name = "ClampdUnregisteredToolError";
    this.toolName = toolName;
    this.hint = hint;
  }
}

/**
 * Thrown when a tool call is denied because the descriptor hash sent to
 * the gateway doesn't match any approved hash for that tool name.
 *
 * Distinct from {@link ClampdUnregisteredToolError} (the tool is unknown
 * entirely) and from {@link import("./interceptor.js").ClampdBlockedError}
 * (a policy / risk / scope decision against an *approved* descriptor):
 * this error means the descriptor exists, but its current hash isn't on
 * the approved list — most often the tool's name / description /
 * parameter schema changed since the dashboard approved it (rug-pull
 * detection) and the new version needs to be approved.
 *
 * The SDK raises this when the gateway returns a `denial_reason`
 * starting with `"descriptor_hash_mismatch:"`. The optional
 * `attemptedHash` field is parsed from the reason text when present
 * (gateway includes it as `"... with hash <hex> ..."`). Mirrors
 * `clampd._errors.ClampdDescriptorMismatchError` in the Python SDK.
 */
export class ClampdDescriptorMismatchError extends Error {
  public readonly toolName: string;
  public readonly attemptedHash: string | undefined;
  public readonly hint: string;

  constructor(
    toolName: string,
    opts?: { attemptedHash?: string; hint?: string },
  ) {
    let hint: string;
    if (opts?.hint !== undefined) {
      hint = opts.hint;
    } else if (opts?.attemptedHash) {
      hint =
        `Approve hash ${opts.attemptedHash.slice(0, 16)}... in the ` +
        `dashboard for tool '${toolName}'.`;
    } else {
      hint =
        `Approve the new descriptor hash for tool '${toolName}' ` +
        `in the dashboard.`;
    }
    super(
      `Tool '${toolName}' descriptor hash does not match any approved ` +
        `version. ${hint}`,
    );
    this.name = "ClampdDescriptorMismatchError";
    this.toolName = toolName;
    this.attemptedHash = opts?.attemptedHash;
    this.hint = hint;
  }
}
