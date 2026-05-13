/**
 * Tool classification taxonomy for the Clampd SDK.
 *
 * THE source of truth for this taxonomy is the TOML file at:
 *   services/crates/ag-common/src/categories.toml
 *
 * If you change this file, keep it in sync with categories.toml — the Rust
 * gateway loads that TOML at startup and will reject (category, subcategory,
 * operation) triples that don't appear there. Conversely, when the TOML
 * gains a new subcategory or operation, regenerate this file. Consider a
 * build-time codegen step when the taxonomy stabilises; for now the file
 * is hand-maintained and the discriminated union below is the compile-time
 * guard against drift.
 *
 * Shape:
 *   - `ToolClassification` — discriminated union, one member per
 *     (category, subcategory) pair. The `operation` field is narrowed by
 *     the compiler based on (category, subcategory). Misclassifications
 *     such as `{ category: "comms", subcategory: "shell" }` are a tsc
 *     error, not a runtime surprise.
 *   - `TAXONOMY`         — flat runtime table mirroring the TOML, for
 *     dashboards, validators, and any consumer that can't rely on the
 *     static union (e.g. values coming over the wire).
 *   - `validateClassification` — runtime belt-and-suspenders check for
 *     callers who bypass the union via `as any`.
 *   - `computeScope`     — canonical `"category:subcategory:operation"`
 *     string the gateway expects.
 */

// ── Discriminated union ─────────────────────────────────────────────
//
// One union member per (category, subcategory) pair. The operation field
// is narrowed by the category+subcategory discriminator, so the compiler
// enforces valid triples at registration time.

export type ToolClassification =
  // comms — messaging, email, notifications
  | { category: "comms"; subcategory: "email"; operation: "read" | "send" | "delete" }
  | { category: "comms"; subcategory: "slack"; operation: "read" | "send" | "delete" }
  | { category: "comms"; subcategory: "sms"; operation: "read" | "send" }
  | { category: "comms"; subcategory: "notification"; operation: "send" }
  | { category: "comms"; subcategory: "messaging"; operation: "read" | "send" | "delete" }

  // db — database access
  | { category: "db"; subcategory: "query"; operation: "read" }
  | { category: "db"; subcategory: "mutate"; operation: "write" | "delete" | "destructive" }
  | { category: "db"; subcategory: "schema"; operation: "read" | "destructive" }

  // exec — code / shell / process execution
  | { category: "exec"; subcategory: "shell"; operation: "run" | "destructive" }
  | { category: "exec"; subcategory: "code"; operation: "run" }
  | { category: "exec"; subcategory: "function"; operation: "run" }

  // fs — filesystem I/O
  | { category: "fs"; subcategory: "file"; operation: "read" | "write" | "delete" }
  | { category: "fs"; subcategory: "blob"; operation: "read" | "write" | "delete" }

  // net — network I/O
  | { category: "net"; subcategory: "http"; operation: "read" | "write" }
  | { category: "net"; subcategory: "dns"; operation: "read" }
  | { category: "net"; subcategory: "socket"; operation: "read" | "write" }

  // auth — credentials, secrets, tokens
  | { category: "auth"; subcategory: "secret"; operation: "read" | "write" | "delete" }
  | { category: "auth"; subcategory: "credential"; operation: "read" | "write" | "delete" }
  | { category: "auth"; subcategory: "token"; operation: "read" | "write" | "delete" | "refresh" }
  | { category: "auth"; subcategory: "oauth"; operation: "read" | "write" }

  // llm — model interaction
  | { category: "llm"; subcategory: "input"; operation: "write" }
  | { category: "llm"; subcategory: "output"; operation: "read" }
  | { category: "llm"; subcategory: "embedding"; operation: "read" | "write" }

  // cloud — infrastructure / IAM / deploy
  | { category: "cloud"; subcategory: "infra"; operation: "read" | "write" | "destructive" }
  | { category: "cloud"; subcategory: "iam"; operation: "read" | "write" | "delete" }
  | { category: "cloud"; subcategory: "deploy"; operation: "read" | "write" | "destructive" }

  // scm — source control / VCS
  | { category: "scm"; subcategory: "git"; operation: "read" | "write" | "delete" }

  // browser — page navigation / scraping
  | { category: "browser"; subcategory: "page"; operation: "read" | "write" }
  | { category: "browser"; subcategory: "screenshot"; operation: "read" }

  // agent — agent-to-agent / delegation
  | { category: "agent"; subcategory: "delegate"; operation: "write" }
  | { category: "agent"; subcategory: "spawn"; operation: "write" }
  | { category: "agent"; subcategory: "a2a"; operation: "read" | "write" }
  | { category: "agent"; subcategory: "config"; operation: "read" | "write" }

  // payment — financial / billing
  | { category: "payment"; subcategory: "transaction"; operation: "read" | "write" | "destructive" }
  | { category: "payment"; subcategory: "billing"; operation: "read" | "write" }
  | { category: "payment"; subcategory: "invoice"; operation: "read" | "write" };

// ── Runtime table ───────────────────────────────────────────────────
//
// Mirrors categories.toml for consumers that need to enumerate the
// taxonomy at runtime (dashboards, validators, docs generation). The
// data comes from `./generated/taxonomy-data.ts`, which is codegen'd by
// ag-common's build.rs from `services/crates/ag-common/src/categories.toml`.

import {
  TAXONOMY,
  type CategorySpec,
  type SubcategorySpec,
} from "./generated/taxonomy-data.js";

export { TAXONOMY };
export type { CategorySpec, SubcategorySpec };

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Validate a (category, subcategory, operation) triple against the
 * runtime taxonomy table. Returns `true` if the triple is present in
 * `TAXONOMY`, else `false`.
 *
 * This is a belt-and-suspenders check for callers that bypass the
 * `ToolClassification` discriminated union (e.g. via `as any` or when
 * the values come from JSON over the wire).
 */
export function validateClassification(
  category: string,
  subcategory: string,
  operation: string,
): boolean {
  const cat = TAXONOMY[category];
  if (!cat) return false;
  const sub = cat.subcategories[subcategory];
  if (!sub) return false;
  return sub.operations.includes(operation);
}

/**
 * Compute the canonical scope string for a classification.
 * Format: `"category:subcategory:operation"` (e.g. `"db:query:read"`).
 */
export function computeScope(c: ToolClassification): string {
  return `${c.category}:${c.subcategory}:${c.operation}`;
}
