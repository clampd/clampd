// AUTO-GENERATED FROM services/crates/ag-common/src/categories.toml
// DO NOT EDIT BY HAND — run `cargo build -p ag-common` to regenerate.
// Runtime taxonomy table for the TypeScript SDK. The discriminated
// union `ToolClassification` stays hand-written in `taxonomy.ts` — only
// this runtime data is regenerated.

export interface SubcategorySpec {
  readonly operations: readonly string[];
  /** Subset of `operations` that mean external-egress (data leaving the org boundary). */
  readonly egress: readonly string[];
  /** Subset of `operations` that ALWAYS produce sensitive data. Sets sticky session-level taint flag. */
  readonly sensitive_source: readonly string[];
}

export interface CategorySpec {
  readonly description: string;
  readonly subcategories: Record<string, SubcategorySpec>;
}

export const TAXONOMY: Record<string, CategorySpec> = {
  agent: {
    description: "Agent delegation, A2A handoff, spawn",
    subcategories: {
      a2a: { operations: ["read", "write"] as const, egress: [] as const, sensitive_source: [] as const },
      config: { operations: ["read", "write"] as const, egress: [] as const, sensitive_source: [] as const },
      delegate: { operations: ["write"] as const, egress: [] as const, sensitive_source: [] as const },
      spawn: { operations: ["write"] as const, egress: [] as const, sensitive_source: [] as const },
    },
  },
  auth: {
    description: "Secrets, credentials, tokens, OAuth flows",
    subcategories: {
      credential: { operations: ["read", "write", "delete"] as const, egress: [] as const, sensitive_source: ["read"] as const },
      oauth: { operations: ["read", "write"] as const, egress: [] as const, sensitive_source: ["read"] as const },
      secret: { operations: ["read", "write", "delete"] as const, egress: [] as const, sensitive_source: ["read"] as const },
      token: { operations: ["read", "write", "delete", "refresh"] as const, egress: [] as const, sensitive_source: ["read"] as const },
    },
  },
  browser: {
    description: "Browser automation, page navigation, scraping",
    subcategories: {
      page: { operations: ["read", "write"] as const, egress: [] as const, sensitive_source: [] as const },
      screenshot: { operations: ["read"] as const, egress: [] as const, sensitive_source: [] as const },
    },
  },
  cloud: {
    description: "Cloud infra, deploys, IAM, object storage",
    subcategories: {
      deploy: { operations: ["read", "write", "destructive"] as const, egress: [] as const, sensitive_source: [] as const },
      iam: { operations: ["read", "write", "delete"] as const, egress: [] as const, sensitive_source: ["read"] as const },
      infra: { operations: ["read", "write", "destructive"] as const, egress: [] as const, sensitive_source: [] as const },
    },
  },
  comms: {
    description: "Email, chat, SMS, notifications — anything agent says to humans or other systems",
    subcategories: {
      email: { operations: ["read", "send", "delete"] as const, egress: ["send"] as const, sensitive_source: [] as const },
      messaging: { operations: ["read", "send", "delete"] as const, egress: ["send"] as const, sensitive_source: [] as const },
      notification: { operations: ["send"] as const, egress: ["send"] as const, sensitive_source: [] as const },
      slack: { operations: ["read", "send", "delete"] as const, egress: ["send"] as const, sensitive_source: [] as const },
      sms: { operations: ["read", "send"] as const, egress: ["send"] as const, sensitive_source: [] as const },
    },
  },
  db: {
    description: "Database queries, mutations, schema operations",
    subcategories: {
      mutate: { operations: ["write", "delete", "destructive"] as const, egress: [] as const, sensitive_source: [] as const },
      query: { operations: ["read"] as const, egress: [] as const, sensitive_source: [] as const },
      schema: { operations: ["read", "destructive"] as const, egress: [] as const, sensitive_source: ["read"] as const },
    },
  },
  exec: {
    description: "Shell commands, code evaluation, function invocation",
    subcategories: {
      code: { operations: ["run"] as const, egress: [] as const, sensitive_source: [] as const },
      function: { operations: ["run"] as const, egress: [] as const, sensitive_source: [] as const },
      shell: { operations: ["run", "destructive"] as const, egress: [] as const, sensitive_source: [] as const },
    },
  },
  fs: {
    description: "Filesystem, blob / object storage",
    subcategories: {
      blob: { operations: ["read", "write", "delete"] as const, egress: ["write"] as const, sensitive_source: [] as const },
      file: { operations: ["read", "write", "delete"] as const, egress: [] as const, sensitive_source: [] as const },
    },
  },
  llm: {
    description: "LLM prompt / completion, embeddings",
    subcategories: {
      embedding: { operations: ["read", "write"] as const, egress: [] as const, sensitive_source: [] as const },
      input: { operations: ["write"] as const, egress: [] as const, sensitive_source: [] as const },
      output: { operations: ["read"] as const, egress: [] as const, sensitive_source: [] as const },
    },
  },
  net: {
    description: "HTTP, webhooks, raw-socket, DNS",
    subcategories: {
      dns: { operations: ["read"] as const, egress: [] as const, sensitive_source: [] as const },
      http: { operations: ["read", "write"] as const, egress: ["write"] as const, sensitive_source: [] as const },
      socket: { operations: ["read", "write"] as const, egress: ["write"] as const, sensitive_source: [] as const },
    },
  },
  payment: {
    description: "Payments, billing, refunds, financial transactions",
    subcategories: {
      billing: { operations: ["read", "write"] as const, egress: [] as const, sensitive_source: [] as const },
      invoice: { operations: ["read", "write"] as const, egress: [] as const, sensitive_source: [] as const },
      transaction: { operations: ["read", "write", "destructive"] as const, egress: [] as const, sensitive_source: [] as const },
    },
  },
  scm: {
    description: "Git / VCS — push, commit, branch management",
    subcategories: {
      git: { operations: ["read", "write", "delete"] as const, egress: [] as const, sensitive_source: [] as const },
    },
  },
};
