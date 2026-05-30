/**
 * Zero-code auto-instrumentation activation for Clampd (TypeScript / Node).
 *
 * Two activation paths, mirroring the Python SDK:
 *
 *   1. One import at the very top of your entrypoint (before importing
 *      `openai` / `@anthropic-ai/sdk`)::
 *
 *        import "@clampd/sdk/auto";
 *
 *   2. The launcher — no code change at all::
 *
 *        clampd run -- node app.js
 *        clampd run -- tsx server.ts
 *
 * Importing this module:
 *   1. Registers an ESM loader hook so every `new OpenAI()` / `new Anthropic()`
 *      imported afterwards is transparently wrapped with `clampd.openai()` /
 *      `clampd.anthropic()` — no manual wrapping in your code.
 *   2. Auto-initializes Clampd from `CLAMPD_DSN` (enrolls; no explicit init()).
 */

import { installHook, autoInit } from "./instrument.js";

export { __clampdWrap, autoInit, installHook } from "./instrument.js";

// Register the loader first so client libraries imported *after* this module
// are intercepted, then auto-init. Top-level await means `--import` /
// `clampd run` finish enrollment before the host program's first call.
installHook();
await autoInit();
