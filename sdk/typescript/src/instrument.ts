/**
 * Auto-instrumentation primitives for Clampd (TypeScript / Node).
 *
 * Side-effect-free building blocks consumed by:
 *   - `auto.ts` — the activation entry (`import "@clampd/sdk/auto"`)
 *   - `hook.ts` — the ESM loader hook (calls `__clampdWrap`)
 *   - `cli.ts`  — the `clampd run` launcher
 *
 * Every failure here is logged, never thrown: auto-instrumentation must not
 * take down the host application.
 */

import { register } from "node:module";
import clampd from "./index.js";
import { init, defaultClient } from "./config.js";

/** Construct-trap wrapper used by the loader hook (see hook.ts).
 *
 * Returns a Proxy of the original client class whose `construct` trap applies
 * the matching Clampd wrapper to each instance. Non-function inputs and any
 * wrapping failure fall through to the original, so a broken instrumentation
 * never breaks `new OpenAI()`.
 */
export function __clampdWrap<T extends abstract new (...a: never[]) => object>(
  cls: T,
  kind: "openai" | "anthropic",
): T {
  if (typeof cls !== "function") return cls;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- both wrappers accept a runtime client shape
  const wrapper: (c: any, o: object) => object = kind === "anthropic" ? clampd.anthropic : clampd.openai;
  return new Proxy(cls, {
    construct(target, args, newTarget) {
      const instance = Reflect.construct(target, args as never[], newTarget);
      try {
        return wrapper(instance, {});
      } catch (e) {
        console.warn(`[clampd] auto-instrument(${kind}) failed: ${String(e)}`);
        return instance;
      }
    },
  }) as T;
}

/** Auto-initialize from CLAMPD_DSN. Idempotent and never fatal. */
export async function autoInit(): Promise<void> {
  if (defaultClient || !process.env.CLAMPD_DSN) return;
  try {
    await init();
  } catch (e) {
    console.warn(`[clampd] auto-init failed (calls will error until init): ${String(e)}`);
  }
}

let _hookRegistered = false;

/** Register the ESM loader hook exactly once. Never fatal. */
export function installHook(): void {
  if (_hookRegistered) return;
  try {
    register(new URL("./hook.js", import.meta.url), import.meta.url);
    _hookRegistered = true;
  } catch (e) {
    console.warn(`[clampd] failed to install import hook (wrap openai/anthropic manually): ${String(e)}`);
  }
}
