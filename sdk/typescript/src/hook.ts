/**
 * Clampd ESM loader hook (runs on the module-loader thread).
 *
 * Registered by `src/auto.ts` via `module.register`. For each target client
 * library it tags the resolved URL, then replaces the loaded module with a
 * thin synthetic module that re-exports everything unchanged except the
 * client class(es), which are wrapped with a construct-trap that applies
 * `clampd.openai()` / `clampd.anthropic()` to every instance.
 *
 * This is the same technique `import-in-the-middle` / OpenTelemetry use,
 * specialized to the two libraries we instrument so we carry no extra deps.
 */

const MARK = "clampd-orig";

interface Target {
  /** Named class exports to wrap (each must exist on the target module). */
  classes: string[];
  /** Which Clampd wrapper to apply. */
  kind: "openai" | "anthropic";
}

const TARGETS: Record<string, Target> = {
  openai: { classes: ["OpenAI", "AzureOpenAI"], kind: "openai" },
  "@anthropic-ai/sdk": { classes: ["Anthropic", "AnthropicBedrock", "AnthropicVertex"], kind: "anthropic" },
};

// Absolute URL to the compiled, side-effect-free module that exports
// __clampdWrap. The synthetic module imports it so wrapping happens on the
// main thread, in the host application's realm (not the loader thread), and
// without re-triggering auto.ts's activation side effects.
const AUTO_URL = new URL("./instrument.js", import.meta.url).href;

interface ResolveContext {
  parentURL?: string;
  [k: string]: unknown;
}
type ResolveResult = { url: string; [k: string]: unknown };
type NextResolve = (spec: string, ctx: ResolveContext) => Promise<ResolveResult>;

export async function resolve(spec: string, ctx: ResolveContext, next: NextResolve): Promise<ResolveResult> {
  const r = await next(spec, ctx);
  if (TARGETS[spec] && !r.url.includes(MARK)) {
    const sep = r.url.includes("?") ? "&" : "?";
    return { ...r, url: `${r.url}${sep}${MARK}=${encodeURIComponent(spec)}` };
  }
  return r;
}

interface LoadResult {
  format?: string | null;
  source?: string;
  shortCircuit?: boolean;
  [k: string]: unknown;
}
type NextLoad = (url: string, ctx: Record<string, unknown>) => Promise<LoadResult>;

export async function load(url: string, ctx: Record<string, unknown>, next: NextLoad): Promise<LoadResult> {
  const re = new RegExp(`[?&]${MARK}=([^&]+)$`);
  const m = url.match(re);
  if (!m) return next(url, ctx);

  const spec = decodeURIComponent(m[1]);
  const target = TARGETS[spec];
  if (!target) return next(url, ctx);

  // Original module URL (query stripped). Importing it does NOT re-trigger
  // this hook — the hook only fires on the marked specifier in resolve().
  const orig = url.replace(re, "");
  const { classes, kind } = target;

  const source = [
    `import * as __orig from ${JSON.stringify(orig)};`,
    `import { __clampdWrap } from ${JSON.stringify(AUTO_URL)};`,
    `export * from ${JSON.stringify(orig)};`,
    ...classes.map(
      (c) => `export const ${c} = __clampdWrap(__orig[${JSON.stringify(c)}], ${JSON.stringify(kind)});`,
    ),
    `export default __clampdWrap(__orig.default, ${JSON.stringify(kind)});`,
  ].join("\n");

  return { format: "module", shortCircuit: true, source };
}
