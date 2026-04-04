/**
 * Minimal logger that writes to stderr (to avoid corrupting MCP stdio streams).
 */

let verbose = false;

export function setVerbose(v: boolean): void {
  verbose = v;
}

export function log(level: "info" | "warn" | "error" | "debug", msg: string): void {
  if (level === "debug" && !verbose) return;

  const ts = new Date().toISOString();
  const prefix = `[${ts}] [clampd-mcp-proxy] [${level}]`;
  process.stderr.write(`${prefix} ${msg}\n`);
}
