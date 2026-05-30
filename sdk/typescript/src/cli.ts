#!/usr/bin/env node
/**
 * `clampd` CLI launcher.
 *
 *   clampd run -- node app.js
 *   clampd run -- tsx server.ts
 *
 * Runs any command with Clampd auto-instrumentation enabled (no code change),
 * mirroring `ddtrace-run` / the Python `clampd run`: it prepends
 * `--import <auto module>` to the child's NODE_OPTIONS so the ESM loader hook
 * and DSN auto-init are active before the target program's first import.
 */

import { spawnSync } from "node:child_process";

function main(): void {
  let argv = process.argv.slice(2);
  if (argv[0] === "run") argv = argv.slice(1);
  if (argv[0] === "--") argv = argv.slice(1);
  if (argv.length === 0) {
    process.stderr.write("usage: clampd run -- <command> [args...]\n  e.g. clampd run -- node app.js\n");
    process.exit(2);
  }

  const autoUrl = new URL("./auto.js", import.meta.url).href;
  const env = { ...process.env };
  const existing = env.NODE_OPTIONS ?? "";
  env.NODE_OPTIONS = `${existing} --import ${autoUrl}`.trim();

  const [cmd, ...rest] = argv;
  const child = spawnSync(cmd, rest, { stdio: "inherit", env });
  if (child.error) {
    const err = child.error as NodeJS.ErrnoException;
    if (err.code === "ENOENT") {
      process.stderr.write(`clampd run: command not found: ${cmd}\n`);
      process.exit(127);
    }
    throw child.error;
  }
  process.exit(child.status ?? 0);
}

main();
