/**
 * Fleet orchestrator - runs multiple MCP proxy instances from a single config.
 *
 * Each proxy wraps a different upstream MCP server with a different agent identity,
 * enabling multi-agent demos showing scope isolation, delegation chains, and
 * behavioral correlation.
 *
 * Usage:
 *   clampd-mcp-proxy --fleet-config fleet.json
 *
 * Config:
 *   {
 *     "gateway": "http://ag-gateway:8080",
 *     "apiKey": "ag_test_acme_demo_2026",
 *     "secret": "ags_...",
 *     "dashboardPort": 3000,
 *     "agents": [
 *       { "name": "Data Analyst", "agentId": "...", "port": 3003, "upstream": "...", "color": "#3b82f6" },
 *       { "name": "DevOps Bot",   "agentId": "...", "port": 3004, "upstream": "...", "color": "#22c55e" },
 *       { "name": "DB Admin",     "agentId": "...", "port": 3005, "upstream": "...", "color": "#f59e0b" }
 *     ]
 *   }
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { startProxy, type ProxyOptions } from "./proxy.js";
import type { ProxyEvent } from "./dashboard.js";
import { log, setVerbose } from "./logger.js";

// ── Fleet Config ──────────────────────────────────────────────────────

export interface FleetAgentConfig {
  name: string;
  agentId: string;
  port: number;
  upstream: string;
  color?: string;
  scanInput?: boolean;
  scanOutput?: boolean;
  checkResponse?: boolean;
  demoPanel?: boolean;
  secret?: string;
}

export interface FleetConfig {
  gateway: string;
  apiKey: string;
  secret?: string;
  dashboardPort: number;
  dryRun?: boolean;
  verbose?: boolean;
  agents: FleetAgentConfig[];
}

// ── Fleet Event (ProxyEvent + agent metadata) ─────────────────────────

export interface FleetEvent extends ProxyEvent {
  agentName?: string;
  agentColor?: string;
  agentId?: string;
}

// ── Fleet State ───────────────────────────────────────────────────────

const fleetEvents: FleetEvent[] = [];
const MAX_FLEET_EVENTS = 2000;
const fleetSubscribers = new Set<ServerResponse>();

function pushFleetEvent(event: FleetEvent): void {
  fleetEvents.push(event);
  if (fleetEvents.length > MAX_FLEET_EVENTS) {
    fleetEvents.shift();
  }
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of fleetSubscribers) {
    try {
      res.write(payload);
    } catch {
      fleetSubscribers.delete(res);
    }
  }
}

// ── Start Fleet ───────────────────────────────────────────────────────

export async function startFleet(configPath: string): Promise<void> {
  const raw = readFileSync(configPath, "utf-8");
  const config: FleetConfig = JSON.parse(raw);

  if (config.verbose) setVerbose(true);

  log("info", "");
  log("info", "=== Clampd MCP Fleet ===");
  log("info", `Agents: ${config.agents.length}`);
  log("info", `Dashboard: http://localhost:${config.dashboardPort}/`);
  log("info", "");

  // Build color map
  const defaultColors = ["#3b82f6", "#22c55e", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899", "#06b6d4", "#84cc16"];
  const colorMap = new Map<string, string>();
  config.agents.forEach((a, i) => {
    colorMap.set(a.agentId, a.color ?? defaultColors[i % defaultColors.length]);
  });

  // Start each proxy instance
  for (const agent of config.agents) {
    const opts: ProxyOptions = {
      upstreamCommand: agent.upstream,
      gatewayUrl: config.gateway,
      apiKey: config.apiKey,
      agentId: agent.agentId,
      port: agent.port,
      secret: agent.secret ?? config.secret,
      dryRun: config.dryRun ?? false,
      verbose: config.verbose ?? false,
      scanInputEnabled: agent.scanInput ?? true,
      scanOutputEnabled: agent.scanOutput ?? true,
      checkResponse: agent.checkResponse ?? false,
      demoPanel: agent.demoPanel ?? false,
      agentName: agent.name,
      onEvent: (event) => {
        pushFleetEvent({
          ...event,
          agentName: agent.name,
          agentColor: colorMap.get(agent.agentId),
          agentId: agent.agentId,
        });
      },
    };

    try {
      await startProxy(opts);
      log("info", `Started agent "${agent.name}" on port ${agent.port} (${agent.agentId.slice(0, 8)}...)`);
    } catch (err: unknown) {
      log("error", `Failed to start agent "${agent.name}": ${err instanceof Error ? err.message : err}`);
    }
  }

  // Start fleet dashboard server
  const httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://localhost:${config.dashboardPort}`);

    // GET / - Fleet dashboard
    if (url.pathname === "/" && req.method === "GET") {
      const html = renderFleetDashboard(fleetEvents, config);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(html);
      return;
    }

    // GET /events - Fleet SSE stream
    if (url.pathname === "/events" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
      res.write(`data: ${JSON.stringify({ type: "connected", total: fleetEvents.length })}\n\n`);
      fleetSubscribers.add(res);
      req.on("close", () => fleetSubscribers.delete(res));
      return;
    }

    // GET /health - Fleet health
    if (url.pathname === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        mode: "fleet",
        agents: config.agents.map((a) => ({ name: a.name, agentId: a.agentId, port: a.port })),
        total_events: fleetEvents.length,
      }));
      return;
    }

    res.writeHead(404);
    res.end("Not found");
  });

  httpServer.listen(config.dashboardPort, () => {
    log("info", `Fleet dashboard: http://localhost:${config.dashboardPort}/`);
    for (const agent of config.agents) {
      log("info", `  ${agent.name}: http://localhost:${agent.port}/sse (MCP) | http://localhost:${agent.port}/ (dashboard)`);
    }
    log("info", "");
    log("info", "Claude Desktop config - add each agent as a separate MCP server:");
    log("info", JSON.stringify({
      mcpServers: Object.fromEntries(
        config.agents.map((a) => [
          a.name.toLowerCase().replace(/\s+/g, "-"),
          { url: `http://localhost:${a.port}/sse` },
        ]),
      ),
    }, null, 2));
    log("info", "");
  });
}

// ── Fleet Dashboard Renderer ──────────────────────────────────────────

function renderFleetDashboard(events: FleetEvent[], config: FleetConfig): string {
  const agentStats = new Map<string, { name: string; color: string; total: number; blocked: number; flagged: number; allowed: number; errors: number; port: number }>();

  for (const a of config.agents) {
    const color = a.color ?? "#888";
    agentStats.set(a.agentId, { name: a.name, color, total: 0, blocked: 0, flagged: 0, allowed: 0, errors: 0, port: a.port });
  }

  for (const e of events) {
    const stats = agentStats.get(e.agentId ?? "");
    if (stats) {
      stats.total++;
      if (e.status === "blocked") stats.blocked++;
      else if (e.status === "flagged") stats.flagged++;
      else if (e.status === "error") stats.errors++;
      else stats.allowed++;
    }
  }

  // Agent cards
  const agentCards = Array.from(agentStats.values())
    .map((s) => `
      <div style="border:1px solid #222;border-left:3px solid ${s.color};border-radius:6px;padding:12px 16px;min-width:200px">
        <div style="font-size:14px;font-weight:600;color:${s.color}">${esc(s.name)}</div>
        <div style="font-size:11px;color:#555;margin-top:2px">Port ${s.port}</div>
        <div style="display:flex;gap:12px;margin-top:8px;font-size:12px">
          <span style="color:#22c55e">${s.allowed} ok</span>
          <span style="color:#ef4444">${s.blocked} blocked</span>
          <span style="color:#f59e0b">${s.flagged} flagged</span>
          <span style="color:#6b7280">${s.errors} err</span>
        </div>
      </div>`)
    .join("");

  // Event rows (last 100)
  const last100 = events.slice(-100).reverse();
  const rows = last100.map((e, i) => {
    const stats = agentStats.get(e.agentId ?? "");
    const color = stats?.color ?? "#888";
    const agentName = stats?.name ?? e.agentId ?? "?";
    const statusColor = e.status === "blocked" ? "#ef4444" : e.status === "flagged" ? "#f59e0b" : e.status === "error" ? "#6b7280" : "#22c55e";
    const rules = e.matched_rules?.map((r) => `<span style="background:#2d1b69;color:#c4b5fd;padding:1px 5px;border-radius:3px;font-size:10px">${esc(r)}</span>`).join(" ") ?? "";
    const time = e.timestamp.split("T")[1]?.slice(0, 12) ?? "";

    return `
      <tr style="cursor:pointer;border-bottom:1px solid #151515" onclick="toggleDetail(${i})">
        <td style="padding:6px 10px;font-family:monospace;font-size:11px;color:#666">${esc(time)}</td>
        <td style="padding:6px 10px"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};margin-right:6px"></span><span style="font-size:12px;color:${color}">${esc(agentName)}</span></td>
        <td style="padding:6px 10px;font-weight:600;font-size:12px">${esc(e.tool)}</td>
        <td style="padding:6px 10px;font-weight:600;color:${statusColor};font-size:12px">${e.status.toUpperCase()}</td>
        <td style="padding:6px 10px;font-family:monospace;font-size:11px">${e.risk_score.toFixed(2)}</td>
        <td style="padding:6px 10px">${rules}</td>
        <td style="padding:6px 10px;font-family:monospace;font-size:11px">${e.latency_ms}ms</td>
      </tr>
      <tr id="detail-${i}" style="display:none">
        <td colspan="7" style="padding:10px 16px;background:#0d0d14;border-bottom:1px solid #1a1a2e;font-size:12px;color:#888">
          ${e.reason ? `<div><strong>Reason:</strong> ${esc(e.reason)}</div>` : ""}
          ${e.reasoning ? `<div><strong>Reasoning:</strong> ${esc(e.reasoning)}</div>` : ""}
          ${e.session_flags?.length ? `<div><strong>Session Flags:</strong> ${e.session_flags.map((f) => `<span style="background:#422006;color:#fbbf24;padding:1px 5px;border-radius:3px;font-size:10px">${esc(f)}</span>`).join(" ")}</div>` : ""}
          ${e.scope_granted ? `<div><strong>Scope:</strong> <span style="background:#042f2e;color:#5eead4;padding:1px 5px;border-radius:3px;font-size:10px">${esc(e.scope_granted)}</span></div>` : ""}
          <div style="margin-top:6px;font-family:monospace;font-size:11px;color:#555;max-height:120px;overflow:auto">${esc(e.params)}</div>
        </td>
      </tr>`;
  }).join("");

  const total = events.length;
  const blocked = events.filter((e) => e.status === "blocked").length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Clampd Fleet Dashboard</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0a0a0a; color:#e0e0e0; }
  </style>
</head>
<body>
  <div style="padding:20px 32px;border-bottom:1px solid #222;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
    <h1 style="font-size:20px;color:#fff">Clampd Fleet</h1>
    <span style="padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600;background:#1a472a;color:#4ade80">${config.agents.length} AGENTS</span>
    <span style="font-size:13px;color:#888">${total} calls | ${blocked} blocked | ${total > 0 ? ((blocked / total) * 100).toFixed(1) : "0"}% threat rate</span>
    <div style="margin-left:auto">
      <button onclick="location.reload()" style="padding:5px 12px;border:1px solid #333;background:#111;color:#aaa;border-radius:4px;cursor:pointer;font-size:11px">Refresh</button>
    </div>
  </div>

  <div style="display:flex;gap:12px;padding:16px 32px;border-bottom:1px solid #222;flex-wrap:wrap;overflow-x:auto">
    ${agentCards}
  </div>

  <div style="max-height:600px;overflow-y:auto">
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead>
        <tr style="background:#111;position:sticky;top:0;z-index:1">
          <th style="text-align:left;padding:7px 10px;color:#666;font-size:10px;text-transform:uppercase">Time</th>
          <th style="text-align:left;padding:7px 10px;color:#666;font-size:10px;text-transform:uppercase">Agent</th>
          <th style="text-align:left;padding:7px 10px;color:#666;font-size:10px;text-transform:uppercase">Tool</th>
          <th style="text-align:left;padding:7px 10px;color:#666;font-size:10px;text-transform:uppercase">Status</th>
          <th style="text-align:left;padding:7px 10px;color:#666;font-size:10px;text-transform:uppercase">Risk</th>
          <th style="text-align:left;padding:7px 10px;color:#666;font-size:10px;text-transform:uppercase">Rules</th>
          <th style="text-align:left;padding:7px 10px;color:#666;font-size:10px;text-transform:uppercase">Latency</th>
        </tr>
      </thead>
      <tbody>
        ${rows || '<tr><td colspan="7" style="padding:48px;text-align:center;color:#333">No events yet. Connect Claude Desktop to the agent SSE endpoints.</td></tr>'}
      </tbody>
    </table>
  </div>

  <script>
    const evtSource = new EventSource('/events');
    let newCount = 0;
    evtSource.onmessage = function() {
      newCount++;
      const btn = document.querySelector('button');
      if (btn) btn.textContent = 'Refresh (' + newCount + ' new)';
    };
    function toggleDetail(idx) {
      const el = document.getElementById('detail-' + idx);
      if (el) el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
    }
  </script>
</body>
</html>`;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
