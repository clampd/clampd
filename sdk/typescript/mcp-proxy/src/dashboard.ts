/**
 * Live dashboard — serves an HTML page at GET / with a real-time event log
 * of all tool calls flowing through the proxy.
 *
 * Features:
 *   - Enriched event data (classification, session flags, intent labels, encodings)
 *   - Expandable detail rows with full gateway response data
 *   - Real-time risk trend SVG sparkline chart
 *   - Session summary panel with aggregated stats
 *   - Export (Copy Report / Download JSON)
 *   - Attack Demo panel with pre-built payloads
 *   - Status filter tabs (All / Allowed / Blocked / Flagged / Errors)
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { ProxyOptions } from "./proxy.js";

// ── Types ─────────────────────────────────────────────────────────────

export interface ProxyEvent {
  timestamp: string;
  tool: string;
  params: string;
  status: "allowed" | "blocked" | "flagged" | "error";
  risk_score: number;
  latency_ms: number;
  reason?: string;
  matched_rules?: string[];
  // Enriched fields from gateway response
  classification?: string;
  session_flags?: string[];
  intent_labels?: string[];
  encodings_detected?: string[];
  scope_granted?: string;
  action?: string;
  reasoning?: string;
  degraded_stages?: string[];
  scan_details?: {
    pii_found?: Array<{ pii_type: string; count: number }>;
    secrets_found?: Array<{ secret_type: string; count: number }>;
    input_risk?: number;
    output_risk?: number;
  };
  descriptor_hash?: string;
  scope_token?: string;
}

export interface SessionStats {
  toolCallCount: number;
  uniqueTools: string[];
  blockedCount: number;
  flaggedCount: number;
  totalRisk: number;
  firstCallAt: string;
  lastCallAt: string;
  rulesTriggered: Record<string, number>;
  piiDetected: boolean;
  secretsDetected: boolean;
}

// ── Dashboard HTML ────────────────────────────────────────────────────

function renderDashboard(events: ProxyEvent[], opts: ProxyOptions & { demoPanel?: boolean; sessionStats?: SessionStats }): string {
  const modeLabel = opts.dryRun ? "DRY-RUN" : "LIVE";
  const blocked = events.filter((e) => e.status === "blocked").length;
  const flagged = events.filter((e) => e.status === "flagged").length;
  const allowed = events.filter((e) => e.status === "allowed").length;
  const errors = events.filter((e) => e.status === "error").length;
  const total = events.length;
  const threatRate = total > 0 ? (((blocked + flagged) / total) * 100).toFixed(1) : "—";
  const avgLatency = total > 0 ? Math.round(events.reduce((s, e) => s + e.latency_ms, 0) / total) : 0;
  const totalRulesFired = events.reduce((s, e) => s + (e.matched_rules?.length ?? 0), 0);

  const last50 = events.slice(-50).reverse();

  // Build risk sparkline SVG
  const sparkline = renderSparkline(last50);

  // Build session summary
  const sessionHtml = opts.sessionStats ? renderSessionSummary(opts.sessionStats) : "";

  // Build event rows with expandable detail
  const rows = last50.map((e, i) => renderEventRow(e, i)).join("");

  // Build demo panel
  const demoHtml = opts.demoPanel ? renderDemoPanel(opts) : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Clampd MCP Proxy</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; }
    .header { padding: 20px 32px; border-bottom: 1px solid #222; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .header h1 { font-size: 20px; color: #fff; }
    .badge { padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .badge-live { background: #1a472a; color: #4ade80; }
    .badge-dryrun { background: #422006; color: #fbbf24; }
    .stats { display: flex; gap: 24px; padding: 14px 32px; border-bottom: 1px solid #222; flex-wrap: wrap; align-items: flex-end; }
    .stat { display: flex; flex-direction: column; }
    .stat-label { font-size: 10px; text-transform: uppercase; color: #555; letter-spacing: 0.5px; }
    .stat-value { font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }
    .stat-allowed { color: #22c55e; }
    .stat-blocked { color: #ef4444; }
    .stat-flagged { color: #f59e0b; }
    .stat-error { color: #6b7280; }
    .stat-sep { width: 1px; height: 32px; background: #222; margin: 0 4px; }
    .info { padding: 10px 32px; font-size: 12px; color: #555; border-bottom: 1px solid #222; display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
    .info span { color: #888; }
    .filters { display: flex; gap: 4px; padding: 12px 32px; border-bottom: 1px solid #222; }
    .filter-btn { padding: 5px 14px; border: 1px solid #333; background: transparent; color: #888; border-radius: 4px; cursor: pointer; font-size: 12px; font-family: inherit; }
    .filter-btn:hover { border-color: #555; color: #ccc; }
    .filter-btn.active { background: #1a1a2e; border-color: #6366f1; color: #a5b4fc; }
    .sparkline-container { padding: 8px 32px; border-bottom: 1px solid #222; }
    .session-panel { padding: 14px 32px; border-bottom: 1px solid #222; display: flex; gap: 24px; flex-wrap: wrap; align-items: flex-start; }
    .session-block { display: flex; flex-direction: column; gap: 4px; }
    .session-title { font-size: 10px; text-transform: uppercase; color: #555; letter-spacing: 0.5px; }
    .session-val { font-size: 13px; color: #ccc; font-family: 'SF Mono', 'Fira Code', monospace; }
    .badge-sm { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 500; margin: 1px 2px; }
    .badge-rule { background: #2d1b69; color: #c4b5fd; }
    .badge-label { background: #1e3a5f; color: #7dd3fc; }
    .badge-flag { background: #422006; color: #fbbf24; }
    .badge-encoding { background: #431407; color: #fb923c; }
    .badge-scope { background: #042f2e; color: #5eead4; }
    .badge-degraded { background: #450a0a; color: #fca5a5; }
    .badge-pii { background: #4a1d96; color: #d8b4fe; }
    .badge-secret { background: #7f1d1d; color: #fca5a5; }
    .table-wrap { max-height: 500px; overflow-y: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 7px 12px; background: #111; color: #666; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; z-index: 1; }
    td { padding: 7px 12px; border-bottom: 1px solid #151515; vertical-align: top; }
    tr.event-row { cursor: pointer; transition: background 0.1s; }
    tr.event-row:hover { background: #111; }
    .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 11px; }
    .params-cell { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #666; }
    .status-allowed { color: #22c55e; font-weight: 600; }
    .status-blocked { color: #ef4444; font-weight: 600; }
    .status-flagged { color: #f59e0b; font-weight: 600; }
    .status-error { color: #6b7280; font-weight: 600; }
    .detail-row { display: none; }
    .detail-row.open { display: table-row; }
    .detail-cell { padding: 12px 16px; background: #0d0d14; border-bottom: 1px solid #1a1a2e; }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 24px; }
    .detail-section { display: flex; flex-direction: column; gap: 3px; }
    .detail-label { font-size: 10px; text-transform: uppercase; color: #444; letter-spacing: 0.3px; }
    .detail-val { font-size: 12px; color: #bbb; }
    .detail-params { max-height: 180px; overflow: auto; background: #080810; border: 1px solid #1a1a2e; border-radius: 4px; padding: 8px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 11px; color: #888; white-space: pre-wrap; word-break: break-all; margin-top: 6px; }
    .empty { padding: 48px; text-align: center; color: #333; }
    .actions { margin-left: auto; display: flex; gap: 8px; }
    .btn { padding: 5px 12px; border: 1px solid #333; background: #111; color: #aaa; border-radius: 4px; cursor: pointer; font-size: 11px; font-family: inherit; transition: all 0.15s; }
    .btn:hover { background: #1a1a2e; border-color: #6366f1; color: #c4b5fd; }
    .btn-copy.copied { background: #1a472a; border-color: #22c55e; color: #4ade80; }
    .demo-panel { padding: 16px 32px; border-bottom: 1px solid #222; }
    .demo-title { font-size: 13px; font-weight: 600; color: #a5b4fc; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
    .demo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; }
    .demo-card { padding: 8px 12px; border: 1px solid #222; border-radius: 6px; cursor: pointer; transition: all 0.15s; }
    .demo-card:hover { border-color: #6366f1; background: #0d0d14; }
    .demo-card.running { opacity: 0.5; pointer-events: none; }
    .demo-card-name { font-size: 12px; font-weight: 600; color: #ccc; }
    .demo-card-desc { font-size: 10px; color: #555; margin-top: 2px; }
    .demo-card-result { font-size: 10px; margin-top: 4px; font-family: 'SF Mono', monospace; }
    .class-malicious { color: #ef4444; }
    .class-suspicious { color: #f59e0b; }
    .class-benign { color: #22c55e; }
    @media (max-width: 768px) {
      .stats { gap: 12px; padding: 10px 16px; }
      .stat-value { font-size: 18px; }
      .info, .filters, .session-panel, .demo-panel, .sparkline-container { padding-left: 16px; padding-right: 16px; }
      .header { padding: 16px; }
      .detail-grid { grid-template-columns: 1fr; }
      .demo-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Clampd MCP Proxy</h1>
    <span class="badge ${modeLabel === "LIVE" ? "badge-live" : "badge-dryrun"}">${modeLabel}</span>
    <div class="actions">
      <button class="btn" onclick="location.reload()" id="refreshBtn">Refresh</button>
      <button class="btn btn-copy" onclick="copyReport()" id="copyBtn">Copy Report</button>
      <button class="btn" onclick="downloadJSON()">Download JSON</button>
    </div>
  </div>
  <div class="stats">
    <div class="stat">
      <span class="stat-label">Allowed</span>
      <span class="stat-value stat-allowed">${allowed}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Blocked</span>
      <span class="stat-value stat-blocked">${blocked}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Flagged</span>
      <span class="stat-value stat-flagged">${flagged}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Errors</span>
      <span class="stat-value stat-error">${errors}</span>
    </div>
    <div class="stat-sep"></div>
    <div class="stat">
      <span class="stat-label">Total</span>
      <span class="stat-value">${total}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Threat Rate</span>
      <span class="stat-value stat-blocked">${threatRate}${total > 0 ? "%" : ""}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Rules Fired</span>
      <span class="stat-value" style="color:#c4b5fd">${totalRulesFired}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Avg Latency</span>
      <span class="stat-value" style="color:#888">${avgLatency}ms</span>
    </div>
  </div>
  <div class="info">
    Gateway: <span>${escapeHtml(opts.gatewayUrl)}</span> &nbsp;|&nbsp;
    Agent: <span>${escapeHtml(opts.agentId)}</span> &nbsp;|&nbsp;
    Port: <span>${opts.port}</span>
  </div>
  ${sessionHtml}
  ${sparkline}
  <div class="filters">
    <button class="filter-btn active" onclick="filterEvents('all')">All (${total})</button>
    <button class="filter-btn" onclick="filterEvents('allowed')">Allowed (${allowed})</button>
    <button class="filter-btn" onclick="filterEvents('blocked')">Blocked (${blocked})</button>
    <button class="filter-btn" onclick="filterEvents('flagged')">Flagged (${flagged})</button>
    <button class="filter-btn" onclick="filterEvents('error')">Errors (${errors})</button>
  </div>
  ${demoHtml}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Tool</th>
          <th>Status</th>
          <th>Risk</th>
          <th>Rules</th>
          <th>Latency</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody id="eventBody">
        ${rows || '<tr><td colspan="7" class="empty">No tool calls yet. Connect Claude Desktop to http://localhost:' + opts.port + '/sse</td></tr>'}
      </tbody>
    </table>
  </div>
  <script>
    // SSE — track new event count, show badge on refresh button
    const evtSource = new EventSource('/events');
    let newCount = 0;
    evtSource.onmessage = function() {
      newCount++;
      const btn = document.getElementById('refreshBtn');
      if (btn) btn.textContent = 'Refresh (' + newCount + ' new)';
    };

    // Filter events by status
    function filterEvents(status) {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      document.querySelectorAll('.event-row').forEach(row => {
        const detail = row.nextElementSibling;
        if (status === 'all' || row.dataset.status === status) {
          row.style.display = '';
          // keep detail state
        } else {
          row.style.display = 'none';
          if (detail && detail.classList.contains('detail-row')) detail.style.display = 'none';
        }
      });
    }

    // Toggle detail row
    function toggleDetail(idx) {
      const detail = document.getElementById('detail-' + idx);
      if (detail) detail.classList.toggle('open');
    }

    // Copy markdown report
    function copyReport() {
      const report = document.getElementById('reportData').textContent;
      navigator.clipboard.writeText(report).then(() => {
        const btn = document.getElementById('copyBtn');
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy Report'; btn.classList.remove('copied'); }, 2000);
      });
    }

    // Download JSON
    function downloadJSON() {
      const data = document.getElementById('jsonData').textContent;
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'clampd-proxy-events-' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.json';
      a.click();
      URL.revokeObjectURL(url);
    }

    // Demo attack buttons
    function runDemo(attackId) {
      const card = document.getElementById('demo-' + attackId);
      if (!card) return;
      card.classList.add('running');
      fetch('/demo/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_id: attackId }),
      })
      .then(r => r.json())
      .then(result => {
        card.classList.remove('running');
        const resultEl = card.querySelector('.demo-card-result');
        if (resultEl) {
          const color = result.status === 'blocked' ? '#ef4444' : result.status === 'allowed' ? '#22c55e' : '#6b7280';
          resultEl.innerHTML = '<span style="color:' + color + '">' + result.status.toUpperCase() + '</span> risk=' + (result.risk_score || 0).toFixed(2) + (result.matched_rules?.length ? ' [' + result.matched_rules.join(', ') + ']' : '');
        }
        // Update refresh button badge
        newCount++;
        const rbtn = document.getElementById('refreshBtn');
        if (rbtn) rbtn.textContent = 'Refresh (' + newCount + ' new)';
      })
      .catch(() => { card.classList.remove('running'); });
    }
  </script>
  <div style="display:none">
    <pre id="reportData">${escapeHtml(generateReport(events, opts))}</pre>
    <pre id="jsonData">${escapeHtml(JSON.stringify(events, null, 2))}</pre>
  </div>
</body>
</html>`;
}

// ── Event Row (expandable) ───────────────────────────────────────────

function renderEventRow(e: ProxyEvent, idx: number): string {
  const statusClass = e.status === "blocked" ? "status-blocked" : e.status === "flagged" ? "status-flagged" : e.status === "error" ? "status-error" : "status-allowed";
  const rules = e.matched_rules?.map((r) => `<span class="badge-sm badge-rule">${escapeHtml(r)}</span>`).join("") ?? "-";
  const time = e.timestamp.split("T")[1]?.slice(0, 12) ?? e.timestamp;

  // Detail panel content
  const classColor = e.classification === "Malicious" ? "class-malicious" : e.classification === "Suspicious" ? "class-suspicious" : "class-benign";

  const detailSections: string[] = [];

  if (e.classification) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Classification</span><span class="detail-val ${classColor}">${escapeHtml(e.classification)}</span></div>`);
  }
  if (e.action) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Action</span><span class="detail-val">${escapeHtml(e.action)}</span></div>`);
  }
  if (e.reasoning) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Reasoning</span><span class="detail-val">${escapeHtml(e.reasoning)}</span></div>`);
  }
  if (e.intent_labels?.length) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Intent Labels</span><span class="detail-val">${e.intent_labels.map((l) => `<span class="badge-sm badge-label">${escapeHtml(l)}</span>`).join("")}</span></div>`);
  }
  if (e.session_flags?.length) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Session Flags</span><span class="detail-val">${e.session_flags.map((f) => `<span class="badge-sm badge-flag">${escapeHtml(f)}</span>`).join("")}</span></div>`);
  }
  if (e.encodings_detected?.length) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Encodings Detected</span><span class="detail-val">${e.encodings_detected.map((enc) => `<span class="badge-sm badge-encoding">${escapeHtml(enc)}</span>`).join("")}</span></div>`);
  }
  if (e.scope_granted) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Scope Granted</span><span class="detail-val"><span class="badge-sm badge-scope">${escapeHtml(e.scope_granted)}</span></span></div>`);
  }
  if (e.degraded_stages?.length) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Degraded Stages</span><span class="detail-val">${e.degraded_stages.map((s) => `<span class="badge-sm badge-degraded">${escapeHtml(s)}</span>`).join("")}</span></div>`);
  }
  if (e.scan_details?.pii_found?.length) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">PII Found</span><span class="detail-val">${e.scan_details.pii_found.map((p) => `<span class="badge-sm badge-pii">${escapeHtml(p.pii_type)} (${p.count})</span>`).join("")}</span></div>`);
  }
  if (e.scan_details?.secrets_found?.length) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Secrets Found</span><span class="detail-val">${e.scan_details.secrets_found.map((s) => `<span class="badge-sm badge-secret">${escapeHtml(s.secret_type)} (${s.count})</span>`).join("")}</span></div>`);
  }
  if (e.descriptor_hash) {
    detailSections.push(`<div class="detail-section"><span class="detail-label">Descriptor Hash</span><span class="detail-val mono">${escapeHtml(e.descriptor_hash.slice(0, 16))}...</span></div>`);
  }

  const reasonText = e.reason ? escapeHtml(e.reason.length > 60 ? e.reason.slice(0, 60) + "..." : e.reason) : "-";

  const hasDetail = detailSections.length > 0 || e.params.length > 5;
  const expandIcon = hasDetail ? `<span style="color:#444;font-size:10px">&#9654;</span> ` : "";

  // Pretty-print params for detail view
  let prettyParams = e.params;
  try {
    prettyParams = JSON.stringify(JSON.parse(e.params), null, 2);
  } catch { /* keep as-is */ }

  return `
    <tr class="event-row" data-status="${e.status}" onclick="toggleDetail(${idx})">
      <td class="mono">${expandIcon}${escapeHtml(time)}</td>
      <td><strong>${escapeHtml(e.tool)}</strong></td>
      <td class="${statusClass}">${e.status.toUpperCase()}</td>
      <td class="mono">${e.risk_score.toFixed(2)}</td>
      <td>${rules}</td>
      <td class="mono">${e.latency_ms}ms</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#888">${reasonText}</td>
    </tr>
    <tr class="detail-row" id="detail-${idx}">
      <td colspan="7" class="detail-cell">
        <div class="detail-grid">${detailSections.join("")}</div>
        ${e.params.length > 2 ? `<div class="detail-params">${escapeHtml(prettyParams)}</div>` : ""}
      </td>
    </tr>`;
}

// ── Risk Sparkline SVG ───────────────────────────────────────────────

function renderSparkline(events: ProxyEvent[]): string {
  if (events.length === 0) return "";

  const width = 800;
  const height = 60;
  const padding = 4;
  const count = Math.min(events.length, 50);
  const data = events.slice(0, count).reverse(); // oldest first for chart

  const stepX = (width - padding * 2) / Math.max(count - 1, 1);

  let points = "";
  let dots = "";
  for (let i = 0; i < data.length; i++) {
    const x = padding + i * stepX;
    const y = height - padding - data[i].risk_score * (height - padding * 2);
    points += `${x},${y} `;

    const color = data[i].status === "blocked" ? "#ef4444" : data[i].risk_score > 0.85 ? "#ef4444" : data[i].risk_score > 0.5 ? "#f59e0b" : "#22c55e";
    const r = data[i].status === "blocked" ? 4 : 3;
    dots += `<circle cx="${x}" cy="${y}" r="${r}" fill="${color}" opacity="0.8"/>`;

    if (data[i].status === "blocked") {
      // X marker for blocked
      dots += `<line x1="${x - 3}" y1="${y - 3}" x2="${x + 3}" y2="${y + 3}" stroke="#ef4444" stroke-width="1.5"/>`;
      dots += `<line x1="${x + 3}" y1="${y - 3}" x2="${x - 3}" y2="${y + 3}" stroke="#ef4444" stroke-width="1.5"/>`;
    }
  }

  return `<div class="sparkline-container">
    <svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" preserveAspectRatio="none">
      <rect width="${width}" height="${height}" fill="#050508" rx="4"/>
      <line x1="${padding}" y1="${height - padding - 0.5 * (height - padding * 2)}" x2="${width - padding}" y2="${height - padding - 0.5 * (height - padding * 2)}" stroke="#1a1a1a" stroke-width="0.5" stroke-dasharray="4"/>
      <line x1="${padding}" y1="${height - padding - 0.85 * (height - padding * 2)}" x2="${width - padding}" y2="${height - padding - 0.85 * (height - padding * 2)}" stroke="#2a1515" stroke-width="0.5" stroke-dasharray="4"/>
      <polyline points="${points}" fill="none" stroke="#6366f1" stroke-width="1.5" opacity="0.5"/>
      ${dots}
      <text x="${padding}" y="10" fill="#333" font-size="8" font-family="sans-serif">1.0</text>
      <text x="${padding}" y="${height - 2}" fill="#333" font-size="8" font-family="sans-serif">0.0</text>
    </svg>
  </div>`;
}

// ── Session Summary ──────────────────────────────────────────────────

function renderSessionSummary(stats: SessionStats): string {
  const duration = stats.firstCallAt && stats.lastCallAt
    ? formatDuration(new Date(stats.lastCallAt).getTime() - new Date(stats.firstCallAt).getTime())
    : "—";
  const avgRisk = stats.toolCallCount > 0 ? (stats.totalRisk / stats.toolCallCount).toFixed(2) : "0.00";
  const topRules = Object.entries(stats.rulesTriggered)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([rule, count]) => `<span class="badge-sm badge-rule">${escapeHtml(rule)} (${count})</span>`)
    .join("");

  const indicators: string[] = [];
  if (stats.piiDetected) indicators.push(`<span class="badge-sm badge-pii">PII Detected</span>`);
  if (stats.secretsDetected) indicators.push(`<span class="badge-sm badge-secret">Secrets Detected</span>`);

  return `<div class="session-panel">
    <div class="session-block"><span class="session-title">Session Duration</span><span class="session-val">${duration}</span></div>
    <div class="session-block"><span class="session-title">Avg Risk</span><span class="session-val">${avgRisk}</span></div>
    <div class="session-block"><span class="session-title">Unique Tools (${stats.uniqueTools.length})</span><span class="session-val">${stats.uniqueTools.slice(0, 8).map((t) => escapeHtml(t)).join(", ") || "—"}</span></div>
    <div class="session-block"><span class="session-title">Top Rules</span><span class="session-val">${topRules || "—"}</span></div>
    ${indicators.length ? `<div class="session-block"><span class="session-title">Alerts</span><span class="session-val">${indicators.join(" ")}</span></div>` : ""}
  </div>`;
}

// ── Demo Panel ───────────────────────────────────────────────────────

function renderDemoPanel(opts: ProxyOptions): string {
  const attacks = [
    { id: "sql_injection", name: "SQL Injection", desc: 'DROP TABLE users via database.query' },
    { id: "path_traversal", name: "Path Traversal", desc: '../../etc/passwd via read_file' },
    { id: "prompt_injection", name: "Prompt Injection", desc: 'IGNORE ALL INSTRUCTIONS via write_file' },
    { id: "ssrf", name: "SSRF", desc: '169.254.169.254 metadata via http_request' },
    { id: "reverse_shell", name: "Reverse Shell", desc: '#!/bin/bash >& /dev/tcp/ via write_file' },
    { id: "schema_injection", name: "Schema Injection", desc: '<functions> XML tag injection' },
    { id: "encoded_attack", name: "Encoded Attack", desc: 'Base64-encoded rm -rf /' },
    { id: "safe_call", name: "Safe Call", desc: 'Normal read_file /tmp/report.txt' },
  ];

  const cards = attacks.map((a) => `
    <div class="demo-card" id="demo-${a.id}" onclick="runDemo('${a.id}')">
      <div class="demo-card-name">${escapeHtml(a.name)}</div>
      <div class="demo-card-desc">${escapeHtml(a.desc)}</div>
      <div class="demo-card-result"></div>
    </div>`).join("");

  return `<div class="demo-panel">
    <div class="demo-title">Demo Attacks <span class="badge badge-dryrun" style="font-size:9px">click to test</span></div>
    <div class="demo-grid">${cards}</div>
  </div>`;
}

// ── Report Generation ────────────────────────────────────────────────

function generateReport(events: ProxyEvent[], opts: ProxyOptions): string {
  const blocked = events.filter((e) => e.status === "blocked");
  const flagged = events.filter((e) => e.status === "flagged");
  const total = events.length;
  const avgLatency = total > 0 ? Math.round(events.reduce((s, e) => s + e.latency_ms, 0) / total) : 0;
  const threatRate = total > 0 ? (((blocked.length + flagged.length) / total) * 100).toFixed(1) : "0";

  // Count rules
  const ruleCounts: Record<string, number> = {};
  for (const e of events) {
    for (const r of e.matched_rules ?? []) {
      ruleCounts[r] = (ruleCounts[r] ?? 0) + 1;
    }
  }
  const ruleRows = Object.entries(ruleCounts)
    .sort(([, a], [, b]) => b - a)
    .map(([rule, count]) => `| ${rule} | ${count} |`)
    .join("\n");

  const blockedRows = blocked
    .slice(0, 20)
    .map((e) => {
      const time = e.timestamp.split("T")[1]?.slice(0, 8) ?? "";
      const rules = e.matched_rules?.join(", ") ?? "";
      return `| ${time} | ${e.tool} | ${e.risk_score.toFixed(2)} | ${rules} | ${(e.reason ?? "").slice(0, 50)} |`;
    })
    .join("\n");

  return `# Clampd MCP Proxy Security Report
**Agent:** ${opts.agentId} | **Gateway:** ${opts.gatewayUrl}
**Generated:** ${new Date().toISOString()}

## Summary
- Allowed: ${total - blocked.length - flagged.length} | Blocked: ${blocked.length} | Flagged: ${flagged.length}
- Threat Rate: ${threatRate}%
- Avg Latency: ${avgLatency}ms
- Total Calls: ${total}

## Rules Triggered
| Rule | Count |
|------|-------|
${ruleRows || "| — | — |"}

## Blocked Calls
| Time | Tool | Risk | Rules | Reason |
|------|------|------|-------|--------|
${blockedRows || "| — | — | — | — | — |"}
`;
}

// ── Utilities ─────────────────────────────────────────────────────────

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ${secs % 60}s`;
  return `${Math.floor(mins / 60)}h ${mins % 60}m`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Serve ─────────────────────────────────────────────────────────────

export function serveDashboard(
  _req: IncomingMessage,
  res: ServerResponse,
  events: ProxyEvent[],
  opts: ProxyOptions & { demoPanel?: boolean; sessionStats?: SessionStats },
): void {
  const html = renderDashboard(events, opts);
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-cache",
  });
  res.end(html);
}
