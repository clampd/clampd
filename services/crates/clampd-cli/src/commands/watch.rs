#[cfg(feature = "tui")]
use anyhow::Result;
#[cfg(feature = "tui")]
use uuid::Uuid;
#[cfg(feature = "tui")]
use crate::state::AppState;

#[cfg(feature = "tui")]
pub async fn run(state: &AppState, agent_filter: Option<Uuid>, plan_info: Option<&str>) -> Result<()> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyModifiers},
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
        ExecutableCommand,
    };
    use futures::{SinkExt, StreamExt};
    use ratatui::prelude::*;
    use ratatui::widgets::*;
    use std::collections::VecDeque;
    use std::io::stdout;
    use tokio::sync::mpsc;

    // ── Data types ──────────────────────────────────────────

    #[derive(Clone)]
    struct ServiceInfo {
        name: String,
        healthy: bool,
        #[allow(dead_code)]
        status: String,
        latency_ms: u32,
    }

    #[derive(Clone)]
    struct AgentInfo {
        id: Uuid,
        name: String,
        state: String,
        framework: Option<String>,
        #[allow(dead_code)]
        description: Option<String>,
        declared_purpose: Option<String>,
        auth_mode: Option<String>,
        kill_reason: Option<String>,
    }

    #[derive(Clone)]
    struct EventLine {
        timestamp: String,
        agent_name: String,
        tool_name: String,
        #[allow(dead_code)]
        tool_action: String,
        params_summary: String,
        risk_score: f64,
        classification: String,
        blocked: bool,
        denial_reason: Option<String>,
        pii_detected: bool,
        encodings: Vec<String>,
        #[allow(dead_code)]
        policy_action: String,
        #[allow(dead_code)]
        latency_ms: u32,
        raw_subject: String,
        raw_detail: Option<String>,
    }

    impl EventLine {
        fn from_risk_ws(payload: &serde_json::Value) -> Self {
            let now = chrono::Local::now().format("%H:%M:%S").to_string();
            let msg_type = payload.get("msg_type")
                .and_then(|v| v.as_str()).unwrap_or("risk_update");
            let agent_id = payload.get("agent_id")
                .and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let tool_name = payload.get("tool_name")
                .and_then(|v| v.as_str()).unwrap_or("").to_string();
            let ema_score = payload.get("ema_score")
                .and_then(|v| v.as_f64()).unwrap_or(0.0);
            let classification = payload.get("classification")
                .and_then(|v| v.as_str()).unwrap_or("").to_string();

            let blocked = classification == "critical" || classification == "auto_killed";
            let is_alert = msg_type == "correlation_alert";

            EventLine {
                timestamp: now,
                agent_name: agent_id,
                tool_name: tool_name.clone(),
                tool_action: String::new(),
                params_summary: if is_alert {
                    // For correlation alerts, tool_name holds the description
                    tool_name
                } else {
                    String::new()
                },
                risk_score: ema_score,
                classification,
                blocked,
                denial_reason: None,
                pii_detected: false,
                encodings: vec![],
                policy_action: String::new(),
                latency_ms: 0,
                raw_subject: msg_type.to_string(),
                raw_detail: if is_alert { Some("CORRELATION".to_string()) } else { None },
            }
        }
    }

    enum WatchMsg {
        RiskEvent { payload: serde_json::Value },
        StateUpdate { services: Vec<ServiceInfo>, agents: Vec<AgentInfo> },
        Tick,
    }

    struct WatchApp {
        services: Vec<ServiceInfo>,
        agents: Vec<AgentInfo>,
        events: VecDeque<EventLine>,
        selected_agent: usize,
        show_confirm_kill: bool,
        show_confirm_suspend: bool,
        show_help: bool,
        event_count: u64,
        blocked_count: u64,
    }

    impl WatchApp {
        fn new() -> Self {
            Self {
                services: Vec::new(), agents: Vec::new(),
                events: VecDeque::with_capacity(500),
                selected_agent: 0, show_confirm_kill: false,
                show_confirm_suspend: false, show_help: false,
                event_count: 0, blocked_count: 0,
            }
        }

        fn push_risk_event(&mut self, payload: &serde_json::Value) {
            let event = EventLine::from_risk_ws(payload);
            self.event_count += 1;
            if event.blocked { self.blocked_count += 1; }
            self.events.push_front(event);
            if self.events.len() > 500 { self.events.pop_back(); }
        }

        fn push_local_event(&mut self, subject: &str, agent_name: &str, detail: &str) {
            let now = chrono::Local::now().format("%H:%M:%S").to_string();
            let event = EventLine {
                timestamp: now,
                agent_name: agent_name.to_string(),
                tool_name: String::new(),
                tool_action: String::new(),
                params_summary: String::new(),
                risk_score: 0.0,
                classification: String::new(),
                blocked: false,
                denial_reason: None,
                pii_detected: false,
                encodings: vec![],
                policy_action: String::new(),
                latency_ms: 0,
                raw_subject: subject.to_string(),
                raw_detail: Some(detail.to_string()),
            };
            self.event_count += 1;
            self.events.push_front(event);
            if self.events.len() > 500 { self.events.pop_back(); }
        }

        fn selected_agent_info(&self) -> Option<&AgentInfo> {
            self.agents.get(self.selected_agent)
        }
    }

    // ── Channel setup ───────────────────────────────────────

    let (tx, mut rx) = mpsc::channel::<WatchMsg>(256);

    // ── Task 1: WebSocket subscriber to ag-risk ─────────────
    // Replaces direct NATS subscription. ag-risk broadcasts real-time
    // risk_update and correlation_alert messages over WS.

    let ws_tx = tx.clone();
    let ws_handle = {
        let risk_url = state.config.services.risk_url.clone();
        tokio::spawn(async move {
            // Convert gRPC URL to WS URL for ag-risk WebSocket port (8081)
            // risk_url is typically http://127.0.0.1:50056 (gRPC), WS is on port 8081
            let ws_host = risk_url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .split(':')
                .next()
                .unwrap_or("127.0.0.1");
            let ws_url = format!("ws://{}:8081/ws/risk", ws_host);

            // Build JWT for WS authentication
            let jwt_token = match build_ws_jwt() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Failed to build JWT for risk WS: {e}");
                    // Fall back to polling-only mode (no real-time events)
                    return;
                }
            };

            let url_with_token = format!("{}?token={}", ws_url, jwt_token);

            loop {
                match tokio_tungstenite::connect_async(&url_with_token).await {
                    Ok((ws_stream, _)) => {
                        let (_write, mut read) = ws_stream.split();
                        while let Some(msg) = read.next().await {
                            match msg {
                                Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                                    if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&text) {
                                        let _ = ws_tx.send(WatchMsg::RiskEvent { payload }).await;
                                    }
                                }
                                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => break,
                                Err(_) => break,
                                _ => {}
                            }
                        }
                    }
                    Err(_) => {}
                }
                // Reconnect after 3 seconds on disconnect
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        })
    };

    // ── Task 2: Periodic poller via Dashboard API ───────────
    // Replaces direct Postgres queries for agents and service health.

    let poll_tx = tx.clone();
    let poll_handle = {
        let dashboard_url = state.config.dashboard_url().to_string();
        let org_id = state.config.org_id().to_string();
        let gateway_url = state.config.services.gateway_url.clone();
        let api_token = state.config.api_token().to_string();
        let agent_filter_clone = agent_filter;
        tokio::spawn(async move {
            let http = reqwest::Client::new();
            loop {
                // Fetch cluster health via Dashboard API
                let mut all_services: Vec<ServiceInfo> = Vec::new();

                // Check Dashboard API health
                let mut dashboard_req = http
                    .get(format!("{}/v1/health", dashboard_url))
                    .timeout(std::time::Duration::from_secs(3));
                if !api_token.is_empty() {
                    dashboard_req = dashboard_req.header("Authorization", format!("Bearer {}", api_token));
                }
                match dashboard_req.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        all_services.push(ServiceInfo {
                            name: "dashboard-api".to_string(),
                            healthy: true,
                            status: "ok".to_string(),
                            latency_ms: 0,
                        });
                    }
                    _ => {
                        all_services.push(ServiceInfo {
                            name: "dashboard-api".to_string(),
                            healthy: false,
                            status: "error".to_string(),
                            latency_ms: 0,
                        });
                    }
                }

                // Check gateway health
                if let Ok(resp) = http
                    .get(format!("{}/health", gateway_url))
                    .timeout(std::time::Duration::from_secs(3))
                    .send().await
                {
                    all_services.push(ServiceInfo {
                        name: "ag-gateway".to_string(),
                        healthy: resp.status().is_success(),
                        status: if resp.status().is_success() { "ok".to_string() } else { "error".to_string() },
                        latency_ms: 0,
                    });
                }

                // Fetch agents via Dashboard API: GET /v1/orgs/:id/agents
                let agents: Vec<AgentInfo> = {
                    let agents_url = format!("{}/v1/orgs/{}/agents", dashboard_url, org_id);
                    let mut req = http.get(&agents_url)
                        .timeout(std::time::Duration::from_secs(5));
                    if !api_token.is_empty() {
                        req = req.header("Authorization", format!("Bearer {}", api_token));
                    }
                    match req.send().await {
                        Ok(resp) if resp.status().is_success() => {
                            match resp.json::<Vec<serde_json::Value>>().await {
                                Ok(items) => {
                                    items.into_iter().filter_map(|v| {
                                        let id_str = v.get("id").and_then(|x| x.as_str())?;
                                        let id = id_str.parse::<Uuid>().ok()?;

                                        // Apply agent filter if specified
                                        if let Some(filter_id) = agent_filter_clone {
                                            if id != filter_id { return None; }
                                        }

                                        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        let st = v.get("state").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
                                        let framework = v.get("framework").and_then(|x| x.as_str()).map(String::from);
                                        let description = v.get("description").and_then(|x| x.as_str()).map(String::from);
                                        let declared_purpose = v.get("declaredPurpose")
                                            .or_else(|| v.get("declared_purpose"))
                                            .and_then(|x| x.as_str()).map(String::from);
                                        let auth_mode = v.get("authMode")
                                            .or_else(|| v.get("auth_mode"))
                                            .and_then(|x| x.as_str()).map(String::from);
                                        let kill_reason = v.get("killReason")
                                            .or_else(|| v.get("kill_reason"))
                                            .and_then(|x| x.as_str()).map(String::from);

                                        Some(AgentInfo {
                                            id, name, state: st, framework, description,
                                            declared_purpose, auth_mode, kill_reason,
                                        })
                                    }).collect()
                                }
                                Err(_) => vec![],
                            }
                        }
                        _ => vec![],
                    }
                };

                let _ = poll_tx.send(WatchMsg::StateUpdate { services: all_services, agents }).await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        })
    };

    // ── Task 3: Tick timer ──────────────────────────────────

    let tick_tx = tx.clone();
    let tick_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            if tick_tx.send(WatchMsg::Tick).await.is_err() { break; }
        }
    });

    // ── Terminal setup ──────────────────────────────────────

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut app = WatchApp::new();

    // Keep references to Dashboard API for kill/revive actions
    let action_client = reqwest::Client::new();
    let action_dashboard_url = state.config.dashboard_url().to_string();
    let action_org_id = state.config.org_id().to_string();
    let action_api_token = state.config.api_token().to_string();

    // ── Main render + event loop ────────────────────────────

    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                WatchMsg::RiskEvent { payload } => app.push_risk_event(&payload),
                WatchMsg::StateUpdate { services, agents } => {
                    app.services = services;
                    app.agents = agents;
                }
                WatchMsg::Tick => {}
            }
        }

        terminal.draw(|frame| {
            let area = frame.area();

            // ── Black + Red theme ─────────────────────────────
            let bg = Color::Black;
            let bright = Color::Rgb(255, 255, 255);    // pure white - headlines, selected
            let text = Color::Rgb(220, 220, 220);      // light text - primary content
            let muted = Color::Rgb(140, 140, 140);     // dim labels, metadata
            let border_c = Color::Rgb(100, 100, 100);  // borders
            let red = Color::Rgb(255, 60, 60);         // danger, blocked, kill
            let red_bright = Color::Rgb(255, 100, 100);// lighter red for denial reasons
            let amber = Color::Rgb(255, 180, 0);       // warnings, suspended
            let green = Color::Rgb(80, 220, 80);       // active, allow

            // ── Help overlay ─────────────────────────────────
            if app.show_help {
                let help_lines = vec![
                    Line::from(Span::styled("  KEYBINDINGS", Style::default().fg(red).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from(vec![Span::styled("  j/k, Up/Down  ", Style::default().fg(bright)), Span::styled("Navigate agents", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  K             ", Style::default().fg(red).add_modifier(Modifier::BOLD)), Span::styled("Kill selected agent", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  S             ", Style::default().fg(amber)), Span::styled("Suspend selected agent", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  R             ", Style::default().fg(green)), Span::styled("Resume/revive agent", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  ?             ", Style::default().fg(bright)), Span::styled("Toggle this help", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  q / Esc       ", Style::default().fg(muted)), Span::styled("Quit", Style::default().fg(text))]),
                    Line::from(""),
                    Line::from(Span::styled("  SECURITY FEATURES", Style::default().fg(red).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from(vec![Span::styled("  [PII]  ", Style::default().fg(red).add_modifier(Modifier::BOLD)), Span::styled("PII detection - email, SSN, credit card, phone regex scan", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  [ENC]  ", Style::default().fg(amber).add_modifier(Modifier::BOLD)), Span::styled("Encoding anomaly - base64, URL-encode, hex, unicode obfuscation (+0.15 risk each)", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  [SES]  ", Style::default().fg(bright)), Span::styled("Session tracking - cross-request correlation, 15-min windows, risk accumulation", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  [ANO]  ", Style::default().fg(bright)), Span::styled("Anomaly detection - velocity, scope, time-of-day, volume baselines", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  [POL]  ", Style::default().fg(bright)), Span::styled("Policy engine - DSL + OPA/Rego rules, intent classification", Style::default().fg(text))]),
                    Line::from(vec![Span::styled("  [KILL] ", Style::default().fg(red).add_modifier(Modifier::BOLD)), Span::styled("Kill switch - < 50ms agent termination, token revocation, session purge", Style::default().fg(text))]),
                    Line::from(""),
                    Line::from(Span::styled("  Press ? to close", Style::default().fg(muted))),
                ];
                let help_block = Block::default()
                    .title(Span::styled(" CLAMPD HELP ", Style::default().fg(red).add_modifier(Modifier::BOLD)))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(red));
                let help_para = Paragraph::new(help_lines).block(help_block).style(Style::default().bg(bg));
                frame.render_widget(Clear, area);
                frame.render_widget(help_para, area);
                return;
            }

            // Main layout
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(std::cmp::max(8, (app.services.len() as u16 + app.agents.len() as u16).max(6) + 2).min(14)),
                    Constraint::Min(10),
                    Constraint::Length(7),
                ])
                .split(area);

            let top_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
                .split(main_chunks[0]);

            // ── Services panel ──────────────────────────────
            let svc_items: Vec<Line> = if app.services.is_empty() {
                vec![Line::from(Span::styled("  connecting...", Style::default().fg(muted)))]
            } else {
                app.services.iter().map(|s| {
                    let (icon, color) = if s.healthy { ("OK", green) } else { ("FAIL", red) };
                    Line::from(vec![
                        Span::styled("  ", Style::default()),
                        Span::styled(format!("{:<16}", s.name), Style::default().fg(text)),
                        Span::styled(format!("[{icon:>4}]"), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                        Span::styled(format!(" {}ms", s.latency_ms), Style::default().fg(muted)),
                    ])
                }).collect()
            };
            let svc_title = if let Some(ref pi) = plan_info {
                format!(" SERVICES  |  {} ", pi)
            } else {
                " SERVICES ".to_string()
            };
            let svc_block = Block::default()
                .title(Span::styled(svc_title, Style::default().fg(red).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL).border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_c));
            frame.render_widget(Paragraph::new(svc_items).block(svc_block).style(Style::default().bg(bg)), top_chunks[0]);

            // ── Agents panel ────────────────────────────────
            let agent_items: Vec<ListItem> = if app.agents.is_empty() {
                vec![ListItem::new(Span::styled("  no agents", Style::default().fg(muted)))]
            } else {
                app.agents.iter().enumerate().map(|(i, a)| {
                    let state_color = match a.state.as_str() {
                        "active" => green, "suspended" => amber, "killed" => red, _ => text,
                    };
                    let selected = i == app.selected_agent;
                    let marker = if selected { ">" } else { " " };
                    let name_style = if selected {
                        Style::default().fg(bright).add_modifier(Modifier::BOLD)
                    } else { Style::default().fg(text) };
                    let fw = a.framework.as_deref().unwrap_or("-");
                    ListItem::new(Line::from(vec![
                        Span::styled(format!(" {marker} "), if selected { Style::default().fg(red).add_modifier(Modifier::BOLD) } else { Style::default().fg(border_c) }),
                        Span::styled(format!("{:<18}", a.name), name_style),
                        Span::styled(format!("{:<12}", a.state), Style::default().fg(state_color).add_modifier(Modifier::BOLD)),
                        Span::styled(fw.to_string(), Style::default().fg(muted)),
                    ]))
                }).collect()
            };
            let agent_block = Block::default()
                .title(Span::styled(" AGENTS ", Style::default().fg(red).add_modifier(Modifier::BOLD)))
                .title_bottom(Span::styled(" j/k:nav  K:kill  S:suspend  R:resume  ?:help  q:quit ", Style::default().fg(muted)))
                .borders(Borders::ALL).border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_c));
            frame.render_widget(List::new(agent_items).block(agent_block).style(Style::default().bg(bg)), top_chunks[1]);

            // ── Events panel ────────────────────────────────
            let event_items: Vec<Line> = if app.events.is_empty() {
                vec![Line::from(Span::styled("  waiting for events from ag-risk WebSocket ...", Style::default().fg(muted)))]
            } else {
                app.events.iter().take(main_chunks[1].height as usize - 2).map(|e| {
                    // Non-risk events (local actions, correlation alerts)
                    if let Some(ref raw) = e.raw_detail {
                        let short_subject = e.raw_subject.rsplit('.').next().unwrap_or(&e.raw_subject);
                        let subject_color = if short_subject.contains("kill") { red }
                            else if short_subject.contains("CORRELATION") || short_subject.contains("correlation") { amber }
                            else { text };
                        return Line::from(vec![
                            Span::styled(format!(" {} ", e.timestamp), Style::default().fg(muted)),
                            Span::styled(format!("{:<10}", short_subject), Style::default().fg(subject_color).add_modifier(Modifier::BOLD)),
                            Span::styled(raw.chars().take(100).collect::<String>(), Style::default().fg(text)),
                        ]);
                    }

                    let mut spans = vec![
                        Span::styled(format!(" {} ", e.timestamp), Style::default().fg(muted)),
                    ];

                    // Agent name
                    let agent_short: String = e.agent_name.chars().take(14).collect();
                    spans.push(Span::styled(format!("{:<15}", agent_short), Style::default().fg(text)));

                    // Tool name
                    let tool_short: String = e.tool_name.chars().take(22).collect();
                    spans.push(Span::styled(format!("{:<23}", tool_short), Style::default().fg(bright)));

                    // Risk score
                    let risk_color = if e.risk_score >= 0.8 { red }
                        else if e.risk_score >= 0.5 { amber }
                        else { text };
                    spans.push(Span::styled(
                        format!("{:.1} ", e.risk_score),
                        Style::default().fg(risk_color).add_modifier(if e.risk_score >= 0.8 { Modifier::BOLD } else { Modifier::empty() }),
                    ));

                    // Classification
                    if e.blocked {
                        spans.push(Span::styled("DENY ", Style::default().fg(red).add_modifier(Modifier::BOLD)));
                    } else {
                        let cls_short: String = e.classification.chars().take(8).collect();
                        spans.push(Span::styled(format!("{:<5}", cls_short), Style::default().fg(green)));
                    }

                    // Params summary
                    if !e.params_summary.is_empty() {
                        let summary: String = e.params_summary.chars().take(50).collect();
                        spans.push(Span::styled(format!(" {summary}"), Style::default().fg(bright)));
                    }

                    // Denial reason
                    if e.blocked {
                        if let Some(ref reason) = e.denial_reason {
                            let short_reason: String = reason.chars().take(30).collect();
                            spans.push(Span::styled(format!(" ({short_reason})"), Style::default().fg(red_bright)));
                        }
                    }

                    // PII flag
                    if e.pii_detected {
                        spans.push(Span::styled(" [PII]", Style::default().fg(red).add_modifier(Modifier::BOLD)));
                    }

                    // Encoding anomalies
                    if !e.encodings.is_empty() {
                        let enc = e.encodings.iter().take(2).cloned().collect::<Vec<_>>().join(",");
                        spans.push(Span::styled(format!(" [ENC:{enc}]"), Style::default().fg(amber)));
                    }

                    Line::from(spans)
                }).collect()
            };
            let events_title = format!(" LIVE EVENTS  total:{}  blocked:{} ", app.event_count, app.blocked_count);
            let events_block = Block::default()
                .title(Span::styled(events_title, Style::default().fg(red).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL).border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_c));
            frame.render_widget(Paragraph::new(event_items).block(events_block).style(Style::default().bg(bg)), main_chunks[1]);

            // ── Detail panel ────────────────────────────────
            let detail_lines: Vec<Line> = if app.show_confirm_kill {
                if let Some(agent) = app.selected_agent_info() {
                    vec![
                        Line::from(Span::styled(format!("  KILL {}? Revokes tokens, terminates sessions.", agent.name), Style::default().fg(red).add_modifier(Modifier::BOLD))),
                        Line::from(vec![
                            Span::styled("  Press ", Style::default().fg(muted)),
                            Span::styled("[Y]", Style::default().fg(red).add_modifier(Modifier::BOLD)),
                            Span::styled(" confirm  ", Style::default().fg(muted)),
                            Span::styled("[N]", Style::default().fg(bright)),
                            Span::styled(" cancel", Style::default().fg(muted)),
                        ]),
                    ]
                } else { vec![Line::from(Span::styled("  No agent selected", Style::default().fg(muted)))] }
            } else if app.show_confirm_suspend {
                if let Some(agent) = app.selected_agent_info() {
                    vec![
                        Line::from(Span::styled(format!("  SUSPEND {}?", agent.name), Style::default().fg(amber).add_modifier(Modifier::BOLD))),
                        Line::from(vec![
                            Span::styled("  Press ", Style::default().fg(muted)),
                            Span::styled("[Y]", Style::default().fg(amber).add_modifier(Modifier::BOLD)),
                            Span::styled(" confirm  ", Style::default().fg(muted)),
                            Span::styled("[N]", Style::default().fg(bright)),
                            Span::styled(" cancel", Style::default().fg(muted)),
                        ]),
                    ]
                } else { vec![Line::from(Span::styled("  No agent selected", Style::default().fg(muted)))] }
            } else if let Some(agent) = app.selected_agent_info() {
                let state_color = match agent.state.as_str() {
                    "active" => green, "suspended" => amber, "killed" => red, _ => text,
                };
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("  ID: ", Style::default().fg(muted)),
                        Span::styled(agent.id.to_string(), Style::default().fg(text)),
                        Span::styled("  State: ", Style::default().fg(muted)),
                        Span::styled(agent.state.clone(), Style::default().fg(state_color).add_modifier(Modifier::BOLD)),
                        Span::styled("  Framework: ", Style::default().fg(muted)),
                        Span::styled(agent.framework.as_deref().unwrap_or("-").to_string(), Style::default().fg(bright)),
                        Span::styled("  Auth: ", Style::default().fg(muted)),
                        Span::styled(agent.auth_mode.as_deref().unwrap_or("clampd").to_string(), Style::default().fg(text)),
                    ]),
                    Line::from(vec![
                        Span::styled("  Purpose: ", Style::default().fg(muted)),
                        Span::styled(agent.declared_purpose.as_deref().unwrap_or("Not declared").to_string(), Style::default().fg(bright)),
                    ]),
                ];
                if let Some(ref reason) = agent.kill_reason {
                    lines.push(Line::from(vec![
                        Span::styled("  Kill Reason: ", Style::default().fg(red)),
                        Span::styled(reason.clone(), Style::default().fg(red_bright)),
                    ]));
                }
                let agent_events = app.events.iter().filter(|e| e.agent_name == agent.name || e.agent_name == agent.id.to_string()).count();
                let agent_blocked = app.events.iter().filter(|e| (e.agent_name == agent.name || e.agent_name == agent.id.to_string()) && e.blocked).count();
                let agent_pii = app.events.iter().filter(|e| (e.agent_name == agent.name || e.agent_name == agent.id.to_string()) && e.pii_detected).count();
                lines.push(Line::from(vec![
                    Span::styled("  Activity: ", Style::default().fg(muted)),
                    Span::styled(format!("{agent_events} events"), Style::default().fg(text)),
                    Span::styled("  ", Style::default()),
                    Span::styled(format!("{agent_blocked} blocked"), Style::default().fg(if agent_blocked > 0 { red } else { text })),
                    Span::styled("  ", Style::default()),
                    Span::styled(format!("{agent_pii} PII"), Style::default().fg(if agent_pii > 0 { red } else { text })),
                ]));
                lines
            } else {
                vec![Line::from(Span::styled("  No agent selected", Style::default().fg(muted)))]
            };

            let detail_block = Block::default()
                .title(Span::styled(" DETAIL ", Style::default().fg(red).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL).border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_c));
            frame.render_widget(Paragraph::new(detail_lines).block(detail_block).style(Style::default().bg(bg)), main_chunks[2]);
        })?;

        // Handle keyboard
        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if app.show_confirm_kill {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            if let Some(agent) = app.agents.get(app.selected_agent) {
                                let agent_id_str = agent.id.to_string();
                                let agent_name = agent.name.clone();
                                let url = format!("{}/v1/orgs/{}/agents/{}/kill",
                                    action_dashboard_url, action_org_id, agent_id_str);
                                let client = action_client.clone();
                                let token = action_api_token.clone();
                                tokio::spawn(async move {
                                    let body = serde_json::json!({
                                        "reason": "Kill from clampd TUI"
                                    });
                                    let mut req = client.post(&url).json(&body);
                                    if !token.is_empty() {
                                        req = req.header("Authorization", format!("Bearer {}", token));
                                    }
                                    let _ = req.send().await;
                                });
                                app.push_local_event("kill", &agent_name, "Manual kill from TUI");
                            }
                            app.show_confirm_kill = false;
                        }
                        _ => { app.show_confirm_kill = false; }
                    }
                } else if app.show_confirm_suspend {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            if let Some(agent) = app.agents.get(app.selected_agent) {
                                let agent_id_str = agent.id.to_string();
                                let agent_name = agent.name.clone();
                                let url = format!("{}/v1/orgs/{}/agents/{}/suspend",
                                    action_dashboard_url, action_org_id, agent_id_str);
                                let client = action_client.clone();
                                let token = action_api_token.clone();
                                tokio::spawn(async move {
                                    let body = serde_json::json!({});
                                    let mut req = client.post(&url).json(&body);
                                    if !token.is_empty() {
                                        req = req.header("Authorization", format!("Bearer {}", token));
                                    }
                                    let _ = req.send().await;
                                });
                                app.push_local_event("suspend", &agent_name, "Suspended from TUI");
                            }
                            app.show_confirm_suspend = false;
                        }
                        _ => { app.show_confirm_suspend = false; }
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !app.agents.is_empty() {
                                app.selected_agent = (app.selected_agent + 1) % app.agents.len();
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if !app.agents.is_empty() {
                                app.selected_agent = if app.selected_agent == 0 { app.agents.len() - 1 } else { app.selected_agent - 1 };
                            }
                        }
                        KeyCode::Char('K') => { if !app.agents.is_empty() { app.show_confirm_kill = true; } }
                        KeyCode::Char('S') => {
                            if let Some(a) = app.agents.get(app.selected_agent) {
                                if a.state == "active" { app.show_confirm_suspend = true; }
                            }
                        }
                        KeyCode::Char('R') => {
                            if let Some(agent) = app.agents.get(app.selected_agent) {
                                if agent.state == "suspended" || agent.state == "killed" {
                                    let agent_id_str = agent.id.to_string();
                                    let agent_name = agent.name.clone();
                                    let url = format!("{}/v1/orgs/{}/agents/{}/revive",
                                        action_dashboard_url, action_org_id, agent_id_str);
                                    let client = action_client.clone();
                                    let token = action_api_token.clone();
                                    tokio::spawn(async move {
                                        let body = serde_json::json!({
                                            "reason": "Revived from clampd TUI"
                                        });
                                        let mut req = client.post(&url).json(&body);
                                        if !token.is_empty() {
                                            req = req.header("Authorization", format!("Bearer {}", token));
                                        }
                                        let _ = req.send().await;
                                    });
                                    app.push_local_event("resume", &agent_name, "Revived from TUI");
                                }
                            }
                        }
                        KeyCode::Char('?') => { app.show_help = !app.show_help; }
                        _ => {}
                    }
                }
            }
        }
    }

    ws_handle.abort();
    poll_handle.abort();
    tick_handle.abort();
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

/// Build a JWT for authenticating to the ag-risk WebSocket endpoint.
#[cfg(feature = "tui")]
fn build_ws_jwt() -> anyhow::Result<String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let jwt_secret = std::env::var("JWT_SECRET")
        .map_err(|_| anyhow::anyhow!("JWT_SECRET required for WebSocket auth"))?;
    if jwt_secret.is_empty() {
        anyhow::bail!("JWT_SECRET required for WebSocket auth");
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload_json = format!(
        r#"{{"sub":"clampd-cli","iss":"clampd-cli","iat":{},"exp":{}}}"#,
        now, now + 3600
    );

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let header = engine.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = engine.encode(&payload_json);
    let signing_input = format!("{header}.{payload}");

    let mut mac = HmacSha256::new_from_slice(jwt_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    let signature = engine.encode(mac.finalize().into_bytes());

    Ok(format!("{signing_input}.{signature}"))
}

#[cfg(not(feature = "tui"))]
pub async fn run(_state: &crate::state::AppState, _agent: Option<uuid::Uuid>, _plan_info: Option<&str>) -> anyhow::Result<()> {
    anyhow::bail!("TUI support not compiled. Rebuild with --features tui")
}
