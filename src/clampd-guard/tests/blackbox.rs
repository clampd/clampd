//! Black box integration tests for clampd-guard.
//!
//! Spawns the compiled binary as a child process with env vars,
//! uses a mock HTTP server as the gateway, and verifies:
//! - Exit codes (0 = allow, 2 = block)
//! - Stdout JSON for blocked calls
//! - Request payloads sent to gateway
//! - Config and hook file management
//! - Fail-open / fail-closed behavior
//! - skip_low_risk behavior
//! - Employee token preference

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{extract::State, http::HeaderMap, routing::{get, post}, Json, Router};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::net::TcpListener;

// ── Helpers ──────────────────────────────────────────────

fn binary_path() -> PathBuf {
    // cargo test builds to target/debug/deps, binary is at target/debug/clampd-guard
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    if path.ends_with("deps") {
        path.pop(); // remove deps/
    }
    path.push("clampd-guard");
    path
}

struct RunResult {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_guard(home: &str, env: Vec<(&str, &str)>) -> RunResult {
    let output = Command::new(binary_path())
        .env("HOME", home)
        .envs(env)
        .output()
        .expect("failed to execute clampd-guard");

    RunResult {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Run guard with JSON payload on stdin (Claude Code hook protocol).
fn run_guard_stdin(home: &str, stdin_json: &str) -> RunResult {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(binary_path())
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn clampd-guard");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_json.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("failed to wait on clampd-guard");

    RunResult {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn run_guard_with_args(home: &str, args: &[&str]) -> RunResult {
    let output = Command::new(binary_path())
        .env("HOME", home)
        .args(args)
        .output()
        .expect("failed to execute clampd-guard");

    RunResult {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn write_config(home: &str, overrides: Value) {
    let dir = PathBuf::from(home).join(".clampd");
    std::fs::create_dir_all(&dir).unwrap();

    let mut config = json!({
        "gateway_url": "http://127.0.0.1:1",
        "api_key": "ag_test_key",
        "agent_id": "test-agent-id",
        "secret": "ags_test_secret",
        "skip_low_risk": false,
        "fail_open": false,
        "timeout_ms": 3000
    });

    if let Some(obj) = overrides.as_object() {
        for (k, v) in obj {
            config[k] = v.clone();
        }
    }

    std::fs::write(
        dir.join("guard.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
}

#[derive(Clone, Default)]
struct MockState {
    requests: Arc<Mutex<Vec<(String, String, HeaderMap)>>>,
}

async fn start_mock_gateway(
    allow: bool,
    risk_score: f64,
    denial_reason: Option<String>,
    rules: Vec<String>,
) -> (SocketAddr, MockState) {
    let state = MockState::default();
    let s = state.clone();

    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .route(
            "/v1/proxy",
            post(move |State(st): State<MockState>, headers: HeaderMap, Json(body): Json<Value>| {
                let requests = st.requests.clone();
                let allow = allow;
                let risk_score = risk_score;
                let denial_reason = denial_reason.clone();
                let rules = rules.clone();
                async move {
                    requests.lock().unwrap().push((
                        "/v1/proxy".into(),
                        serde_json::to_string(&body).unwrap(),
                        headers,
                    ));
                    Json(json!({
                        "request_id": "test-req-001",
                        "allowed": allow,
                        "action": if allow { "pass" } else { "block" },
                        "risk_score": risk_score,
                        "denial_reason": denial_reason,
                        "matched_rules": rules,
                        "reasoning": null,
                        "latency_ms": 5
                    }))
                }
            }),
        )
        .route(
            "/v1/inspect",
            post(move |State(st): State<MockState>, headers: HeaderMap, Json(body): Json<Value>| {
                let requests = st.requests.clone();
                async move {
                    requests.lock().unwrap().push((
                        "/v1/inspect".into(),
                        serde_json::to_string(&body).unwrap(),
                        headers,
                    ));
                    Json(json!({
                        "request_id": "test-inspect-001",
                        "allowed": true,
                        "action": "pass",
                        "risk_score": 0.0,
                        "denial_reason": null,
                        "matched_rules": [],
                        "latency_ms": 2
                    }))
                }
            }),
        )
        .with_state(s);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server a moment to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    (addr, state)
}

// ── Guard Hook Tests ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn guard_allows_when_no_config() {
    let tmp = TempDir::new().unwrap();
    let result = run_guard(
        tmp.path().to_str().unwrap(),
        vec![("CLAUDE_TOOL_NAME", "Bash"), ("CLAUDE_TOOL_INPUT", r#"{"command":"ls"}"#)],
    );
    assert_eq!(result.code, 0);
    assert!(result.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_allows_when_no_tool_name() {
    let tmp = TempDir::new().unwrap();
    let result = run_guard(tmp.path().to_str().unwrap(), vec![]);
    assert_eq!(result.code, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_allows_when_gateway_allows() {
    let (addr, _state) = start_mock_gateway(true, 0.05, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let result = run_guard(
        tmp.path().to_str().unwrap(),
        vec![("CLAUDE_TOOL_NAME", "Bash"), ("CLAUDE_TOOL_INPUT", r#"{"command":"ls -la"}"#)],
    );
    assert_eq!(result.code, 0, "stderr: {}", result.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_blocks_when_gateway_denies() {
    let (addr, _state) = start_mock_gateway(
        false,
        0.92,
        Some("Destructive shell command detected".into()),
        vec!["R042".into(), "R078".into()],
    ).await;

    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let result = run_guard(
        tmp.path().to_str().unwrap(),
        vec![("CLAUDE_TOOL_NAME", "Bash"), ("CLAUDE_TOOL_INPUT", r#"{"command":"rm -rf /"}"#)],
    );
    assert_eq!(result.code, 2, "stderr: {}", result.stderr);

    let output: Value = serde_json::from_str(&result.stdout).expect("stdout should be JSON");
    assert_eq!(output["decision"], "block");
    assert!(output["reason"].as_str().unwrap().contains("Destructive shell command"));
    assert!(output["reason"].as_str().unwrap().contains("R042"));
    assert!(output["reason"].as_str().unwrap().contains("0.92"));
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_sends_correct_payload() {
    let (addr, state) = start_mock_gateway(true, 0.0, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    run_guard(
        tmp.path().to_str().unwrap(),
        vec![
            ("CLAUDE_TOOL_NAME", "Write"),
            ("CLAUDE_TOOL_INPUT", r#"{"file_path":"/tmp/test.txt","content":"hello"}"#),
        ],
    );

    let requests = state.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);

    let (url, body_str, headers) = &requests[0];
    assert_eq!(url, "/v1/proxy");

    let body: Value = serde_json::from_str(body_str).unwrap();
    assert_eq!(body["tool"], "Write");
    assert_eq!(body["params"]["file_path"], "/tmp/test.txt");
    assert_eq!(body["prompt_context"], "scope:fs:write:file");
    assert_eq!(body["target_url"], "");

    // Check auth headers
    assert!(headers.get("authorization").unwrap().to_str().unwrap().starts_with("Bearer "));
    assert_eq!(headers.get("x-ag-key").unwrap().to_str().unwrap(), "ag_test_key");
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_maps_mcp_tools() {
    let (addr, state) = start_mock_gateway(true, 0.0, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    run_guard(
        tmp.path().to_str().unwrap(),
        vec![
            ("CLAUDE_TOOL_NAME", "mcp__github__create_pull_request"),
            ("CLAUDE_TOOL_INPUT", r#"{"title":"fix"}"#),
        ],
    );

    let requests = state.requests.lock().unwrap();
    let body: Value = serde_json::from_str(&requests[0].1).unwrap();
    assert_eq!(body["prompt_context"], "scope:scm:git:api");
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_fail_open_on_unreachable_gateway() {
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": "http://127.0.0.1:1",
        "fail_open": true,
        "timeout_ms": 1000
    }));

    let result = run_guard(
        tmp.path().to_str().unwrap(),
        vec![("CLAUDE_TOOL_NAME", "Bash"), ("CLAUDE_TOOL_INPUT", r#"{"command":"ls"}"#)],
    );
    assert_eq!(result.code, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_fail_closed_on_unreachable_gateway() {
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": "http://127.0.0.1:1",
        "fail_open": false,
        "timeout_ms": 1000
    }));

    let result = run_guard(
        tmp.path().to_str().unwrap(),
        vec![("CLAUDE_TOOL_NAME", "Bash"), ("CLAUDE_TOOL_INPUT", r#"{"command":"ls"}"#)],
    );
    assert_eq!(result.code, 2);
    let output: Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(output["decision"], "block");
    assert!(output["reason"].as_str().unwrap().contains("unreachable"));
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_skips_low_risk_when_configured() {
    let tmp = TempDir::new().unwrap();
    // Point to unreachable gateway with fail_open=false
    // If skip_low_risk works, Read won't hit the gateway and will exit 0
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": "http://127.0.0.1:1",
        "skip_low_risk": true,
        "fail_open": false,
        "timeout_ms": 500
    }));

    let result = run_guard(
        tmp.path().to_str().unwrap(),
        vec![("CLAUDE_TOOL_NAME", "Read"), ("CLAUDE_TOOL_INPUT", r#"{"file_path":"/tmp/x"}"#)],
    );
    assert_eq!(result.code, 0, "Read should be skipped when skip_low_risk=true");

    // Bash should still go through (and fail since gateway unreachable)
    let result2 = run_guard(
        tmp.path().to_str().unwrap(),
        vec![("CLAUDE_TOOL_NAME", "Bash"), ("CLAUDE_TOOL_INPUT", r#"{"command":"ls"}"#)],
    );
    assert_eq!(result2.code, 2, "Bash should NOT be skipped");
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_handles_malformed_input() {
    let (addr, state) = start_mock_gateway(true, 0.0, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    run_guard(
        tmp.path().to_str().unwrap(),
        vec![("CLAUDE_TOOL_NAME", "Bash"), ("CLAUDE_TOOL_INPUT", "not-valid-json{{{")],
    );

    let requests = state.requests.lock().unwrap();
    let body: Value = serde_json::from_str(&requests[0].1).unwrap();
    assert_eq!(body["params"]["raw"], "not-valid-json{{{");
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_post_tool_use_calls_inspect() {
    let (addr, state) = start_mock_gateway(true, 0.0, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let result = run_guard(
        tmp.path().to_str().unwrap(),
        vec![
            ("CLAUDE_TOOL_NAME", "Bash"),
            ("CLAUDE_TOOL_INPUT", ""),
            ("CLAUDE_TOOL_OUTPUT", r#"{"output":"file1.txt\nfile2.txt"}"#),
        ],
    );
    assert_eq!(result.code, 0);

    let requests = state.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "/v1/inspect");
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_uses_employee_token_when_available() {
    let (addr, state) = start_mock_gateway(true, 0.0, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();
    write_config(home, json!({
        "gateway_url": format!("http://{}", addr)
    }));

    // Write employee token
    let clampd_dir = tmp.path().join(".clampd");
    let future_exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 86400;
    std::fs::write(
        clampd_dir.join("token.json"),
        serde_json::to_string(&json!({
            "access_token": "employee-jwt-from-sso",
            "token_type": "Bearer",
            "expires_at": future_exp,
            "email": "mehul@acme.co"
        })).unwrap(),
    ).unwrap();

    run_guard(
        home,
        vec![("CLAUDE_TOOL_NAME", "Bash"), ("CLAUDE_TOOL_INPUT", r#"{"command":"ls"}"#)],
    );

    let requests = state.requests.lock().unwrap();
    let auth = requests[0].2.get("authorization").unwrap().to_str().unwrap();
    assert_eq!(auth, "Bearer employee-jwt-from-sso");
}

// ── Hook Install/Uninstall Tests ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn hook_install_creates_settings() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();

    let result = run_guard_with_args(home, &["hook", "install", "--target", "claude-code"]);
    assert_eq!(result.code, 0, "stderr: {}", result.stderr);

    let settings_path = tmp.path().join(".claude").join("settings.json");
    assert!(settings_path.exists(), "settings.json should be created");

    let settings: Value = serde_json::from_str(
        &std::fs::read_to_string(&settings_path).unwrap()
    ).unwrap();

    // Check PreToolUse
    let pre = &settings["hooks"]["PreToolUse"];
    assert!(pre.is_array());
    assert_eq!(pre[0]["hooks"][0]["command"], "clampd-guard");

    // Check PostToolUse
    let post = &settings["hooks"]["PostToolUse"];
    assert!(post.is_array());
    assert_eq!(post[0]["hooks"][0]["command"], "clampd-guard");
}

#[tokio::test(flavor = "multi_thread")]
async fn hook_install_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();

    run_guard_with_args(home, &["hook", "install"]);
    run_guard_with_args(home, &["hook", "install"]);
    run_guard_with_args(home, &["hook", "install"]);

    let settings: Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".claude").join("settings.json")).unwrap()
    ).unwrap();

    assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    assert_eq!(settings["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn hook_install_preserves_existing_settings() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();

    let claude_dir = tmp.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string(&json!({
            "existingKey": "must-survive",
            "hooks": {
                "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "other-tool"}]}]
            }
        })).unwrap(),
    ).unwrap();

    run_guard_with_args(home, &["hook", "install"]);

    let settings: Value = serde_json::from_str(
        &std::fs::read_to_string(claude_dir.join("settings.json")).unwrap()
    ).unwrap();

    assert_eq!(settings["existingKey"], "must-survive");
    assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 2); // other-tool + clampd-guard
}

#[tokio::test(flavor = "multi_thread")]
async fn hook_uninstall_removes_hooks() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();

    run_guard_with_args(home, &["hook", "install"]);
    run_guard_with_args(home, &["hook", "uninstall"]);

    let settings: Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".claude").join("settings.json")).unwrap()
    ).unwrap();

    assert!(settings.get("hooks").is_none(), "hooks should be removed");
}

// ── Setup Tests ──────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn setup_creates_config_and_installs_hooks() {
    let (addr, _state) = start_mock_gateway(true, 0.0, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();

    let result = run_guard_with_args(home, &[
        "setup",
        "--url", &format!("http://{}", addr),
        "--key", "ag_test_key",
        "--agent", "my-agent-id",
        "--secret", "ags_my_secret",
    ]);

    assert_eq!(result.code, 0, "stderr: {}", result.stderr);

    // Config created
    let config_path = tmp.path().join(".clampd").join("guard.json");
    assert!(config_path.exists());
    let config: Value = serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(config["api_key"], "ag_test_key");
    assert_eq!(config["agent_id"], "my-agent-id");
    assert_eq!(config["secret"], "ags_my_secret");

    // Hooks installed
    let settings_path = tmp.path().join(".claude").join("settings.json");
    assert!(settings_path.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_fails_with_unreachable_gateway() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();

    let result = run_guard_with_args(home, &[
        "setup",
        "--url", "http://127.0.0.1:1",
        "--key", "ag_test",
        "--agent", "test-id",
        "--secret", "ags_test",
    ]);

    assert_ne!(result.code, 0);
    assert!(result.stderr.contains("Cannot reach") || result.stderr.contains("FAILED"));
}

// ── CLI Tests ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn cli_help() {
    let tmp = TempDir::new().unwrap();
    let result = run_guard_with_args(tmp.path().to_str().unwrap(), &["--help"]);
    assert_eq!(result.code, 0);
    assert!(result.stdout.contains("clampd-guard"));
    assert!(result.stdout.contains("hook"));
    assert!(result.stdout.contains("setup"));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_version() {
    let tmp = TempDir::new().unwrap();
    let result = run_guard_with_args(tmp.path().to_str().unwrap(), &["--version"]);
    assert_eq!(result.code, 0);
    assert!(result.stdout.contains("clampd-guard"));
}

// ── End-to-End: Setup → Guard Flow ──────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn e2e_setup_then_guard() {
    // Start mock that blocks rm -rf, allows everything else
    let state = MockState::default();
    let s = state.clone();

    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .route("/v1/proxy", post(move |State(st): State<MockState>, Json(body): Json<Value>| {
            let requests = st.requests.clone();
            async move {
                requests.lock().unwrap().push(("/v1/proxy".into(), serde_json::to_string(&body).unwrap(), HeaderMap::new()));

                let is_destructive = body["params"]["command"]
                    .as_str()
                    .map(|c| c.contains("rm -rf"))
                    .unwrap_or(false);

                Json(json!({
                    "request_id": "e2e",
                    "allowed": !is_destructive,
                    "action": if is_destructive { "block" } else { "pass" },
                    "risk_score": if is_destructive { 0.95 } else { 0.01 },
                    "denial_reason": if is_destructive { Some("Destructive command blocked") } else { None::<&str> },
                    "matched_rules": if is_destructive { vec!["R042"] } else { Vec::<&str>::new() },
                    "latency_ms": 3
                }))
            }
        }))
        .with_state(s);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();

    // Step 1: Setup
    let result = run_guard_with_args(home, &[
        "setup",
        "-u", &format!("http://{}", addr),
        "-k", "ag_e2e_key",
        "-a", "e2e-agent",
        "-s", "ags_e2e_secret",
    ]);
    assert_eq!(result.code, 0, "setup failed: {}", result.stderr);

    // Step 2: Allow safe command
    let result = run_guard(home, vec![
        ("CLAUDE_TOOL_NAME", "Bash"),
        ("CLAUDE_TOOL_INPUT", r#"{"command":"echo hello"}"#),
    ]);
    assert_eq!(result.code, 0);

    // Step 3: Block destructive command
    let result = run_guard(home, vec![
        ("CLAUDE_TOOL_NAME", "Bash"),
        ("CLAUDE_TOOL_INPUT", r#"{"command":"rm -rf /var/data"}"#),
    ]);
    assert_eq!(result.code, 2);
    let output: Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(output["decision"], "block");

    // Step 4: Allow Read
    let result = run_guard(home, vec![
        ("CLAUDE_TOOL_NAME", "Read"),
        ("CLAUDE_TOOL_INPUT", r#"{"file_path":"/tmp/test"}"#),
    ]);
    assert_eq!(result.code, 0);

    // Step 5: Verify all requests had auth headers
    let requests = state.requests.lock().unwrap();
    assert_eq!(requests.len(), 3); // echo, rm -rf, Read
}

// ── Stdin Protocol Tests (Claude Code hook format) ──────

#[tokio::test(flavor = "multi_thread")]
async fn stdin_allows_safe_command() {
    let (addr, _state) = start_mock_gateway(true, 0.05, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "ls -la" }
    });

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), &input.to_string());
    assert_eq!(result.code, 0, "Safe command should be allowed via stdin. stderr: {}", result.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_blocks_destructive_command() {
    let (addr, _state) = start_mock_gateway(
        false, 0.95,
        Some("Destructive shell command detected".into()),
        vec!["R042".into()],
    ).await;

    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "rm -rf /" }
    });

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), &input.to_string());
    assert_eq!(result.code, 2, "Destructive command should be blocked via stdin");

    let output: Value = serde_json::from_str(&result.stdout).expect("stdout should be JSON");
    assert_eq!(output["decision"], "block");
    assert!(output["reason"].as_str().unwrap().contains("R042"));
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_sends_correct_payload_to_gateway() {
    let (addr, state) = start_mock_gateway(true, 0.0, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": "/tmp/test.txt", "content": "hello" },
        "session_id": "test-session",
        "tool_use_id": "toolu_123"
    });

    run_guard_stdin(tmp.path().to_str().unwrap(), &input.to_string());

    let requests = state.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let body: Value = serde_json::from_str(&requests[0].1).unwrap();
    assert_eq!(body["tool"], "Write");
    assert_eq!(body["params"]["file_path"], "/tmp/test.txt");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_post_tool_use_calls_inspect() {
    let (addr, state) = start_mock_gateway(true, 0.0, None, vec![]).await;
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "ls" },
        "tool_response": { "stdout": "file1.txt\nfile2.txt", "stderr": "" }
    });

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), &input.to_string());
    assert_eq!(result.code, 0);

    let requests = state.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "/v1/inspect");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_empty_allows_gracefully() {
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({}));

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), "");
    assert_eq!(result.code, 0, "Empty stdin should fall back to env vars and allow");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_malformed_json_allows_gracefully() {
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({}));

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), "not-valid-json{{{");
    assert_eq!(result.code, 0, "Malformed stdin JSON should fall back to env vars and allow");
}

// ── Credential / SSH Key Access Tests ───────────────────

#[tokio::test(flavor = "multi_thread")]
async fn stdin_blocks_ssh_private_key_read() {
    let (addr, _state) = start_mock_gateway(
        false, 1.0,
        Some("Credential access denied".into()),
        vec!["R143".into()],
    ).await;

    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/home/user/.ssh/id_rsa" }
    });

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), &input.to_string());
    assert_eq!(result.code, 2, "Reading SSH private key should be blocked");

    let output: Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(output["decision"], "block");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_blocks_ssh_public_key_cat() {
    let (addr, _state) = start_mock_gateway(
        false, 0.60,
        Some("Credential access denied".into()),
        vec!["R143".into()],
    ).await;

    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "cat ~/.ssh/id_rsa.pub" }
    });

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), &input.to_string());
    assert_eq!(result.code, 2, "Reading SSH public key should be blocked");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_blocks_etc_shadow_read() {
    let (addr, _state) = start_mock_gateway(
        false, 1.0,
        Some("Malicious intent classification".into()),
        vec!["R143".into()],
    ).await;

    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/shadow" }
    });

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), &input.to_string());
    assert_eq!(result.code, 2, "Reading /etc/shadow should be blocked");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_blocks_etc_passwd_cat() {
    let (addr, _state) = start_mock_gateway(
        false, 1.0,
        Some("Malicious intent classification".into()),
        vec!["R143".into()],
    ).await;

    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "cat /etc/passwd" }
    });

    let result = run_guard_stdin(tmp.path().to_str().unwrap(), &input.to_string());
    assert_eq!(result.code, 2, "Reading /etc/passwd should be blocked");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_env_var_fallback_still_works() {
    let (addr, _state) = start_mock_gateway(
        false, 0.92,
        Some("Blocked".into()),
        vec!["R042".into()],
    ).await;

    let tmp = TempDir::new().unwrap();
    write_config(tmp.path().to_str().unwrap(), json!({
        "gateway_url": format!("http://{}", addr)
    }));

    // No stdin, use env vars (backward compat for direct invocation)
    let result = run_guard(
        tmp.path().to_str().unwrap(),
        vec![
            ("CLAUDE_TOOL_NAME", "Bash"),
            ("CLAUDE_TOOL_INPUT", r#"{"command":"rm -rf /"}"#),
        ],
    );
    assert_eq!(result.code, 2, "Env var fallback should still block dangerous commands");
}

// ── E2E: Stdin protocol with smart mock ─────────────────

#[tokio::test(flavor = "multi_thread")]
async fn e2e_stdin_credential_vs_safe_commands() {
    // Mock that blocks credential access, allows safe commands
    let state = MockState::default();
    let s = state.clone();

    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .route("/v1/proxy", post(move |State(st): State<MockState>, Json(body): Json<Value>| {
            let requests = st.requests.clone();
            async move {
                requests.lock().unwrap().push((
                    "/v1/proxy".into(),
                    serde_json::to_string(&body).unwrap(),
                    HeaderMap::new(),
                ));

                let is_credential = {
                    let params = &body["params"];
                    let cmd = params["command"].as_str().unwrap_or("");
                    let path = params["file_path"].as_str().unwrap_or("");
                    cmd.contains(".ssh") || cmd.contains("shadow") || cmd.contains("passwd")
                        || path.contains(".ssh") || path.contains("shadow") || path.contains("passwd")
                };

                Json(json!({
                    "request_id": "e2e-stdin",
                    "allowed": !is_credential,
                    "action": if is_credential { "block" } else { "pass" },
                    "risk_score": if is_credential { 1.0 } else { 0.05 },
                    "denial_reason": if is_credential { Some("Credential access denied") } else { None::<&str> },
                    "matched_rules": if is_credential { vec!["R143"] } else { Vec::<&str>::new() },
                    "latency_ms": 3
                }))
            }
        }))
        .route("/v1/inspect", post(move |State(st): State<MockState>, Json(body): Json<Value>| {
            let requests = st.requests.clone();
            async move {
                requests.lock().unwrap().push((
                    "/v1/inspect".into(),
                    serde_json::to_string(&body).unwrap(),
                    HeaderMap::new(),
                ));
                Json(json!({
                    "request_id": "inspect",
                    "allowed": true,
                    "action": "pass",
                    "risk_score": 0.0,
                    "denial_reason": null,
                    "matched_rules": [],
                    "latency_ms": 1
                }))
            }
        }))
        .with_state(s);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_str().unwrap();
    write_config(home, json!({ "gateway_url": format!("http://{}", addr) }));

    // Safe: df -h → allowed
    let r = run_guard_stdin(home, &json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "df -h" }
    }).to_string());
    assert_eq!(r.code, 0, "df -h should be allowed");

    // Safe: ls → allowed
    let r = run_guard_stdin(home, &json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "ls" }
    }).to_string());
    assert_eq!(r.code, 0, "ls should be allowed");

    // Credential: SSH private key via Read → blocked
    let r = run_guard_stdin(home, &json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/home/user/.ssh/id_rsa" }
    }).to_string());
    assert_eq!(r.code, 2, "SSH private key read should be blocked");

    // Credential: SSH public key via Bash → blocked
    let r = run_guard_stdin(home, &json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "cat ~/.ssh/id_rsa.pub" }
    }).to_string());
    assert_eq!(r.code, 2, "SSH public key cat should be blocked");

    // Credential: /etc/shadow → blocked
    let r = run_guard_stdin(home, &json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/shadow" }
    }).to_string());
    assert_eq!(r.code, 2, "/etc/shadow should be blocked");

    // Credential: /etc/passwd via Bash → blocked
    let r = run_guard_stdin(home, &json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "cat /etc/passwd" }
    }).to_string());
    assert_eq!(r.code, 2, "/etc/passwd should be blocked");

    // PostToolUse: inspect safe output → allowed
    let r = run_guard_stdin(home, &json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "df -h" },
        "tool_response": { "stdout": "Filesystem Size Used", "stderr": "" }
    }).to_string());
    assert_eq!(r.code, 0, "PostToolUse inspect should allow safe output");

    // Verify request count: 6 pre + 1 post = 7
    let requests = state.requests.lock().unwrap();
    assert_eq!(requests.len(), 7);
}
