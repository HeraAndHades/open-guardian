use crate::proxy::ProxyClient;
use crate::security::{
    redact_pii, check_for_violations, analyze_injection,
    Judge, ThreatEngine, DlpAction,
};
use crate::config::{JudgeConfig, RouteConfig, PolicyConfig, PolicyAction};
use crate::banner;
use colored::Colorize;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use serde_json::Value;
use chrono::Utc;

pub struct ServerConfig {
    pub port: u16,
    pub default_upstream: String,
    pub routes: HashMap<String, RouteConfig>,
    pub judge_config: JudgeConfig,
    pub audit_log_path: Option<String>,
    pub block_threshold: Option<u32>,
    pub requests_per_minute: Option<u32>,
    pub timeout_seconds: u64,
    pub verbose: bool,
    pub policies: PolicyConfig,
}

#[derive(Clone)]
struct AppState {
    proxy: Arc<ProxyClient>,
    judge: Arc<Judge>,
    threat_engine: Arc<ThreatEngine>,
    default_upstream: String,
    routes: HashMap<String, RouteConfig>,
    audit_log_path: Option<String>,
    block_threshold: u32,
    rate_limiter: Option<Arc<tokio::sync::Mutex<HashMap<String, (u32, std::time::Instant)>>>>,
    rate_limit_requests_per_minute: u32,
    verbose: bool,
    // Policy settings
    default_action: PolicyAction,
    dlp_action: DlpAction,
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK\n")
}

pub async fn start_server(config: ServerConfig, shutdown_token: tokio_util::sync::CancellationToken) -> anyhow::Result<()> {
    let proxy = ProxyClient::new(config.timeout_seconds)?;
    let judge = Judge::new(config.judge_config.clone());
    let threat_engine = ThreatEngine::new(
        &config.policies.threats_path,
        config.policies.allowed_patterns.clone(),
    );
    
    let default_action = PolicyAction::from_str(&config.policies.default_action);
    let dlp_action = DlpAction::from_str(&config.policies.dlp_action);

    let state = AppState {
        proxy: Arc::new(proxy),
        judge: Arc::new(judge),
        threat_engine: Arc::new(threat_engine),
        default_upstream: config.default_upstream.clone(),
        routes: config.routes,
        audit_log_path: config.audit_log_path.clone(),
        block_threshold: config.block_threshold.unwrap_or(50),
        rate_limiter: Some(Arc::new(tokio::sync::Mutex::new(HashMap::new()))),
        rate_limit_requests_per_minute: config.requests_per_minute.unwrap_or(u32::MAX),
        verbose: config.verbose,
        default_action,
        dlp_action,
    };

    let app = Router::new()
        .route("/health", any(health_handler))
        .route("/*path", any(handler))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    banner::print_step(&format!("Shield active on {}", addr));
    banner::print_step(&format!("Default upstream target: {}", config.default_upstream));
    banner::print_step(&format!("Policy: default_action={:?}, dlp_action={:?}", default_action, dlp_action));
    
    if config.judge_config.ai_judge_enabled.unwrap_or(false) {
        banner::print_step(&format!("AI Administrative Judge active (The Sheriff) — Model: {}", 
            config.judge_config.ai_judge_model.as_ref().unwrap_or(&"gemma3:1b".to_string())));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    tracing::info!("Server listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_token.cancelled().await;
            banner::print_success("Shutdown signal received. Closing server...");
            tracing::info!("Server shutting down gracefully");
        })
        .await?;

    Ok(())
}

fn extract_full_content(content: &Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    
    if let Some(parts) = content.as_array() {
        let mut full_text = String::new();
        for part in parts {
            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                full_text.push_str(text);
                full_text.push(' ');
            }
        }
        return full_text.trim().to_string();
    }
    
    String::new()
}

fn log_security_event(path: Option<String>, event: Value) {
    tokio::spawn(async move {
        if let Some(log_path) = path {
            if let Ok(line) = serde_json::to_string(&event) {
                use tokio::io::AsyncWriteExt;
                if let Ok(mut file) = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path).await {
                    let _ = file.write_all(format!("{}\n", line).as_bytes()).await;
                }
            }
        }
    });
}

/// Build the 403 Forbidden response for policy violations.
fn block_response(category: &str, detail: &str, message: &str) -> Response {
    let error_msg = serde_json::json!({
        "error": "policy_violation",
        "category": category,
        "details": detail,
        "message": message
    });
    let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body
    ).into_response()
}

// ================================================================
// THE PIPELINE ORCHESTRATOR — Strict 3-Layer Enforcement
// ================================================================
// Layer 1: Heuristic Engine (CPU — Fast — Always On)
//   a. DLP → Redact PII / Block if policy=Block
//   b. Injection Scanner → Block if score ≥ threshold
//   c. Threat Engine Signatures → Block if match found
//
// Layer 2: Cognitive Engine (GPU — Optional)
//   RAG context from ThreatEngine → moka cache → Semaphore → LLM
//
// Layer 3: Final Execution
//   Block → 403 | Audit → Log + Header + Forward | Allow → Forward
// ================================================================
async fn handler(
    State(state): State<AppState>,
    method: Method,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let global_start = std::time::Instant::now();
    let path_str = format!("/{}", path);
    tracing::info!("{} request to {}", method, path_str);
    
    if state.verbose {
        println!("{} {} {}", "INCOMING:".bright_black(), method, path_str);
    }

    // ── Rate Limiting ──
    if let Some(limiter) = &state.rate_limiter {
        let mut lock = limiter.lock().await;
        let now = std::time::Instant::now();
        let entry = lock.entry("global".to_string()).or_insert((0, now));
        
        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (1, now);
        } else if entry.0 >= state.rate_limit_requests_per_minute {
            banner::print_warning("Global Rate Limit Exceeded");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                "{\"error\": \"rate_limit_exceeded\"}\n"
            ).into_response();
        } else {
            entry.0 += 1;
        }
    }

    // ── Parse JSON body ──
    if let Ok(mut json_body) = serde_json::from_slice::<Value>(&body) {
        let model_alias = json_body.get("model").and_then(|m| m.as_str()).unwrap_or("default").to_string();
        let route = state.routes.get(&model_alias);
        
        // Rewrite model if a real model name is provided in the config
        if let Some(r) = route {
            if let Some(real_model) = &r.model {
                if let Some(m_val) = json_body.get_mut("model") {
                    tracing::info!("Rewriting model alias '{}' to '{}'", model_alias, real_model);
                    *m_val = serde_json::Value::String(real_model.clone());
                }
            }
        }

        let upstream_url = route.map(|r| r.url.clone()).unwrap_or_else(|| state.default_upstream.clone());
        let api_key_env = route.and_then(|r| r.key_env.as_deref());

        let mut modified = true;
        let mut risk_level: Option<&str> = None; // For X-Guardian-Risk header in audit mode

        if let Some(messages) = json_body.get_mut("messages").and_then(|m| m.as_array_mut()) {
            for message in messages {
                let role = message.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                if role != "user" && role != "system" {
                    continue;
                }

                let content_raw = message.get("content").unwrap_or(&Value::Null);
                let content_text = extract_full_content(content_raw);
                
                if content_text.is_empty() {
                    continue;
                }

                // ════════════════════════════════════════════════════
                // LAYER 1: HEURISTIC ENGINE (CPU — Sub-millisecond)
                // ════════════════════════════════════════════════════

                // ── Step 1a: DLP (Data Loss Prevention) ──
                let dlp_start = std::time::Instant::now();
                match state.dlp_action {
                    DlpAction::Block => {
                        if let Some(violation) = check_for_violations(&content_text) {
                            if state.verbose { println!("   {} DLP block check: {:?}", "DEBUG:".bright_black(), dlp_start.elapsed()); }
                            
                            banner::print_warning(&format!("DLP BLOCKED: {} in {}", violation.description, path_str));
                            log_security_event(state.audit_log_path.clone(), serde_json::json!({
                                "timestamp": Utc::now().to_rfc3339(),
                                "event": "dlp_blocked",
                                "path": path_str,
                                "category": violation.category,
                                "description": violation.description
                            }));

                            return block_response(
                                &violation.category,
                                "dlp_violation",
                                &format!("Access Denied: {}", violation.description)
                            );
                        }
                    }
                    DlpAction::Redact => {
                        let cleaned = redact_pii(&content_text);
                        if state.verbose { println!("   {} DLP redact check: {:?}", "DEBUG:".bright_black(), dlp_start.elapsed()); }

                        if cleaned != content_text {
                            banner::print_success(&format!("Redacted sensitive data in request to {}", path_str));
                            tracing::info!("DLP redaction applied for request to {}", path_str);
                            modified = true;

                            log_security_event(state.audit_log_path.clone(), serde_json::json!({
                                "timestamp": Utc::now().to_rfc3339(),
                                "event": "data_redacted",
                                "path": path_str
                            }));

                            if let Some(content_val) = message.get_mut("content") {
                                if content_val.is_string() {
                                    *content_val = Value::String(cleaned.clone());
                                } else if let Some(parts) = content_val.as_array_mut() {
                                    for part in parts {
                                        if let Some(text_val) = part.get("text").and_then(|t| t.as_str()) {
                                            let part_cleaned = redact_pii(text_val);
                                            if let Some(t) = part.get_mut("text") {
                                                *t = Value::String(part_cleaned);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Get current content text (possibly redacted)
                let current_content = extract_full_content(message.get("content").unwrap_or(&Value::Null));
                let scan_text = if current_content.is_empty() { &content_text } else { &current_content };

                // ── Step 1b: Injection Scanner ──
                let inj_start = std::time::Instant::now();
                let security_report = analyze_injection(scan_text);
                if state.verbose { println!("   {} Injection check: {:?} (score={})", "DEBUG:".bright_black(), inj_start.elapsed(), security_report.score); }

                if security_report.score >= state.block_threshold {
                    let category_str = format!("{:?}", security_report.category);
                    banner::print_warning(&format!("Blocked {:?} attempt in {} (score={})", security_report.category, path_str, security_report.score));
                    
                    log_security_event(state.audit_log_path.clone(), serde_json::json!({
                        "timestamp": Utc::now().to_rfc3339(),
                        "event": "injection_blocked",
                        "path": path_str,
                        "category": category_str,
                        "score": security_report.score
                    }));

                    match state.default_action {
                        PolicyAction::Audit => {
                            risk_level = Some("High");
                            tracing::warn!("AUDIT: Injection detected (score={}, category={}) but forwarding per audit policy", security_report.score, category_str);
                        }
                        PolicyAction::Allow => {
                            // Allow policy: log but don't block
                            tracing::warn!("ALLOW: Injection detected but policy is 'allow'");
                        }
                        _ => {
                            return block_response(
                                &category_str,
                                "heuristic_injection_detected",
                                "Access Denied: Potential Prompt Injection Detected by Heuristic Guard"
                            );
                        }
                    }
                }

                // ── Step 1c: Threat Engine Signatures ──
                let sig_start = std::time::Instant::now();
                let threat_match = state.threat_engine.check_signatures(scan_text);
                if state.verbose { println!("   {} Threat signatures: {:?}", "DEBUG:".bright_black(), sig_start.elapsed()); }

                if let Some(ref tm) = threat_match {
                    banner::print_warning(&format!("Threat signature match: {} ({}, severity={})", tm.id, tm.category, tm.severity));
                    
                    log_security_event(state.audit_log_path.clone(), serde_json::json!({
                        "timestamp": Utc::now().to_rfc3339(),
                        "event": "threat_signature_match",
                        "path": path_str,
                        "threat_id": tm.id,
                        "category": tm.category,
                        "severity": tm.severity,
                        "matched_pattern": tm.matched_pattern
                    }));

                    match state.default_action {
                        PolicyAction::Audit => {
                            risk_level = Some("Critical");
                            tracing::warn!("AUDIT: Threat signature {} matched but forwarding per audit policy", tm.id);
                        }
                        PolicyAction::Allow => {
                            tracing::warn!("ALLOW: Threat signature {} matched but policy is 'allow'", tm.id);
                        }
                        _ => {
                            return block_response(
                                &tm.category,
                                &format!("threat_signature:{}", tm.id),
                                &format!("Access Denied: Known threat pattern detected ({})", tm.category)
                            );
                        }
                    }
                }

                // ════════════════════════════════════════════════════
                // LAYER 2: COGNITIVE ENGINE (GPU — Optional)
                // ════════════════════════════════════════════════════
                // Runs ONLY if Layer 1 passes AND judge.enabled = true

                let judge_start = std::time::Instant::now();
                
                // RAG Retrieval: get similar threats for context injection
                let similar_threats = state.threat_engine.find_similar(scan_text, 0.4);
                if state.verbose && !similar_threats.is_empty() {
                    println!("   {} RAG context: {} similar threats found", "DEBUG:".bright_black(), similar_threats.len());
                }

                let judge_passed = state.judge.check_prompt(scan_text, &similar_threats).await;
                if state.verbose { println!("   {} AI Judge check: {:?}", "DEBUG:".bright_black(), judge_start.elapsed()); }

                if !judge_passed {
                    banner::print_error(&format!("AI Judge blocked request to {}: Violates Safety Policy", path_str));
                    tracing::error!("Semantic policy block by AI Judge for request to {}", path_str);
                    
                    log_security_event(state.audit_log_path.clone(), serde_json::json!({
                        "timestamp": Utc::now().to_rfc3339(),
                        "event": "semantic_blocked",
                        "path": path_str,
                        "similar_threats": similar_threats.len()
                    }));

                    match state.default_action {
                        PolicyAction::Audit => {
                            risk_level = Some("High");
                            tracing::warn!("AUDIT: AI Judge flagged request but forwarding per audit policy");
                        }
                        PolicyAction::Allow => {
                            tracing::warn!("ALLOW: AI Judge flagged request but policy is 'allow'");
                        }
                        _ => {
                            return block_response(
                                "SemanticViolation",
                                "semantic_violation_detected",
                                "Access Denied: Your request was blocked by the AI Governance Engine (The Sheriff)."
                            );
                        }
                    }
                }
            }
        }
        
        // ════════════════════════════════════════════════════
        // LAYER 3: FINAL EXECUTION
        // ════════════════════════════════════════════════════
        let final_body = if modified {
            Bytes::from(serde_json::to_vec(&json_body).unwrap_or_else(|_| body.to_vec()))
        } else {
            body.clone()
        };
        
        banner::print_step(&format!("Forwarding to [{}] target: {}...", model_alias, upstream_url));
        let response = match state.proxy.forward_request(&upstream_url, api_key_env, method, &path_str, headers, final_body).await {
            Ok(mut res) => {
                // Inject X-Guardian-Risk header in audit mode
                if let Some(level) = risk_level {
                    if let Ok(hv) = axum::http::HeaderValue::from_str(level) {
                        res.headers_mut().insert("x-guardian-risk", hv);
                    }
                    tracing::warn!("AUDIT MODE: Request forwarded with X-Guardian-Risk: {}", level);
                }
                res
            }
            Err(e) => {
                banner::print_error(&format!("Internal Proxy Error: {}", e));
                let error_msg = serde_json::json!({
                    "error": "proxy_internal_error",
                    "message": format!("Internal failure in proxy: {}", e)
                });
                let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body
                ).into_response()
            }
        };

        if state.verbose {
            println!("{} Total processed in {:?}", "SHIELD:".bright_green(), global_start.elapsed());
        }
        response
    } else {
        // Non-JSON passthrough
        let upstream_url = state.default_upstream.clone();
        let response = match state.proxy.forward_request(&upstream_url, None, method, &path_str, headers, body).await {
            Ok(res) => res,
            Err(e) => {
                banner::print_error(&format!("Internal Proxy Error: {}", e));
                let error_msg = serde_json::json!({
                    "error": "proxy_internal_error",
                    "message": format!("Internal failure in proxy: {}", e)
                });
                let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body
                ).into_response()
            }
        };

        if state.verbose {
            banner::print_warning(&format!("Non-JSON request to {}: Skipping security logic.", path_str));
            println!("{} Total processed (Passthrough) in {:?}", "SHIELD:".bright_green(), global_start.elapsed());
        }
        response
    }
}
