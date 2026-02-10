use crate::proxy::ProxyClient;
use crate::security::{redact_pii, Judge};
use crate::config::{JudgeConfig, RouteConfig};
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
}

#[derive(Clone)]
struct AppState {
    proxy: Arc<ProxyClient>,
    judge: Arc<Judge>,
    default_upstream: String,
    routes: HashMap<String, RouteConfig>,
    audit_log_path: Option<String>,
    block_threshold: u32,
    rate_limiter: Option<Arc<tokio::sync::Mutex<HashMap<String, (u32, std::time::Instant)>>>>,
    rate_limit_requests_per_minute: u32,
    verbose: bool,
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK\n")
}

pub async fn start_server(config: ServerConfig, shutdown_token: tokio_util::sync::CancellationToken) -> anyhow::Result<()> {
    let proxy = ProxyClient::new(config.timeout_seconds)?;
    let judge = Judge::new(config.judge_config.clone());
    
    let state = AppState {
        proxy: Arc::new(proxy),
        judge: Arc::new(judge),
        default_upstream: config.default_upstream.clone(),
        routes: config.routes,
        audit_log_path: config.audit_log_path.clone(),
        block_threshold: config.block_threshold.unwrap_or(50),
        rate_limiter: Some(Arc::new(tokio::sync::Mutex::new(HashMap::new()))),
        rate_limit_requests_per_minute: config.requests_per_minute.unwrap_or(u32::MAX),
        verbose: config.verbose,
    };

    let app = Router::new()
        .route("/health", any(health_handler))
        .route("/*path", any(handler))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    banner::print_step(&format!("Shield active on {}", addr));
    banner::print_step(&format!("Default upstream target: {}", config.default_upstream));
    
    if config.judge_config.ai_judge_enabled.unwrap_or(false) {
        banner::print_step(&format!("AI Administrative Judge active (The Sheriff) - Model: {}", 
            config.judge_config.ai_judge_model.as_ref().unwrap_or(&"llama3.2:1b".to_string())));
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

        let mut modified = true; // Set to true because we might have rewritten the model

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

                let inj_start = std::time::Instant::now();
                let security_report = crate::security::analyze_injection(&content_text);
                if state.verbose { println!("   {} Injection check: {:?}", "DEBUG:".bright_black(), inj_start.elapsed()); }

                if security_report.score >= state.block_threshold {
                    banner::print_warning(&format!("Blocked {:?} attempt in {}", security_report.category, path_str));
                    
                    log_security_event(state.audit_log_path.clone(), serde_json::json!({
                        "timestamp": Utc::now().to_rfc3339(),
                        "event": "injection_blocked",
                        "path": path_str,
                        "category": format!("{:?}", security_report.category),
                        "score": security_report.score
                    }));

                    let error_msg = serde_json::json!({
                        "error": "policy_violation",
                        "details": "heuristic_injection_detected",
                        "category": format!("{:?}", security_report.category),
                        "message": "Access Denied: Potential Prompt Injection Detected by Heuristic Guard"
                    });
                    let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
                    return (
                        StatusCode::FORBIDDEN,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body
                    ).into_response();
                }

                let dlp_start = std::time::Instant::now();
                let cleaned = redact_pii(&content_text);
                if state.verbose { println!("   {} DLP check: {:?}", "DEBUG:".bright_black(), dlp_start.elapsed()); }

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

                let judge_start = std::time::Instant::now();
                let judge_passed = state.judge.check_prompt(&cleaned).await;
                if state.verbose { println!("   {} AI Judge check: {:?}", "DEBUG:".bright_black(), judge_start.elapsed()); }

                if !judge_passed {
                    banner::print_error(&format!("AI Judge blocked request to {}: Violates Safety Policy", path_str));
                    tracing::error!("Semantic policy block by AI Judge for request to {}: prompt='{}'", path_str, cleaned);
                    
                    log_security_event(state.audit_log_path.clone(), serde_json::json!({
                        "timestamp": Utc::now().to_rfc3339(),
                        "event": "semantic_blocked",
                        "path": path_str,
                        "prompt": cleaned
                    }));

                    let error_msg = serde_json::json!({
                        "error": "policy_violation",
                        "details": "semantic_violation_detected",
                        "message": "Access Denied: Your request was blocked by the AI Governance Engine (The Sheriff)."
                    });
                    let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
                    return (
                        StatusCode::FORBIDDEN,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body
                    ).into_response();
                }
            }
        }
        
        let final_body = if modified {
            Bytes::from(serde_json::to_vec(&json_body).unwrap_or_else(|_| body.to_vec()))
        } else {
            body.clone()
        };
        
        banner::print_step(&format!("Forwarding to [{}] target: {}...", model_alias, upstream_url));
        let response = match state.proxy.forward_request(&upstream_url, api_key_env, method, &path_str, headers, final_body).await {
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
            println!("{} Total processed in {:?}", "SHIELD:".bright_green(), global_start.elapsed());
        }
        response
    } else {
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
