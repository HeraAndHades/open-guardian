use serde::Deserialize;
use std::fs;
use std::collections::HashMap;
use crate::banner;

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    pub server: Option<ServerConfig>,
    pub security: Option<SecurityConfig>,
    pub judge: Option<JudgeConfig>,
    pub routes: Option<HashMap<String, RouteConfig>>,
}

#[derive(Deserialize, Debug, Default)]
pub struct ServerConfig {
    pub port: Option<u16>,
    pub default_upstream: Option<String>,
    pub requests_per_minute: Option<u32>,
}

#[derive(Deserialize, Debug, Default)]
pub struct SecurityConfig {
    pub audit_log_path: Option<String>,
    pub block_threshold: Option<u32>,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct JudgeConfig {
    pub ai_judge_enabled: Option<bool>,
    pub ai_judge_endpoint: Option<String>,
    pub ai_judge_model: Option<String>,
    pub judge_cache_ttl_seconds: Option<u64>,
    pub judge_max_concurrency: Option<usize>,
    pub fail_open: Option<bool>,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct RouteConfig {
    pub url: String,
    pub model: Option<String>,
    pub key_env: Option<String>,
}

pub fn load_config() -> Config {
    // Determine the base directory: the directory containing the executable.
    let base_dir = if let Ok(exe_path) = std::env::current_exe() {
        exe_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
    } else {
        std::env::current_dir().unwrap_or_default()
    };

    let path = base_dir.join("guardian.toml");

    if path.exists() {
        match fs::read_to_string(&path) {
            Ok(content) => {
                match toml::from_str::<Config>(&content) {
                    Ok(config) => {
                        banner::print_success(&format!("Loaded config from {}", path.display()));
                        return config;
                    }
                    Err(e) => banner::print_error(&format!("Failed to parse {}: {}", path.display(), e)),
                }
            }
            Err(e) => banner::print_error(&format!("Failed to read {}: {}", path.display(), e)),
        }
    } else {
        banner::print_warning(&format!("No guardian.toml found at {}. Using defaults.", path.display()));
    }
    Config::default()
}
