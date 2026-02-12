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

#[derive(Deserialize, Debug, Default, Clone)]
pub struct SecurityConfig {
    pub audit_log_path: Option<String>,
    pub block_threshold: Option<u32>,
    pub policies: Option<PolicyConfig>,
    pub dlp: Option<DlpConfig>,
}

/// Per-category DLP toggle switches.
/// All default to `true` — disable specific categories as needed.
#[derive(Deserialize, Debug, Clone)]
pub struct DlpConfig {
    #[serde(default = "DlpConfig::default_true")]
    pub email_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub credit_card_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub secret_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub ssn_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub ip_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub phone_redaction: bool,
}

impl DlpConfig {
    fn default_true() -> bool { true }
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            email_redaction: true,
            credit_card_redaction: true,
            secret_redaction: true,
            ssn_redaction: true,
            ip_redaction: true,
            phone_redaction: true,
        }
    }
}

/// A single dictionary source for threat signatures.
#[derive(Deserialize, Debug, Clone)]
pub struct DictionarySource {
    pub id: String,
    pub path: String,
    #[serde(default = "DictionarySource::default_enabled")]
    pub enabled: bool,
}

impl DictionarySource {
    fn default_enabled() -> bool { true }
}

/// Policy configuration: "Secure by Default, Configurable by Choice."
#[derive(Deserialize, Debug, Clone)]
pub struct PolicyConfig {
    /// Default action when a threat is detected: block, audit, redact, allow
    #[serde(default = "PolicyConfig::default_action")]
    pub default_action: String,

    /// DLP action: "block" or "redact"
    #[serde(default = "PolicyConfig::default_dlp_action")]
    pub dlp_action: String,

    /// Modular threat dictionaries (replaces old threats_path)
    #[serde(default = "PolicyConfig::default_dictionaries")]
    pub dictionaries: Vec<DictionarySource>,

    /// Whitelisted patterns (DevOps Mode) — these bypass the Threat Engine
    #[serde(default)]
    pub allowed_patterns: Vec<String>,
}

impl PolicyConfig {
    fn default_action() -> String { "block".to_string() }
    fn default_dlp_action() -> String { "redact".to_string() }
    fn default_dictionaries() -> Vec<DictionarySource> {
        vec![
            DictionarySource { id: "common".into(), path: "rules/common.json".into(), enabled: true },
            DictionarySource { id: "jailbreaks_en".into(), path: "rules/jailbreaks_en.json".into(), enabled: true },
            DictionarySource { id: "jailbreaks_es".into(), path: "rules/jailbreaks_es.json".into(), enabled: true },
        ]
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: Self::default_action(),
            dlp_action: Self::default_dlp_action(),
            dictionaries: Self::default_dictionaries(),
            allowed_patterns: Vec::new(),
        }
    }
}

/// Parsed policy action enum used at runtime.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PolicyAction {
    Block,
    Audit,
    Redact,
    Allow,
}

impl PolicyAction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "audit" => PolicyAction::Audit,
            "redact" => PolicyAction::Redact,
            "allow" => PolicyAction::Allow,
            _ => PolicyAction::Block, // secure default
        }
    }
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
