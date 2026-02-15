pub mod dlp;
pub mod injection_scanner;
pub mod judge;
pub mod normalizer;
pub mod threat_engine;

// New Phase 1-2 security modules
pub mod env_security;
pub mod integrity;
pub mod path_security;
pub mod rate_limit;
pub mod smuggling;

pub use dlp::{check_for_violations, redact_pii, DlpAction};
pub use injection_scanner::analyze_injection;
pub use judge::Judge;
pub use threat_engine::ThreatEngine;

// Re-export new security module types
pub use integrity::{
    compute_hmac, emergency_kit, verify_all_rules, RuleIntegrityChecker, RuleManifest,
    RuleVerificationResult,
};
pub use normalizer::{
    normalize_unicode, NormalizationResult, UnicodeNormalizer, UnicodeNormalizerConfig,
};
pub use path_security::{
    is_path_safe, sanitize_path, validate_path, PathSecurity, PathSecurityConfig,
    PathValidationError, PathValidationResult,
};
pub use rate_limit::{
    apply_rate_limit, extract_client_ip, PerIpRateLimiter, RateLimitCheck, RateLimitConfig,
    RateLimitStats, TrafficClass,
};
pub use smuggling::{
    check_request_headers, sanitize_headers, smuggling_blocked_response, HeaderSecurityResult,
    SmugglingProtectionConfig,
};

pub use env_security::{
    check_env_security, get_secret, validate_env_startup, EnvSecurityConfig, EnvSecurityResult,
    SecretStore,
};
