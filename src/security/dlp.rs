use regex::Regex;
use std::sync::OnceLock;

// ── PII Patterns ──
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static CC_REGEX: OnceLock<Regex> = OnceLock::new();
static PHONE_REGEX: OnceLock<Regex> = OnceLock::new();
static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
static SSN_REGEX: OnceLock<Regex> = OnceLock::new();

// ── Secret/Credential Patterns ──
static AWS_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static GITHUB_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
static OPENAI_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static GROQ_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static GENERIC_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
static BEARER_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();

/// DLP action policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DlpAction {
    /// Stop the request entirely if PII/secrets are found.
    Block,
    /// Replace sensitive data with [REDACTED_*] tags and forward.
    Redact,
}

impl DlpAction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "block" => DlpAction::Block,
            _ => DlpAction::Redact,
        }
    }
}

/// Violation details when DLP action is Block.
#[derive(Debug, Clone)]
pub struct DlpViolation {
    pub category: String,
    pub description: String,
}

/// Check if content contains any PII or secrets, returning a violation if found.
/// Used when DLP action is set to "block".
pub fn check_for_violations(content: &str) -> Option<DlpViolation> {
    let email_re = EMAIL_REGEX.get_or_init(|| Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap());
    let cc_re = CC_REGEX.get_or_init(|| Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap());
    let ssn_re = SSN_REGEX.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
    let aws_re = AWS_KEY_REGEX.get_or_init(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap());
    let github_re = GITHUB_TOKEN_REGEX.get_or_init(|| Regex::new(r"\b(gh[pous]_[a-zA-Z0-9]{36})\b").unwrap());
    let openai_re = OPENAI_KEY_REGEX.get_or_init(|| Regex::new(r"\bsk-[a-zA-Z0-9]{20,}\b").unwrap());
    let groq_re = GROQ_KEY_REGEX.get_or_init(|| Regex::new(r"\bgsk_[a-zA-Z0-9]{20,}\b").unwrap());

    if email_re.is_match(content) { return Some(DlpViolation { category: "PII".into(), description: "Email address detected".into() }); }
    if ssn_re.is_match(content) { return Some(DlpViolation { category: "PII".into(), description: "Social Security Number detected".into() }); }
    if cc_re.is_match(content) { return Some(DlpViolation { category: "PII".into(), description: "Credit card number detected".into() }); }
    if aws_re.is_match(content) { return Some(DlpViolation { category: "Secret".into(), description: "AWS access key detected".into() }); }
    if github_re.is_match(content) { return Some(DlpViolation { category: "Secret".into(), description: "GitHub token detected".into() }); }
    if openai_re.is_match(content) { return Some(DlpViolation { category: "Secret".into(), description: "OpenAI API key detected".into() }); }
    if groq_re.is_match(content) { return Some(DlpViolation { category: "Secret".into(), description: "Groq API key detected".into() }); }

    None
}

/// Redact PII and secrets from content, replacing with [REDACTED_*] tags.
/// Used when DLP action is set to "redact".
pub fn redact_pii(content: &str) -> String {
    let email_re = EMAIL_REGEX.get_or_init(|| Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap());
    let cc_re = CC_REGEX.get_or_init(|| Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap());
    let phone_re = PHONE_REGEX.get_or_init(|| Regex::new(r"\b(?:\+?\d{1,3}[-. ]?)?\(?\d{2,4}\)?[-. ]?\d{3,4}[-. ]?\d{3,4}\b").unwrap());
    let ipv4_re = IPV4_REGEX.get_or_init(|| Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap());
    let ssn_re = SSN_REGEX.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

    let aws_re = AWS_KEY_REGEX.get_or_init(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap());
    let github_re = GITHUB_TOKEN_REGEX.get_or_init(|| Regex::new(r"\b(gh[pous]_[a-zA-Z0-9]{36})\b").unwrap());
    let openai_re = OPENAI_KEY_REGEX.get_or_init(|| Regex::new(r"\bsk-[a-zA-Z0-9]{20,}\b").unwrap());
    let groq_re = GROQ_KEY_REGEX.get_or_init(|| Regex::new(r"\bgsk_[a-zA-Z0-9]{20,}\b").unwrap());
    let generic_re = GENERIC_SECRET_REGEX.get_or_init(|| Regex::new(r#"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#).unwrap());
    let bearer_re = BEARER_TOKEN_REGEX.get_or_init(|| Regex::new(r#"Bearer\s+[a-zA-Z0-9_\-\.]{20,}"#).unwrap());

    // Apply redactions in order: secrets first (more specific), then PII
    let mut redacted = aws_re.replace_all(content, "[REDACTED_AWS_KEY]").to_string();
    redacted = github_re.replace_all(&redacted, "[REDACTED_GITHUB_TOKEN]").to_string();
    redacted = openai_re.replace_all(&redacted, "[REDACTED_API_KEY]").to_string();
    redacted = groq_re.replace_all(&redacted, "[REDACTED_API_KEY]").to_string();
    redacted = generic_re.replace_all(&redacted, "[REDACTED_SECRET]").to_string();
    redacted = bearer_re.replace_all(&redacted, "[REDACTED_BEARER]").to_string();

    redacted = ssn_re.replace_all(&redacted, "[REDACTED_SSN]").to_string();
    redacted = email_re.replace_all(&redacted, "[REDACTED_EMAIL]").to_string();
    redacted = cc_re.replace_all(&redacted, "[REDACTED_CC]").to_string();
    redacted = phone_re.replace_all(&redacted, "[REDACTED_PHONE]").to_string();
    redacted = ipv4_re.replace_all(&redacted, "[REDACTED_IP]").to_string();

    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redaction() {
        let input = "Send an email to john.doe@example.com for info.";
        let expected = "Send an email to [REDACTED_EMAIL] for info.";
        assert_eq!(redact_pii(input), expected);
    }

    #[test]
    fn test_cc_redaction() {
        let input = "My card number is 1234-5678-9012-3456.";
        let expected = "My card number is [REDACTED_CC].";
        assert_eq!(redact_pii(input), expected);
    }

    #[test]
    fn test_ssn_redaction() {
        let input = "My SSN is 123-45-6789 please process.";
        let expected = "My SSN is [REDACTED_SSN] please process.";
        assert_eq!(redact_pii(input), expected);
    }

    #[test]
    fn test_openai_key_redaction() {
        let input = "My key is sk-abc123def456ghi789jklmnop and it works.";
        let expected = "My key is [REDACTED_API_KEY] and it works.";
        assert_eq!(redact_pii(input), expected);
    }

    #[test]
    fn test_aws_key_redaction() {
        let input = "Use key AKIAIOSFODNN7EXAMPLE for AWS.";
        let expected = "Use key [REDACTED_AWS_KEY] for AWS.";
        assert_eq!(redact_pii(input), expected);
    }

    #[test]
    fn test_check_violations_blocks_email() {
        let result = check_for_violations("Contact me at admin@secret.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().category, "PII");
    }

    #[test]
    fn test_clean_content_passes() {
        let result = check_for_violations("Tell me a joke about cats.");
        assert!(result.is_none());
    }
}
