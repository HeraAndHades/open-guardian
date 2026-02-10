use regex::Regex;
use std::sync::OnceLock;

static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static CC_REGEX: OnceLock<Regex> = OnceLock::new();
static PHONE_REGEX: OnceLock<Regex> = OnceLock::new();
static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
static AWS_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static GITHUB_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();

pub fn redact_pii(content: &str) -> String {
    let email_re = EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap()
    });

    let cc_re = CC_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap()
    });

    let phone_re = PHONE_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\+?\d{1,3}[-. ]?)?\(?\d{2,4}\)?[-. ]?\d{3,4}[-. ]?\d{3,4}\b").unwrap()
    });

    let ipv4_re = IPV4_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
    });

    let aws_re = AWS_KEY_REGEX.get_or_init(|| {
        Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()
    });

    let github_re = GITHUB_TOKEN_REGEX.get_or_init(|| {
        Regex::new(r"\b(gh[pous]_[a-zA-Z0-9]{36})\b").unwrap()
    });

    let mut redacted = email_re.replace_all(content, "[BLOCKED_EMAIL]").to_string();
    redacted = cc_re.replace_all(&redacted, "[BLOCKED_CC]").to_string();
    redacted = phone_re.replace_all(&redacted, "[BLOCKED_PHONE]").to_string();
    redacted = ipv4_re.replace_all(&redacted, "[BLOCKED_IP]").to_string();
    redacted = aws_re.replace_all(&redacted, "[BLOCKED_AWS_KEY]").to_string();
    redacted = github_re.replace_all(&redacted, "[BLOCKED_GITHUB_TOKEN]").to_string();

    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redaction() {
        let input = "Send an email to john.doe@example.com for info.";
        let expected = "Send an email to [BLOCKED_EMAIL] for info.";
        assert_eq!(redact_pii(input), expected);
    }

    #[test]
    fn test_cc_redaction() {
        let input = "My card number is 1234-5678-9012-3456.";
        let expected = "My card number is [BLOCKED_CC].";
        assert_eq!(redact_pii(input), expected);
    }
}
