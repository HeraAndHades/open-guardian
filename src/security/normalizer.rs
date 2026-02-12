use unidecode::unidecode;

/// Normalize input using a "Code-Aware" pipeline.
/// 
/// Logic:
/// 1. Lowercase
/// 2. De-unicode/ascii-folding (remove accents)
/// 3. CRITICAL: Preserve code syntax characters: { } ( ) [ ] . , ; : / \ < > = + - * & | ^ % $ @ # ! ? " ' ~
pub fn normalize(input: &str) -> String {
    // Stage 1: Lowercase
    let lowered = input.to_lowercase();

    // Stage 2: Unicode de-accent / ASCII folding
    let ascii = unidecode(&lowered);

    // Stage 3: Filter characters
    // Keep: Alphanumeric, Whitespace, and the Preserved Symbols
    let filtered: String = ascii.chars().filter(|c| {
        c.is_alphanumeric() 
        || c.is_whitespace() 
        || matches!(c, '{' | '}' | '(' | ')' | '[' | ']' | '.' | ',' | ';' | ':' | '/' | '\\' | '<' | '>' | '=' | '+' | '-' | '*' | '&' | '|' | '^' | '%' | '$' | '@' | '#' | '!' | '?' | '"' | '\'' | '~')
    }).collect();

    // Stage 4: Collapse whitespace (Optional but good for matching)
    // The spec doesn't explicitly forbid this, and it helps with "rm  -rf".
    filtered
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lowercase_and_deaccent() {
        assert_eq!(normalize("Héllò World"), "hello world");
    }

    #[test]
    fn test_preserves_syntax() {
        // SSTI
        assert_eq!(normalize("{{7*7}}"), "{{7*7}}");
        // RCE
        assert_eq!(normalize("System.exit(0)"), "system.exit(0)");
        assert_eq!(normalize("rm -rf /"), "rm -rf /");
        assert_eq!(normalize("cat /etc/passwd"), "cat /etc/passwd");
        assert_eq!(normalize("../../../etc/shadow"), "../../../etc/shadow");
    }

    #[test]
    fn test_shell_operators() {
        assert_eq!(normalize("curl | bash"), "curl | bash");
        assert_eq!(normalize("chmod +x script.sh"), "chmod +x script.sh");
        assert_eq!(normalize("./script.sh && whoami"), "./script.sh && whoami");
    }

    #[test]
    fn test_sql_syntax() {
        assert_eq!(normalize("SELECT * FROM users;"), "select * from users;");
        assert_eq!(normalize("DROP TABLE 'users' --"), "drop table 'users' --"); // -- comment style
    }

    #[test]
    fn test_special_chars() {
        // Check a mix of preserved chars
        let chars = "{}().[]./\\<>=+-*&|^%$@#!?\"\'~";
        assert_eq!(normalize(chars), chars);
    }
}
