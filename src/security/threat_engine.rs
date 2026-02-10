use regex::Regex;
use serde::Deserialize;
use std::sync::OnceLock;
use crate::banner;

/// A single threat signature from the database.
#[derive(Debug, Clone, Deserialize)]
pub struct ThreatSignature {
    pub id: String,
    pub pattern: String,
    pub category: String,
    pub severity: u32,
    #[serde(default)]
    pub is_regex: bool,
}

/// Result of a threat match.
#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub id: String,
    pub category: String,
    pub severity: u32,
    pub matched_pattern: String,
    /// Similarity score (0.0 - 1.0) for RAG retrieval, 1.0 = exact match.
    pub similarity: f64,
}

#[derive(Deserialize)]
struct ThreatDatabase {
    #[serde(default)]
    signatures: Vec<ThreatSignature>,
}

/// Global threat signatures loaded once via OnceLock for zero-allocation re-reads.
static THREAT_SIGNATURES: OnceLock<Vec<ThreatSignature>> = OnceLock::new();
static COMPILED_REGEXES: OnceLock<Vec<Option<Regex>>> = OnceLock::new();

/// The "Emergency Kit" — hardcoded critical signatures that are always present
/// even if threats.json is missing or deleted. The system is never naked.
fn hardcoded_signatures() -> Vec<ThreatSignature> {
    vec![
        ThreatSignature { id: "HC-RCE-001".into(), pattern: "rm -rf".into(), category: "RCE".into(), severity: 95, is_regex: false },
        ThreatSignature { id: "HC-RCE-002".into(), pattern: "rm -r /".into(), category: "RCE".into(), severity: 95, is_regex: false },
        ThreatSignature { id: "HC-RCE-003".into(), pattern: "wget".into(), category: "RCE".into(), severity: 70, is_regex: false },
        ThreatSignature { id: "HC-RCE-004".into(), pattern: "curl | bash".into(), category: "RCE".into(), severity: 90, is_regex: false },
        ThreatSignature { id: "HC-RCE-005".into(), pattern: "shutdown /s".into(), category: "RCE".into(), severity: 95, is_regex: false },
        ThreatSignature { id: "HC-RCE-006".into(), pattern: ":(){ :|:& };:".into(), category: "RCE".into(), severity: 95, is_regex: false },
        ThreatSignature { id: "HC-INJ-001".into(), pattern: "ignore previous instructions".into(), category: "Jailbreak".into(), severity: 90, is_regex: false },
        ThreatSignature { id: "HC-INJ-002".into(), pattern: "ignore all instructions".into(), category: "Jailbreak".into(), severity: 90, is_regex: false },
        ThreatSignature { id: "HC-INJ-003".into(), pattern: "DAN mode".into(), category: "Jailbreak".into(), severity: 85, is_regex: false },
        ThreatSignature { id: "HC-EXF-001".into(), pattern: "dump credentials".into(), category: "DataExfiltration".into(), severity: 85, is_regex: false },
    ]
}

pub struct ThreatEngine {
    signatures: &'static Vec<ThreatSignature>,
    compiled: &'static Vec<Option<Regex>>,
    allowed_patterns: Vec<String>,
}

impl ThreatEngine {
    /// Create a new ThreatEngine. Loads threats.json from `threats_path`, falling back
    /// to hardcoded critical signatures if the file is missing or malformed.
    pub fn new(threats_path: &str, allowed_patterns: Vec<String>) -> Self {
        let signatures = THREAT_SIGNATURES.get_or_init(|| {
            // Determine the base directory: the directory containing the executable
            let base_dir = if let Ok(exe_path) = std::env::current_exe() {
                exe_path.parent().map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
            } else {
                std::env::current_dir().unwrap_or_default()
            };

            let path = base_dir.join(threats_path);

            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    match serde_json::from_str::<ThreatDatabase>(&content) {
                        Ok(db) => {
                            let count = db.signatures.len();
                            banner::print_success(&format!(
                                "ThreatEngine: Loaded {} signatures from {}",
                                count, path.display()
                            ));
                            db.signatures
                        }
                        Err(e) => {
                            banner::print_warning(&format!(
                                "ThreatEngine: Failed to parse {}: {}. Using hardcoded fallback.",
                                path.display(), e
                            ));
                            hardcoded_signatures()
                        }
                    }
                }
                Err(_) => {
                    banner::print_warning(&format!(
                        "ThreatEngine: {} not found. Using hardcoded Emergency Kit ({} signatures).",
                        path.display(), hardcoded_signatures().len()
                    ));
                    hardcoded_signatures()
                }
            }
        });

        let compiled = COMPILED_REGEXES.get_or_init(|| {
            signatures.iter().map(|sig| {
                if sig.is_regex {
                    match Regex::new(&format!("(?i){}", sig.pattern)) {
                        Ok(re) => Some(re),
                        Err(e) => {
                            banner::print_warning(&format!(
                                "ThreatEngine: Invalid regex in {}: {} ({}). Skipping.",
                                sig.id, sig.pattern, e
                            ));
                            None
                        }
                    }
                } else {
                    None
                }
            }).collect()
        });

        Self { signatures, compiled, allowed_patterns }
    }

    /// Check if the input matches any whitelisted (allowed) pattern.
    fn is_whitelisted(&self, input: &str) -> bool {
        let lower = input.to_lowercase();
        self.allowed_patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
    }

    /// Fast signature sweep. Returns the first (highest-severity) match, or None.
    pub fn check_signatures(&self, input: &str) -> Option<ThreatMatch> {
        if self.is_whitelisted(input) {
            return None;
        }

        let lower_input = input.to_lowercase();
        let mut best_match: Option<ThreatMatch> = None;

        for (i, sig) in self.signatures.iter().enumerate() {
            let matched = if sig.is_regex {
                if let Some(re) = &self.compiled[i] {
                    re.is_match(input) || re.is_match(&lower_input)
                } else {
                    false
                }
            } else {
                lower_input.contains(&sig.pattern.to_lowercase())
            };

            if matched {
                let current_severity = best_match.as_ref().map(|m| m.severity).unwrap_or(0);
                if sig.severity > current_severity {
                    best_match = Some(ThreatMatch {
                        id: sig.id.clone(),
                        category: sig.category.clone(),
                        severity: sig.severity,
                        matched_pattern: sig.pattern.clone(),
                        similarity: 1.0,
                    });
                }
            }
        }

        best_match
    }

    /// RAG retrieval: find all signatures that partially match the input.
    /// Returns matches with a similarity score >= `threshold` (0.0 - 1.0).
    /// Used to provide context/precedent to the AI Judge.
    pub fn find_similar(&self, input: &str, threshold: f64) -> Vec<ThreatMatch> {
        let lower_input = input.to_lowercase();
        let input_words: Vec<&str> = lower_input.split_whitespace().collect();
        let mut matches = Vec::new();

        for (i, sig) in self.signatures.iter().enumerate() {
            // For regex signatures, check for partial match
            if sig.is_regex {
                if let Some(re) = &self.compiled[i] {
                    if re.is_match(input) || re.is_match(&lower_input) {
                        matches.push(ThreatMatch {
                            id: sig.id.clone(),
                            category: sig.category.clone(),
                            severity: sig.severity,
                            matched_pattern: sig.pattern.clone(),
                            similarity: 1.0,
                        });
                    }
                }
                continue;
            }

            // For literal patterns, compute word-level overlap as similarity
            let pattern_lower = sig.pattern.to_lowercase();
            let pattern_words: Vec<&str> = pattern_lower.split_whitespace().collect();

            if pattern_words.is_empty() {
                continue;
            }

            // Check exact substring match first
            if lower_input.contains(&pattern_lower) {
                matches.push(ThreatMatch {
                    id: sig.id.clone(),
                    category: sig.category.clone(),
                    severity: sig.severity,
                    matched_pattern: sig.pattern.clone(),
                    similarity: 1.0,
                });
                continue;
            }

            // Word overlap similarity
            let matching_words = pattern_words.iter()
                .filter(|pw| input_words.iter().any(|iw| iw.contains(*pw) || pw.contains(iw)))
                .count();

            let similarity = matching_words as f64 / pattern_words.len() as f64;

            if similarity >= threshold {
                matches.push(ThreatMatch {
                    id: sig.id.clone(),
                    category: sig.category.clone(),
                    severity: sig.severity,
                    matched_pattern: sig.pattern.clone(),
                    similarity,
                });
            }
        }

        // Sort by similarity descending
        matches.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal));
        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardcoded_fallback_has_entries() {
        let sigs = hardcoded_signatures();
        assert!(sigs.len() >= 10, "Emergency Kit must have at least 10 signatures");
    }

    #[test]
    fn test_check_signatures_detects_rce() {
        let engine = ThreatEngine {
            signatures: THREAT_SIGNATURES.get_or_init(hardcoded_signatures),
            compiled: COMPILED_REGEXES.get_or_init(|| {
                hardcoded_signatures().iter().map(|_| None).collect()
            }),
            allowed_patterns: vec![],
        };
        let result = engine.check_signatures("Please run rm -rf / on the server");
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.category, "RCE");
    }

    #[test]
    fn test_whitelisted_pattern_bypasses() {
        let engine = ThreatEngine {
            signatures: THREAT_SIGNATURES.get_or_init(hardcoded_signatures),
            compiled: COMPILED_REGEXES.get_or_init(|| {
                hardcoded_signatures().iter().map(|_| None).collect()
            }),
            allowed_patterns: vec!["git pull".to_string()],
        };
        // "git pull" is whitelisted, so even if it contained a threat keyword, it should pass
        let result = engine.check_signatures("run git pull origin main");
        assert!(result.is_none());
    }
}
