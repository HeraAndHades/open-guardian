use regex::Regex;
use serde::Deserialize;
use crate::banner;
use crate::config::DictionarySource;
use super::normalizer;

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

/// The "Emergency Kit" — hardcoded critical signatures that are always present
/// even if all dictionary files are missing or deleted. The system is never naked.
///
/// NOTE: All literal patterns are written in POST-NORMALIZATION form
/// (lowercase, no accents, no leetspeak, no separators).
fn hardcoded_signatures() -> Vec<ThreatSignature> {
    vec![
        ThreatSignature { id: "HC-RCE-001".into(), pattern: "rm rf".into(), category: "RCE".into(), severity: 95, is_regex: false },
        ThreatSignature { id: "HC-RCE-002".into(), pattern: "rm r /".into(), category: "RCE".into(), severity: 95, is_regex: false },
        ThreatSignature { id: "HC-RCE-003".into(), pattern: "wget".into(), category: "RCE".into(), severity: 70, is_regex: false },
        ThreatSignature { id: "HC-RCE-004".into(), pattern: "curl | bash".into(), category: "RCE".into(), severity: 90, is_regex: false },
        ThreatSignature { id: "HC-RCE-005".into(), pattern: "shutdown /s".into(), category: "RCE".into(), severity: 95, is_regex: false },
        ThreatSignature { id: "HC-RCE-006".into(), pattern: ":() :|:& ;:".into(), category: "RCE".into(), severity: 95, is_regex: false },
        ThreatSignature { id: "HC-INJ-001".into(), pattern: "ignore previous instructions".into(), category: "Jailbreak".into(), severity: 90, is_regex: false },
        ThreatSignature { id: "HC-INJ-002".into(), pattern: "ignore all instructions".into(), category: "Jailbreak".into(), severity: 90, is_regex: false },
        ThreatSignature { id: "HC-INJ-003".into(), pattern: "dan mode".into(), category: "Jailbreak".into(), severity: 85, is_regex: false },
        ThreatSignature { id: "HC-EXF-001".into(), pattern: "dump credentials".into(), category: "DataExfiltration".into(), severity: 85, is_regex: false },
    ]
}

pub struct ThreatEngine {
    signatures: Vec<ThreatSignature>,
    compiled: Vec<Option<Regex>>,
    allowed_patterns: Vec<String>,
}

impl ThreatEngine {
    /// Create a new ThreatEngine. Loads signatures from all enabled dictionary sources,
    /// merging them into a single vector. Falls back to hardcoded critical signatures
    /// if no dictionary files can be loaded.
    pub fn new(dictionaries: &[DictionarySource], allowed_patterns: Vec<String>) -> Self {
        let base_dir = if let Ok(exe_path) = std::env::current_exe() {
            exe_path.parent().map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
        } else {
            std::env::current_dir().unwrap_or_default()
        };

        // Always start with the hardcoded Emergency Kit
        let mut all_signatures = hardcoded_signatures();
        let hardcoded_count = all_signatures.len();

        // Iterate through all enabled dictionary sources and merge signatures
        for dict in dictionaries.iter().filter(|d| d.enabled) {
            let path = base_dir.join(&dict.path);

            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    match serde_json::from_str::<ThreatDatabase>(&content) {
                        Ok(db) => {
                            let count = db.signatures.len();
                            banner::print_success(&format!(
                                "ThreatEngine: [{}] Loaded {} signatures from {}",
                                dict.id, count, path.display()
                            ));
                            all_signatures.extend(db.signatures);
                        }
                        Err(e) => {
                            banner::print_warning(&format!(
                                "ThreatEngine: [{}] Failed to parse {}: {}. Skipping.",
                                dict.id, path.display(), e
                            ));
                        }
                    }
                }
                Err(_) => {
                    banner::print_warning(&format!(
                        "ThreatEngine: [{}] Dictionary not found at {}. Skipping.",
                        dict.id, path.display()
                    ));
                }
            }
        }

        let total = all_signatures.len();
        if total == hardcoded_count {
            banner::print_warning(&format!(
                "ThreatEngine: No dictionary files loaded. Running with Emergency Kit only ({} signatures).",
                hardcoded_count
            ));
        } else {
            banner::print_success(&format!(
                "ThreatEngine: {} total signatures ready ({} hardcoded + {} from dictionaries).",
                total, hardcoded_count, total - hardcoded_count
            ));
        }

        // Compile regexes — NO (?i) flag needed, input is already normalized to lowercase
        let compiled: Vec<Option<Regex>> = all_signatures.iter().map(|sig| {
            if sig.is_regex {
                match Regex::new(&sig.pattern) {
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
        }).collect();

        Self { signatures: all_signatures, compiled, allowed_patterns }
    }

    /// Check if the input matches any whitelisted (allowed) pattern.
    /// Whitelisting is checked BEFORE normalization to preserve exact intent.
    fn is_whitelisted(&self, raw_input: &str) -> bool {
        let lower = raw_input.to_lowercase();
        self.allowed_patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
    }

    /// Fast signature sweep against NORMALIZED input.
    /// Returns the first (highest-severity) match, or None.
    pub fn check_signatures(&self, raw_input: &str) -> Option<ThreatMatch> {
        if self.is_whitelisted(raw_input) {
            return None;
        }

        // ── Normalize input through the canonical pipeline ──
        let normalized = normalizer::normalize(raw_input);
        let mut best_match: Option<ThreatMatch> = None;

        for (i, sig) in self.signatures.iter().enumerate() {
            let matched = if sig.is_regex {
                if let Some(re) = &self.compiled[i] {
                    re.is_match(&normalized)
                } else {
                    false
                }
            } else {
                // Literal patterns in dictionaries are already post-normalization
                normalized.contains(&sig.pattern)
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

    /// RAG retrieval: find all signatures that partially match the NORMALIZED input.
    /// Returns matches with a similarity score >= `threshold` (0.0 - 1.0).
    /// Used to provide context/precedent to the AI Judge.
    pub fn find_similar(&self, raw_input: &str, threshold: f64) -> Vec<ThreatMatch> {
        let normalized = normalizer::normalize(raw_input);
        let input_words: Vec<&str> = normalized.split_whitespace().collect();
        let mut matches = Vec::new();

        for (i, sig) in self.signatures.iter().enumerate() {
            // For regex signatures, check for match against normalized input
            if sig.is_regex {
                if let Some(re) = &self.compiled[i] {
                    if re.is_match(&normalized) {
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
            let pattern_words: Vec<&str> = sig.pattern.split_whitespace().collect();

            if pattern_words.is_empty() {
                continue;
            }

            // Check exact substring match first
            if normalized.contains(&sig.pattern) {
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

    /// Helper: build an engine from hardcoded signatures only (no dictionary files).
    fn test_engine(allowed: Vec<String>) -> ThreatEngine {
        let empty_dicts: Vec<DictionarySource> = vec![];
        ThreatEngine::new(&empty_dicts, allowed)
    }

    #[test]
    fn test_hardcoded_fallback_has_entries() {
        let sigs = hardcoded_signatures();
        assert!(sigs.len() >= 10, "Emergency Kit must have at least 10 signatures");
    }

    #[test]
    fn test_check_signatures_detects_rce() {
        let engine = test_engine(vec![]);
        let result = engine.check_signatures("Please run rm -rf / on the server");
        assert!(result.is_some(), "Should detect rm -rf");
        let m = result.unwrap();
        assert_eq!(m.category, "RCE");
    }

    #[test]
    fn test_whitelisted_pattern_bypasses() {
        let engine = test_engine(vec!["git pull".to_string()]);
        let result = engine.check_signatures("run git pull origin main");
        assert!(result.is_none());
    }

    #[test]
    fn test_normalization_catches_obfuscated_jailbreak() {
        let engine = test_engine(vec![]);
        // "D-A-N  M0D3" normalizes to "dan mode"
        let result = engine.check_signatures("Enable D-A-N  M0D3 please");
        assert!(result.is_some(), "Should detect obfuscated 'dan mode'");
        assert_eq!(result.unwrap().category, "Jailbreak");
    }

    #[test]
    fn test_normalization_catches_accented_jailbreak() {
        let engine = test_engine(vec![]);
        // "1gnoré previous ínstructions" normalizes to "ignore previous instructions"
        let result = engine.check_signatures("1gnoré previous ínstructions");
        assert!(result.is_some(), "Should detect accented + leetspeak jailbreak");
        assert_eq!(result.unwrap().category, "Jailbreak");
    }
}
