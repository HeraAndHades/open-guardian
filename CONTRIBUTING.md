# Contributing to Open-GuardIAn

Thank you for your interest in contributing to Open-GuardIAn! This document provides guidelines for contributing code, threat signatures, documentation, and other improvements.

---

## 🧭 Project Philosophy

Before contributing, understand our core principles:

1. **Agent-First** — We enable AI Agents to use tools, not block them blindly. `rm -rf /tmp/cache` for cleanup is legitimate. `rm -rf /` without context is not.
2. **Layered Defense** — Layer 1 (DLP + Regex) must work 100% without GPU. Layer 3 (AI Judge) is optional backup.
3. **Performance** — We compete against Python gateways. Heuristic checks must be sub-millisecond. Never add blocking I/O to the hot path.
4. **Fail-Safe** — The system must be secure even if all config files are deleted.

---

## 🚀 Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (1.70+)
- (Optional) [Ollama](https://ollama.ai/) running locally for AI Judge testing.
  - Recommended for testing: `ollama pull qwen2.5:0.5b`
  - Note: You can run tests without Ollama, but integration tests for Layer 3 will be skipped or mocked.

### Development Setup

```bash
# Clone the repo
git clone https://github.com/AnthonySmith96/open-guardian.git
cd open-guardian

# Build in debug mode (faster compile)
cargo build

# Run tests
cargo test

# Run with verbose output
cargo run -- start --verbose
```

### Project Structure

```
src/
├── security/
│   ├── dlp.rs              # DLP Anonymizer — PII/Secret detection & redaction
│   ├── normalizer.rs       # Code-aware text normalization (lowercase, de-accent)
│   ├── injection_scanner.rs # Adversarial pattern scoring engine
│   ├── threat_engine.rs    # Signature database + Emergency Kit + RAG retrieval
│   └── judge.rs            # AI Judge (qwen3:4b via Ollama)
├── server.rs               # Axum server & 3-layer pipeline orchestrator
├── config.rs               # TOML config loader
└── main.rs                 # CLI entry point
rules/                      # Modular threat dictionaries (JSON)
guardian.toml               # Runtime configuration
```

---

## 📋 How To Contribute

### 1. Adding Threat Signatures

This is the **easiest** and **most impactful** way to contribute.

**Where**: `rules/` directory

**Format**:
```json
{
  "signatures": [
    {
      "id": "UNIQUE-ID-001",
      "pattern": "your normalized pattern",
      "category": "CategoryName",
      "severity": 80,
      "is_regex": false
    }
  ]
}
```

**Rules for patterns**:
- All patterns must be **NORMALIZED**: lowercase, no accents (`ñ` → `n`, `é` → `e`), no leetspeak
- The normalizer preserves code syntax: `{ } ( ) [ ] . , ; : / \ < > = + - * & | ^ % $ @ # ! ? " ' ~`
- Test your pattern against the normalizer: `cargo test -- normalizer`

**Severity guide**:

| Severity | When to use | Examples |
|----------|------------|---------|
| 100 | Always block. Active exploit. | `cat /etc/passwd`, `drop table`, `{{7*7}}` |
| 95 | Always block. Jailbreak/prompt leak. | `ignore previous instructions`, `god mode` |
| 80 | Tag & Audit. Risky tool (Agent-First). | `rm -rf`, `curl`, `wget`, `chmod` |
| 70 | Context signal. Suspicious topic. | `hacker`, `malware`, `act as` |

**Adding a new language/category**:
1. Create `rules/jailbreaks_fr.json` (or your language)
2. Add to `guardian.toml`:
   ```toml
   [[security.dictionaries]]
   id = "jailbreaks_fr"
   path = "rules/jailbreaks_fr.json"
   enabled = true
   ```
3. Submit a PR with test evidence

---

### 2. Adding DLP Patterns

**Where**: `src/security/dlp.rs`

To add a new secret/PII pattern:
1. Add a `OnceLock<Regex>` static at the top
2. Create an `fn your_re()` helper function
3. Add the pattern to `check_for_violations()` and `redact_pii()`
4. Use an appropriate anonymizer token (e.g., `<YOUR_TOKEN>`)
5. Add tests

**Token naming convention**: `<TYPE>` format — e.g., `<EMAIL>`, `<KEY>`, `<AWS_KEY>`, `<SSN>`.

---

### 3. Adding Scanner Modules

**Where**: `src/security/`

If you want to add a new scanner type (e.g., code injection, prompt compression):
1. Create `src/security/your_scanner.rs`
2. Add `pub mod your_scanner;` to `src/security/mod.rs`
3. Integrate into the pipeline in `src/server.rs` (after DLP, before Threat Engine)
4. Add unit tests
5. Ensure it doesn't add blocking I/O to the hot path

---

### 4. Improving the AI Judge

**Where**: `src/security/judge.rs`

- System prompt improvements: more specific examples, better Agent-First logic
- Support for additional models (add model-specific formatting)
- Response parsing improvements

---

## ✅ Pull Request Checklist

Before submitting a PR, ensure:

- [ ] `cargo build --release` compiles with zero errors
- [ ] `cargo test` passes all tests
- [ ] New code includes unit tests
- [ ] Threat signatures are normalized (lowercase, no accents)
- [ ] DLP tokens follow `<TYPE>` naming convention
- [ ] No blocking I/O in the hot path (Layer 1 & 2)
- [ ] Severity levels follow the guide (100 = exploit, 95 = jailbreak, 80 = risky tool, 70 = context)
- [ ] Documentation is updated if behavior changes

---

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test -- dlp
cargo test -- normalizer
cargo test -- threat_engine
cargo test -- injection_scanner

# Run with output
cargo test -- --nocapture
```

### Test categories:
- **DLP**: Email, CC, SSN, IPv4, API keys (OpenAI, AWS, GitHub, Slack, Groq), violation checks
- **Normalizer**: Lowercase, de-accent, syntax preservation, SSTI, SQL, shell operators
- **Threat Engine**: Sev 100 blocking, Sev 80 tagging, SSTI regex, whitelisting
- **Injection Scanner**: Jailbreak, prompt extraction, RCE, safe input

---

## 🐛 Reporting Issues

When reporting a bug, include:
1. The input prompt that caused the issue
2. Expected behavior vs actual behavior
3. Your `guardian.toml` config (redact API keys)
4. Output from `--verbose` mode
5. OS and Rust version

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

<p align="center">
  <strong>Thank you for helping make AI safer. 🛡️</strong>
</p>
