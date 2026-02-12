<p align="center">
  <h1 align="center">🛡️ Open-GuardIAn</h1>
  <p align="center"><strong>Stopping AI agents (and chatbots) from doing stupid things.</strong></p>
  <p align="center">
    <a href="#-quickstart"><img src="https://img.shields.io/badge/Get_Started-blue?style=for-the-badge" alt="Get Started"></a>
    <a href="#-architecture"><img src="https://img.shields.io/badge/Architecture-purple?style=for-the-badge" alt="Architecture"></a>
    <a href="#%EF%B8%8F-configuration"><img src="https://img.shields.io/badge/Configuration-green?style=for-the-badge" alt="Configuration"></a>
  </p>
</p>

---

Open-GuardIAn is a **high-performance security middleware / reverse proxy** built in Rust that sits between your applications and any LLM provider (OpenAI, Groq, Ollama, Anthropic, etc.). It enforces real-time governance policies to prevent data leaks, block prompt injections, and stop agents from executing dangerous actions — all before the request ever reaches the model.

```
 Your App ──▶ Open-GuardIAn ──▶ LLM Provider
                   │
            ┌──────┴───────┐
            │  DLP Scanner │  ← Redacts PII & secrets
            │  Injection   │  ← Blocks jailbreaks
            │  ThreatEngine│  ← OWASP/MITRE signatures
            │  AI Sheriff  │  ← Contextual AI judge (optional)
            └──────────────┘
```

## 🎯 Who Is This For?

| Audience | Problem We Solve |
|----------|-----------------|
| **Agent builders** (AutoGPT, CrewAI, LangChain) | Prevent agents from executing `rm -rf /`, `curl | bash`, or destroying infrastructure |
| **RAG chatbot developers** | Stop end-users from jailbreaking your bot, leaking system prompts, or exfiltrating PII |
| **Enterprise teams** | Enforce DLP policies — no API keys, SSNs, or credit cards ever leave your network |
| **AI platform operators** | Drop-in reverse proxy with zero code changes to existing OpenAI-compatible APIs |

## ✨ Key Features

### ⚡ Dual-Engine Architecture: Defense-in-Depth

Open-GuardIAn uses a **two-layer security model** — a fast heuristic layer handles 90% of threats deterministically, backed by an optional AI engine for the nuanced 10%.

#### Layer 1: Heuristic Engine (CPU — Sub-millisecond — Always On)

- **🔒 DLP (Data Loss Prevention)** — Regex-based detection & redaction of:
  - **PII**: Emails, SSNs, Credit Cards, Phone Numbers, IP Addresses
  - **Secrets**: AWS Keys (`AKIA...`), GitHub Tokens (`ghp_...`), OpenAI Keys (`sk-...`), Groq Keys (`gsk_...`), Bearer Tokens, Generic API Keys
  - Configurable action: **Block** (stop request) or **Redact** (replace with `[REDACTED_*]` tags)

- **🛡️ Injection Scanner** — Normalization-aware scoring engine that catches obfuscated attacks:
  - Defeats **leetspeak** (`J4ilbr3ak` → `jailbreak`)
  - 5 threat categories: Jailbreak, System Prompt Extraction, Roleplay, RCE, Data Exfiltration
  - ~40 weighted patterns with configurable score threshold

- **📋 Threat Engine (Project Babel)** — Modular, internationalized signature database:
  - **Modular Dictionaries**: Split into multiple JSON files (e.g., `common`, `jailbreaks_en`, `jailbreaks_es`) for easy maintenance.
  - **Normalization Pipeline**: All input is lowercased, de-accented (`Tú`→`tu`), de-leetspeak'd (`d4n`→`dan`), and stripped of symbol separators (`r-m`→`rm`) BEFORE matching.
  - **Emergency Kit**: 10 critical patterns hardcoded in Rust — the system is **never** unprotected, even if rule files are deleted.
  - **DevOps Whitelisting**: Explicitly allow commands like `git pull`, `kubectl apply`.

#### Layer 2: Cognitive Engine (The Sheriff — Optional)

- **🤠 AI Judge** — Uses a local LLM (via Ollama) for contextual intent analysis when heuristics are uncertain
- **RAG-Powered**: The Judge doesn't guess blindly — it receives similar threat patterns from the Threat Engine as precedent in its system prompt
- **Performance-Optimized**:
  - `moka` semantic cache — repeat prompts resolved in <1ms
  - `tokio::Semaphore` concurrency control — protects host resources
  - Configurable **fail-open** or **fail-closed** when the AI is unavailable

### 🛣️ Smart Multi-Provider Router

- Route requests to different LLM providers based on the `model` field
- Automatic **credential injection** from environment variables
- Model alias rewriting (e.g., `"llama-4"` → `"meta-llama/llama-4-maverick-17b-128e-instruct"`)
- Zero-config fallback to default upstream

### � Policy Manager (The Governor)

Four enforcement modes for every security check:

| Policy | Behavior |
|--------|----------|
| `block` | Return 403 Forbidden — request never reaches the LLM |
| `audit` | Log `WARN` + inject `X-Guardian-Risk: High` header + forward |
| `redact` | Sanitize sensitive data and forward |
| `allow` | No enforcement (not recommended for production) |

### 📝 Forensic Audit Logging

- All security events logged in **JSONL** format with timestamps
- Events: `injection_blocked`, `dlp_blocked`, `data_redacted`, `threat_signature_match`, `semantic_blocked`
- Easily ingestible by SIEM tools (Splunk, ELK, Datadog)

---

## 🚀 Quickstart

### Prerequisites

- [Rust](https://rustup.rs/) (1.70+)
- (Optional) [Ollama](https://ollama.ai/) for the AI Sheriff

### 1. Clone & Build

```bash
git clone https://github.com/your-org/open-guardian.git
cd open-guardian
cargo build --release
```

### 2. Configure

Create a `.env` file with your API keys:

```env
GROQ_API_KEY=gsk_your_key_here
OPENAI_API_KEY=sk-your_key_here
```

Edit `guardian.toml` to your needs (see [Configuration](#%EF%B8%8F-configuration) below), or run with the secure defaults.

### 3. Run the Shield

```bash
# Standard mode
./target/release/open-guardian start

# With verbose debug output
./target/release/open-guardian start --verbose

# Local-only mode (routes all traffic to Ollama)
./target/release/open-guardian start --local
```

### 4. Point Your App

Replace your LLM base URL with Open-GuardIAn:

```python
# Before
client = OpenAI(base_url="https://api.groq.com/openai/v1")

# After — all requests are now protected
client = OpenAI(base_url="http://localhost:8080/v1")
```

That's it. **Zero code changes** — Open-GuardIAn is API-compatible with OpenAI, Groq, Ollama, and any provider using the `/v1/chat/completions` standard.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     OPEN-GUARDIAN PROXY                         │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              LAYER 1: HEURISTIC ENGINE (CPU)              │  │
│  │  ┌─────────┐  ┌──────────────┐  ┌──────────────────────┐ │  │
│  │  │   DLP   │→ │  Injection   │→ │   Threat Engine      │ │  │
│  │  │ Scanner │  │   Scanner    │  │ (OWASP/MITRE + RAG)  │ │  │
│  │  └─────────┘  └──────────────┘  └──────────────────────┘ │  │
│  └───────────────────────┬───────────────────────────────────┘  │
│                          ▼                                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │        LAYER 2: COGNITIVE ENGINE (Optional GPU)           │  │
│  │  ┌─────────────┐  ┌─────────┐  ┌───────────────────────┐ │  │
│  │  │ RAG Context │→ │  Cache  │→ │  AI Judge (Ollama)    │ │  │
│  │  │  Retrieval  │  │ (moka)  │  │  + Semaphore Control  │ │  │
│  │  └─────────────┘  └─────────┘  └───────────────────────┘ │  │
│  └───────────────────────┬───────────────────────────────────┘  │
│                          ▼                                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │            LAYER 3: POLICY ENFORCEMENT                    │  │
│  │         Block (403) │ Audit (Log+Forward) │ Allow         │  │
│  └───────────────────────┬───────────────────────────────────┘  │
│                          ▼                                      │
│               Smart Router → Upstream LLM                       │
└─────────────────────────────────────────────────────────────────┘
```

### Pipeline Flow

1. **Incoming Request** → Rate limiter check
2. **Layer 1** (always runs, sub-ms):
   - **DLP**: Redact PII/secrets or block if policy = `block`
   - **Injection Scanner**: Score adversarial patterns → block if score ≥ threshold
   - **Threat Engine**: Match against OWASP/MITRE signature database
3. **Layer 2** (runs only if enabled and Layer 1 passes):
   - Retrieve similar threat patterns (RAG) → check moka cache → acquire semaphore → call AI Judge
4. **Layer 3**: Enforce verdict — `403 Block` / `Audit + Forward` / `Allow + Forward`

---

## ⚙️ Configuration

### `guardian.toml`

```toml
[server]
port = 8080
default_upstream = "https://api.groq.com/openai"
requests_per_minute = 60

[security]
audit_log_path = "guardian_audit.jsonl"
block_threshold = 50       # Injection score threshold (0-100)

[security.policies]
default_action = "block"   # block | audit | redact | allow
dlp_action = "redact"      # block | redact
allowed_patterns = ["git pull", "git push", "kubectl get", "kubectl apply"]

# Modular Threat Dictionaries (Project Babel)
[[security.dictionaries]]
id = "common"
path = "rules/common.json"
enabled = true

[[security.dictionaries]]
id = "jailbreaks_en"
path = "rules/jailbreaks_en.json"
enabled = true

[[security.dictionaries]]
id = "jailbreaks_es"
path = "rules/jailbreaks_es.json"
enabled = true

[judge]
ai_judge_enabled = true
ai_judge_endpoint = "http://127.0.0.1:11434/api/chat"
ai_judge_model = "gemma3:1b"
judge_cache_ttl_seconds = 60
judge_max_concurrency = 4
fail_open = true            # true = Prioritize reliability, false = Prioritize security

[routes]
"gpt-oss" = { url = "https://api.groq.com/openai", model = "openai/gpt-oss-120b", key_env = "GROQ_API_KEY" }
"llama-4" = { url = "https://api.groq.com/openai", model = "meta-llama/llama-4-maverick-17b-128e-instruct", key_env = "GROQ_API_KEY" }
"gpt-4o" = { url = "https://api.openai.com/v1", key_env = "OPENAI_API_KEY" }
"gemma3:1b" = { url = "http://127.0.0.1:11434/v1" }
```

### `rules/` Directory (Modular Dictionaries)

Add new languages or categories by creating a simple JSON file in `rules/` and adding it to `guardian.toml`. All patterns should be **NORMALIZED** (lowercase, no accents, no leetspeak).

**Example: `rules/jailbreaks_es.json` (Spanish)**
```json
{
  "signatures": [
    {
      "id": "JB-ES-001",
      "pattern": "tu eres dan",  // Normalized from "Tú eres DAN"
      "category": "Jailbreak",
      "severity": 90,
      "is_regex": false
    },
    {
      "id": "JB-ES-002",
      "pattern": "olvida tus reglas",
      "category": "Jailbreak",
      "severity": 90,
      "is_regex": false
    }
  ]
}
```

---

## 🔧 CLI Reference

```bash
# Start the proxy
open-guardian start [--port 8080] [--upstream URL] [--local] [--verbose]

# Security audit — scan for exposed secrets and misconfigurations
open-guardian audit [path]

# Service management (Windows/Linux/macOS)
open-guardian service install    # Install as system service
open-guardian service uninstall  # Remove system service
open-guardian service start      # Start the service
open-guardian service stop       # Stop the service
```

---

## 📁 Project Structure

```
open-guardian/
├── src/
│   ├── main.rs                    # CLI entry point & service management
│   ├── server.rs                  # Axum server & 3-layer pipeline orchestrator
│   ├── proxy.rs                   # Reqwest-based request forwarding
│   ├── config.rs                  # TOML config loader & policy definitions
│   ├── audit.rs                   # Static security analysis
│   ├── banner.rs                  # Terminal UI (colored output)
│   ├── logger.rs                  # Tracing/logging initialization
│   └── security/
│       ├── mod.rs                 # Module exports
│       ├── dlp.rs                 # Data Loss Prevention (PII + Secrets)
│       ├── injection_scanner.rs   # Adversarial pattern scoring engine
│       ├── threat_engine.rs       # Signature DB + Emergency Kit + RAG
│       └── judge.rs               # AI Sheriff (moka cache + semaphore + RAG)
├── guardian.toml                  # Runtime configuration
├── rules/                         # Modular threat dictionaries
│   ├── common.json                # Universal threats (RCE, SQLi, Secrets)
│   ├── jailbreaks_en.json         # English jailbreak patterns
│   └── jailbreaks_es.json         # Spanish jailbreak patterns
├── Cargo.toml                     # Rust dependencies
└── .env                           # API keys (gitignored)
```

---

## 🧪 Testing

```bash
# Run all unit tests
cargo test

# Current test coverage:
#   ✔ DLP: email, CC, SSN, AWS key, OpenAI key redaction + block mode
#   ✔ Injection Scanner: jailbreak, extraction, leetspeak, RCE, safe input
#   ✔ Threat Engine: RCE detection, hardcoded fallback, whitelisting
```

---

## 🛡️ Security Philosophy

> **"Defense-in-Depth. Secure by Default. Configurable by Choice."**

1. **Never naked** — Even if `threats.json` is deleted, 10 critical signatures are hardcoded in the binary.
2. **Heuristics first** — 90% of threats are caught deterministically at sub-millisecond latency, with zero external dependencies.
3. **AI as backup** — The Sheriff only runs when heuristics pass AND you enable it. It uses RAG precedent, not blind guessing.
4. **Fail gracefully** — `fail_open = true` means if Ollama is down, requests pass through (reliability over security). Set to `false` for high-security environments.
5. **Audit everything** — Every block, redaction, and threat match is logged with full forensic detail.

---

## 🤝 Contributing

Contributions are welcome! Here are some ways to help:

- **Add threat signatures** — Submit PRs to `rules/` with new OWASP/MITRE patterns (remember: normalize them!)
- **Improve regex coverage** — Better PII detection for non-US formats (IBAN, passport numbers, etc.)
- **New scanner modules** — Prompt leak detection, code injection scoring, etc.
- **Benchmarks** — Measure and optimize latency under load

---

## 📄 License

This project is open source. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with ❤️ in Rust for a safer AI future.</strong><br>
  <em>"Because the best AI firewall is the one that's always on."</em>
</p>
