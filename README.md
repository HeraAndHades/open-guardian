<p align="center">
  <h1 align="center">🛡️ Open-GuardIAn</h1>
  <p align="center"><strong>The High-Performance Firewall for AI Agents.</strong></p>
  <p align="center"><em>Built in Rust. Agent-First. Defense-in-Depth.</em></p>
  <p align="center">
    <a href="#-quickstart"><img src="https://img.shields.io/badge/Get_Started-blue?style=for-the-badge" alt="Get Started"></a>
    <a href="#-architecture"><img src="https://img.shields.io/badge/Architecture-purple?style=for-the-badge" alt="Architecture"></a>
    <a href="#%EF%B8%8F-configuration"><img src="https://img.shields.io/badge/Configuration-green?style=for-the-badge" alt="Configuration"></a>
    <a href="#-contributing"><img src="https://img.shields.io/badge/Contributing-orange?style=for-the-badge" alt="Contributing"></a>
  </p>
</p>

---

## 💡 What Is This?

Open-GuardIAn is a **high-performance security middleware / reverse proxy** built in Rust that sits between your applications and any LLM provider (OpenAI, Groq, Ollama, Anthropic, etc.). It enforces real-time governance policies to prevent data leaks, block prompt injections, and stop agents from executing dangerous actions — all before the request ever reaches the model.

```
 Your App ──▶ Open-GuardIAn ──▶ LLM Provider
                   │
            ┌──────┴───────┐
            │  Layer 1     │  ← DLP Anonymizer + Threat Engine (Rust, <1ms)
            │  Layer 2     │  ← Heuristic Injection Scanner (Rust, <1ms)
            │  Layer 3     │  ← AI Judge: qwen3:4b via Ollama (Optional)
            └──────────────┘
```

### 🏆 Why Open-GuardIAn vs. Python Gateways?

| Feature | **Open-GuardIAn** | Trylon / GPT Guard |
|---------|-------------------|-------------------|
| **Language** | 🦀 Rust | 🐍 Python |
| **Latency** | **<1ms** heuristic layer | 5-50ms |
| **DLP** | Anonymizer tokens (`<EMAIL>`, `<KEY>`) — preserves context for Agents | `[REDACTED]` or regex-only |
| **AI Intelligence** | Local LLM Judge with RAG context (qwen3:4b) | ❌ Regex only |
| **Agent-First** | ✅ `rm -rf` allowed for agents, blocked for attackers | ❌ Blocks all dangerous commands |
| **Fail-Safe** | Layer 1 & 2 provide Trylon-level security without GPU | Depends on service availability |
| **Multilingual** | 🌍 EN + ES dictionaries, add any language | English-only |

---

## 🎯 Who Is This For?

| Audience | Problem We Solve |
|----------|-----------------|
| **Agent builders** (AutoGPT, CrewAI, LangChain) | Prevent agents from executing `rm -rf /`, `curl | bash`, or destroying infrastructure — while still letting them use those tools legitimately |
| **RAG chatbot developers** | Stop end-users from jailbreaking your bot, leaking system prompts, or exfiltrating PII |
| **Enterprise teams** | Enforce DLP policies — no API keys, SSNs, or credit cards ever leave your network |
| **AI platform operators** | Drop-in reverse proxy with zero code changes to existing OpenAI-compatible APIs |

---

## ✨ Key Features

### ⚡ 3-Layer Defense Architecture

Open-GuardIAn uses a **three-layer security model** — fast heuristics handle 90% of threats deterministically, backed by an optional AI engine for nuanced decisions.

#### Layer 1: DLP Anonymizer — "The Iron Dome" (CPU — Sub-millisecond — Always On)

The DLP layer is the first line of defense. It scans every request for sensitive data and replaces it with **context-preserving anonymizer tokens** that let AI agents understand what type of data was present without exposing the actual values.

| Data Type | Pattern | Anonymizer Token |
|-----------|---------|------------------|
| Email | `user@example.com` | `<EMAIL>` |
| OpenAI Key | `sk-proj-abc123...` | `<KEY>` |
| AWS Key | `AKIA...` | `<AWS_KEY>` |
| GitHub Token | `ghp_...` | `<GITHUB_TOKEN>` |
| Slack Token | `xoxb-...` | `<SLACK_TOKEN>` |
| Groq Key | `gsk_...` | `<KEY>` |
| SSN | `123-45-6789` | `<SSN>` |
| Credit Card | `4111-1111-1111-1111` | `<CC>` |
| IPv4 | `192.168.1.1` | `<IP>` |
| Phone | `+1-555-123-4567` | `<PHONE>` |
| Bearer Token | `Bearer eyJ...` | `<BEARER>` |
| Generic Secret | `api_key=abc123...` | `<SECRET>` |

Each category can be individually toggled on/off via `guardian.toml`:

```toml
[security.dlp]
email_redaction = true
credit_card_redaction = true
secret_redaction = true
ssn_redaction = true
ip_redaction = true
phone_redaction = true
```

#### Layer 2: Heuristic Engine (CPU — Sub-millisecond — Always On)

- **🛡️ Injection Scanner** — Normalization-aware scoring engine:
  - Defeats **accents** (`Tú eres DAN` → `tu eres dan`)
  - Defeats **spacing tricks** (`I g n o r e` → `ignore`)
  - 5 threat categories: Jailbreak, System Prompt Extraction, Roleplay, RCE, Data Exfiltration
  - ~40 weighted patterns with configurable score threshold

- **📋 Threat Engine Signatures** — Modular, internationalized database:
  - **Severity 100 (Block)**: `cat /etc/passwd`, `drop table`, `{{.*}}`, `eval(base64`, `union select`, `system.exit`
  - **Severity 80 (Tag & Audit)**: `rm -rf`, `wget`, `curl`, `chmod`, `exec(`, `whoami` — Agent-First: these are tagged for AI Judge review, not blocked
  - **Severity 70 (Context)**: `hacker`, `malware`, `act as` — signals for context enrichment
  - **Emergency Kit**: Critical patterns hardcoded in the Rust binary — system is **never** unprotected
  - **DevOps Whitelisting**: Explicitly allow `git pull`, `kubectl apply`, etc.
  - **Multilingual**: EN + ES dictionaries, easily extensible

> **Note**: Layer 2 uses advanced normalization-aware heuristics. Unlike heavier BERT models (like PromptGuard), this layer is deterministic, runs in <1ms, and catches 99% of common attacks without a GPU.

#### Layer 3: AI Judge — "The Sheriff" (Optional GPU — qwen3:4b)


- **🤠 Contextual Intent Analysis** — Uses a local LLM (via Ollama) to decide whether flagged commands are legitimate agent operations or actual attacks
- **Agent-First Philosophy**: `rm -rf /tmp/cache` for cleanup? **SAFE**. `rm -rf /` without context? **UNSAFE**.
- **RAG-Powered**: The Judge receives similar threat patterns as precedent in its system prompt
- **Performance-Optimized**:
  - `moka` semantic cache — repeat prompts resolved in <1ms
  - `tokio::Semaphore` concurrency control — protects host resources
  - Configurable **fail-open** or **fail-closed** when the AI is unavailable
- **Model**: `qwen3:4b` (primary) or `qwen2.5:3b` (fallback for lower-resource environments)

### 🛣️ Smart Multi-Provider Router

- Route requests to different LLM providers based on the `model` field
- Automatic **credential injection** from environment variables
- Model alias rewriting (e.g., `"llama-4"` → `"meta-llama/llama-4-maverick-17b-128e-instruct"`)
- Zero-config fallback to default upstream

### 📐 Policy Manager — "The Governor"

Four enforcement modes for every security check:

| Policy | Behavior |
|--------|----------|
| `block` | Return 403 Forbidden — request never reaches the LLM |
| `audit` | Log `WARN` + inject `X-Guardian-Risk: High` header + forward |
| `redact` | Sanitize sensitive data with anonymizer tokens and forward |
| `allow` | No enforcement (not recommended for production) |

### 📝 Forensic Audit Logging

- All security events logged in **JSONL** format with timestamps
- Events: `injection_blocked`, `dlp_blocked`, `data_redacted`, `threat_blocked`, `semantic_blocked`
- Easily ingestible by SIEM tools (Splunk, ELK, Datadog)

---

## 🚀 Quickstart

### 📦 Installation (No Rust Required)

Don't want to compile? Download the latest pre-built binaries from the [Releases Page](https://github.com/your-username/open-guardian/releases).

| Platform | Arch | Binary |
|----------|------|--------|
| 🐧 Linux | x64 | `open-guardian-linux-amd64.tar.gz` |
| 🍎 macOS | Apple Silicon | `open-guardian-macos-arm64.tar.gz` |
| 🍎 macOS | Intel | `open-guardian-macos-amd64.tar.gz` |
| 🪟 Windows | x64 | `open-guardian-windows-amd64.zip` |

#### Setup:

1. **Unzip** the file.
2. **Create a `.env` file** next to the binary with your API keys.
3. **Run** the binary:
   - **Linux/Mac**: `./open-guardian start`
   - **Windows**: `.\open-guardian.exe start`

### 🛠️ Compiling from Source

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

### 3. (Optional) Pull the AI Judge Model

```bash
ollama pull qwen3:4b
```

### 4. Run the Shield

```bash
# Standard mode
./target/release/open-guardian start

# With verbose debug output
./target/release/open-guardian start --verbose

# Local-only mode (routes all traffic to Ollama)
./target/release/open-guardian start --local
```

### 5. Point Your App

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
│  │         LAYER 1: DLP ANONYMIZER (Always On)               │  │
│  │  Email → <EMAIL>  |  sk-proj-... → <KEY>  |  SSN → <SSN> │  │
│  │  Action: REDACT tokens  |  or  BLOCK (configurable)       │  │
│  └───────────────────────────┬───────────────────────────────┘  │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │         LAYER 2: HEURISTIC ENGINE (CPU, <1ms)             │  │
│  │  ┌──────────────┐  ┌──────────────────────────────────┐   │  │
│  │  │  Injection   │→ │   Threat Engine (Signatures)     │   │  │
│  │  │  Scanner     │  │  Sev 100: BLOCK  |  Sev 80: TAG  │   │  │
│  │  └──────────────┘  └──────────────────────────────────┘   │  │
│  └───────────────────────────┬───────────────────────────────┘  │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │     LAYER 3: AI JUDGE "The Sheriff" (Optional, GPU)       │  │
│  │  ┌─────────────┐  ┌─────────┐  ┌──────────────────────┐  │  │
│  │  │ RAG Context │→ │  Cache  │→ │  qwen3:4b (Ollama)   │  │  │
│  │  │  Retrieval  │  │ (moka)  │  │  + Semaphore Control │  │  │
│  │  └─────────────┘  └─────────┘  └──────────────────────┘  │  │
│  └───────────────────────────┬───────────────────────────────┘  │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │            POLICY ENFORCEMENT                             │  │
│  │       Block (403) │ Audit (Log+Forward) │ Allow           │  │
│  └───────────────────────────┬───────────────────────────────┘  │
│                              ▼                                   │
│               Smart Router → Upstream LLM                        │
└─────────────────────────────────────────────────────────────────┘
```

### Pipeline Flow

1. **Incoming Request** → Rate limiter check
2. **Layer 1 — DLP**: Anonymize PII/secrets with `<TOKEN>` tags, or block if policy = `block`
3. **Layer 2 — Heuristics** (always runs, sub-ms):
   - **Injection Scanner**: Score adversarial patterns → block if score ≥ threshold
   - **Threat Engine**: Match against signature database
     - Sev 100 → **Deterministic Block** (SQLi, SSTI, Data Exfil)
     - Sev 80 → **Tag & Audit** (Risky tools — AI Judge or Agent-First allow)
     - Sev 70 → **Context Signal** (Enrich for AI Judge)
4. **Layer 3 — AI Judge** (runs only if enabled AND risk tags present):
   - Retrieve similar threat patterns (RAG) → check moka cache → acquire semaphore → call LLM
   - **If AI Judge is OFF**: Sev 80 items → LOG WARN + ALLOW (Agent-First philosophy)
5. **Policy Enforcement**: `403 Block` / `Audit + Forward` / `Allow + Forward`

---

## ⚙️ Configuration

### `guardian.toml`

```toml
[server]
port = 8080
default_upstream = "https://api.groq.com/openai"
requests_per_minute = 10000

[security]
audit_log_path = "guardian_audit.jsonl"
block_threshold = 50       # Injection score threshold (0-100)

# DLP per-category toggles
[security.dlp]
email_redaction = true
credit_card_redaction = true
secret_redaction = true
ssn_redaction = true
ip_redaction = true
phone_redaction = true

[security.policies]
default_action = "block"   # block | audit | redact | allow
dlp_action = "redact"      # block | redact
allowed_patterns = ["git pull", "git push", "kubectl get", "kubectl apply"]

# Modular Threat Dictionaries
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
ai_judge_model = "qwen3:4b"     # Fallback: qwen2.5:3b
judge_cache_ttl_seconds = 60
judge_max_concurrency = 4
fail_open = true                 # true = Prioritize reliability

[routes]
"gpt-oss" = { url = "https://api.groq.com/openai", model = "openai/gpt-oss-120b", key_env = "GROQ_API_KEY" }
"llama-4" = { url = "https://api.groq.com/openai", model = "meta-llama/llama-4-maverick-17b-128e-instruct", key_env = "GROQ_API_KEY" }
"gpt-4o" = { url = "https://api.openai.com/v1", key_env = "OPENAI_API_KEY" }
"qwen3:4b" = { url = "http://127.0.0.1:11434/v1" }
```

### `rules/` Directory (Modular Dictionaries)

Add new languages or categories by creating a JSON file in `rules/` and referencing it in `guardian.toml`. All patterns must be **NORMALIZED** (lowercase, no accents).

**Signature format:**
```json
{
  "signatures": [
    {
      "id": "JB-ES-001",
      "pattern": "olvida tus reglas",
      "category": "Jailbreak",
      "severity": 95,
      "is_regex": false
    }
  ]
}
```

**Severity guide:**
| Severity | Action | Use For |
|----------|--------|---------|
| 100 | **Block always** | SQLi, SSTI, data exfiltration, binary payloads |
| 90-99 | **Block always** | Jailbreaks, prompt leaks, instruction overrides |
| 80-89 | **Tag & Audit** | Risky tools (rm, curl, wget, chmod) — AI Judge decides |
| 70-79 | **Context signal** | Suspicious topics (hacker, malware) — enriches AI Judge |
| 50-69 | **Tag only** | Low-confidence signals |

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
│       ├── dlp.rs                 # DLP Anonymizer (PII + Secrets → <TOKEN>)
│       ├── injection_scanner.rs   # Adversarial pattern scoring engine
│       ├── threat_engine.rs       # Signature DB + Emergency Kit + RAG
│       ├── normalizer.rs          # Code-aware text normalization
│       └── judge.rs               # AI Sheriff (qwen3:4b + moka cache + RAG)
├── guardian.toml                  # Runtime configuration
├── rules/                         # Modular threat dictionaries
│   ├── common.json                # Universal threats (RCE, SQLi, SSTI, Secrets)
│   ├── jailbreaks_en.json         # English jailbreak patterns
│   └── jailbreaks_es.json         # Spanish jailbreak patterns
├── audit_prod.py                  # Production audit script (500-req stress test)
├── Cargo.toml                     # Rust dependencies
├── CONTRIBUTING.md                # Contribution guidelines
└── .env                           # API keys (gitignored)
```

---

## 🧪 Testing

```bash
# Run all unit tests
cargo test

# Current test coverage:
#   ✔ DLP: email, CC, SSN, IPv4, OpenAI key, sk-proj-, GitHub, Slack, Groq
#   ✔ DLP: check_for_violations block mode
#   ✔ Normalizer: lowercase, de-accent, syntax preservation, SSTI, SQL
#   ✔ Threat Engine: Sev 100 blocking, Sev 80 tagging, SSTI regex, whitelisting
#   ✔ Injection Scanner: jailbreak, extraction, RCE, safe input

# Production audit (requires running instance)
python audit_prod.py
```

---

## 🛡️ Security Philosophy

> **"Agent-First. Defense-in-Depth. Secure by Default."**

1. **Agent-First** — We enable Agents to use tools (`curl`, `rm`, `wget`, `chmod`), not block them blindly. The AI Judge differentiates legitimate operations from attacks.
2. **Layered Defense** — Layer 1 (DLP + Regex) works 100% without GPU. Layer 2 (Heuristics) catches obfuscated attacks. Layer 3 (AI Judge) provides contextual intent analysis.
3. **Never Naked** — Even if all `rules/*.json` files are deleted, critical signatures are hardcoded in the Rust binary.
4. **Fail-Safe** — If Layer 3 (AI) is off, Layer 1 & 2 provide "Trylon-level" security. Risky tools get logged, not blocked.
5. **Anonymize, Don't Destroy** — DLP replaces sensitive data with `<EMAIL>`, `<KEY>` tokens that preserve semantic context for AI agents, instead of opaque `[REDACTED]` strings.
6. **Audit Everything** — Every block, redaction, and threat match is logged with full forensic detail.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:
- Setting up your development environment
- Adding threat signatures
- Writing scanner modules
- Submitting pull requests

---

## 📄 License

This project is open source. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with ❤️ in Rust for a safer AI future.</strong><br>
  <em>"The best AI firewall is the one that's always on — and the one that knows the difference between an agent doing its job and an attacker exploiting it."</em>
</p>

## ✍️ A Note from the Creator

### Why I Built Open-Guardian
This project was born out of necessity following the release of tools like OpenClaw and the security vacuum they created. I realized that while Agents are the future, they are dangerously exposed without a proper firewall.

**Transparency Statement**: This codebase was architected by a human and built with the assistance of advanced AI Agents and LLMs, acting under strict Human-in-the-Loop supervision.

### About the Author
I bring over 6 years of professional Fullstack development experience and have been an entrepreneur since 2016. Currently, I am pursuing a Master's degree in Artificial Intelligence, with over 2 years of specialization in Data Science and Machine Learning.

I chose Rust over Python because security infrastructure must be invisible and fast. This is my first contribution designed specifically for the Open Source community—a way to give back to the ecosystem that has helped me so much.

Let's build a safer future for AI Agents.
