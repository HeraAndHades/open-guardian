# Open-GuardIAn 🛡️

**The AI Firewall & Security Gateway** — *Keeping AI agents from doing stupid things.*

Open-GuardIAn is a high-performance, security-first middleware designed for the age of autonomous AI agents. It sits between your applications and LLM providers (OpenAI, Groq, Ollama, etc.), providing a robust governance layer that prevents data leaks, blocks prompt injections, and enforces semantic safety policies in real-time.

## 🚀 Why Open-GuardIAn?

As AI agents gain more autonomy and access to sensitive data, the risk of "stupid things" happening increases exponentially. Open-GuardIAn provides the guardrails needed to deploy AI with confidence.

- **Data Privacy:** Automatically redacts PII and Secrets before they ever reach an external API.
- **Cost & Performance Control:** Smart routing and caching ensure you use the right model for the right task at the lowest latency.
- **Semantic Governance:** "The Sheriff" engine uses local LLMs to judge request safety, going beyond simple keyword filters.
- **Agent Safety:** Prevents agents from being manipulated into performing unauthorized actions or leaking system prompts.

## ✨ Key Features

### ⚖️ The Sheriff (AI Governance Engine)
A semantic evaluation layer that uses a local judge (e.g., Llama 3) to analyze intent. It features:
- **High-Performance Caching:** Powered by `moka`, repeat requests are resolved in <1ms.
- **Concurrency Control:** Resource-aware semaphores prevent CPU exhaustion.
- **Fail-Open Design:** Security that doesn't break production reliability.

### 🛣️ Smart Multi-Provider Router
Dynamic routing based on the `model` field in your JSON requests.
- Map specific models to different upstreams (e.g., GPT-4 to OpenAI, Llama-3 to Groq).
- Zero-config fallback to default providers.

### 🔒 Advanced DLP (Data Loss Prevention)
Ultra-fast regex engine using `OnceLock` for single-pass detection of:
- **Secrets:** AWS Keys, GitHub Tokens, and Generic API Keys.
- **PII:** Emails, Credit Cards, IPv4 Addresses, and Phone Numbers.

### 🛡️ Heuristic Injection Guard
Normalization-aware guard that catches obfuscated (leetspeak) injection attacks (e.g., `J4ilbr3ak`) using a risk-scoring system.

## 🛠️ Getting Started

### 1. Configuration (`guardian.toml`)
Create a `guardian.toml` in your project root:

```toml
[server]
port = 8080
upstream = "https://api.openai.com/v1"

[server.routes]
"llama-3.1-8b-instant" = "https://api.groq.com/openai"

[judge]
enabled = true
model = "llama3.2:1b"
```

### 2. Run the Shield
```bash
open-guardian start
```

### 3. Run the Inspector (Audit)
Scan your environment for exposed secrets and insecure configurations:
```bash
open-guardian audit
```

## 🏗️ Project Structure
- `src/main.rs`: CLI Entry point.
- `src/server.rs`: Axum server & Interception logic.
- `src/proxy.rs`: Request forwarding.
- `src/security/`: DLP, Injection Guard, and The Judge logic.
- `src/audit.rs`: Static analysis for security.

---
*Built with ❤️ in Rust for a safer AI future.*
