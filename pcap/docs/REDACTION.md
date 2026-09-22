# Secret Redaction Engine

AgentPCAP includes an integrated, high-performance regex redaction engine (`internal/redact`) designed to prevent credential leakage.

## 1. Redacted Patterns

The redactor automatically matches and sanitizes:
- **Anthropic API Keys**: `sk-ant-api03-...` -> `[REDACTED_ANTHROPIC_KEY]`
- **OpenAI API Keys**: `sk-...` -> `[REDACTED_OPENAI_KEY]`
- **Google / Gemini API Keys**: `AIza...` -> `[REDACTED_GOOGLE_KEY]`
- **AWS Access Keys**: `AKIA...` -> `[REDACTED_AWS_KEY]`
- **GitHub Personal Tokens**: `ghp_...` -> `[REDACTED_GITHUB_TOKEN]`
- **Bearer Tokens**: `Bearer eyJ...` -> `Bearer [REDACTED_TOKEN]`
- **JSON Web Tokens (JWT)**: `eyJhbG...` -> `[REDACTED_JWT]`
- **Database Connection Strings**: `postgres://user:pass@host` -> `postgres://[USER]:[REDACTED_PASS]@host`
- **Private Key Blocks**: `-----BEGIN PRIVATE KEY-----` -> `[REDACTED_PRIVATE_KEY]`

---

## 2. CLI Scrubbing

Scrub all sensitive fields from an existing capture:

```bash
agentpcap redact raw_run.apcap -o safe_run.apcap
```

---

## 3. Secret Inspection

Scan a capture file to verify that zero credentials or tokens leaked:

```bash
agentpcap inspect-redaction safe_run.apcap
```

Output:
```text
✓ Zero unredacted secrets found in capture file.
```
