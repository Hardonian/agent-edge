# Threat Model

This document outlines the threat vectors considered during the design and implementation of AgentPCAP v1.0, along with mitigations enforced by the codebase.

---

## 1. Untrusted Capture Bundle (`.apcap` Ingestion)

### Vector: Zip-Slip / Path Traversal

- **Threat**: An attacker creates an `.apcap` archive containing entries like `../../../../etc/passwd` or `..\..\AppData\Malicious.exe`. If extracted naively, it overwrites critical host files.
- **Mitigation**: In [`pkg/apcap/reader.go`](file:///c:/Users/scott/GitHub/AgentPCAP/pkg/apcap/reader.go), all entry filenames are passed to `filepath.Clean` and checked with `filepath.Rel(destDir, target)`. Any entry that resolves outside `destDir` or contains `..` segments fails immediately with `ErrPathTraversal`.

### Vector: Decompression Bomb (Zip Bomb)

- **Threat**: An attacker provides a tiny `.apcap` file that expands into gigabytes of zeroes when uncompressed, exhausting host disk or memory.
- **Mitigation**: In [`pkg/apcap/reader.go`](file:///c:/Users/scott/GitHub/AgentPCAP/pkg/apcap/reader.go), reading is wrapped with `io.LimitReader`. Single entry files cannot exceed 128 MB (`MaxEntrySizeBytes`), and cumulative extraction across all archive entries cannot exceed 256 MB (`MaxBundleSizeBytes`). Exceeding either limit triggers `ErrDecompressionBomb`.

### Vector: Malformed or Recursive JSON

- **Threat**: Crafting arbitrarily nested JSON objects in `manifest.json` or `events.jsonl` to cause stack overflow or unbounded parser allocations.
- **Mitigation**: Event streams are decoded line-by-line using `bufio.Scanner` with a bounded token buffer (1 MB max line). Nested schemas are parsed into typed structs without recursive schema reflection.

---

## 2. Web Viewer & Frontend UI (XSS & Injection)

### Vector: Stored Cross-Site Scripting (XSS)

- **Threat**: Untrusted agent traces containing `<script>alert(1)</script>` or malicious HTML payloads are rendered inside the web viewer, executing scripts within the operator's browser session.
- **Mitigation**:
  1. The React DOM reconciler escapes all interpolated strings by default.
  2. The embedded Go web server ([`internal/server/server.go`](file:///c:/Users/scott/GitHub/AgentPCAP/internal/server/server.go)) applies strict Content Security Policy (CSP) headers:
     `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'`.
  3. `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` are sent on all responses.

---

## 3. Network & Proxy Subsystem

### Vector: Unauthenticated Remote Access

- **Threat**: Running AgentPCAP on a shared or cloud development box binds to `0.0.0.0`, allowing unauthorized network users to view sensitive agent workflows.
- **Mitigation**: Default listener binding is strictly `127.0.0.1`. Binding to external interfaces requires an explicit `--listen` argument and triggers console warnings.

### Vector: Open HTTP Forward Proxy (SSRF / Relay Abuse)

- **Threat**: The proxy listener is exposed to external network actors who abuse it to access internal cloud metadata services (`http://169.254.169.254`) or internal databases.
- **Mitigation**:
  1. Proxy listens on loopback only.
  2. Transparent TCP tunneling (`CONNECT`) directly dials target addresses without acting as an open caching or header-injecting proxy.

---

## 4. Secret Leakage & Redaction

### Vector: Hardcoded API Keys & Authorization Headers in Captures

- **Threat**: An agent's runtime environment variables or headers (e.g. `Authorization: Bearer sk-...`) are written to `.apcap` files and inadvertently committed to public GitHub issues.
- **Mitigation**:
  1. Metadata-only is the default capture mode.
  2. Centralized redactor ([`internal/redact/redactor.go`](file:///c:/Users/scott/GitHub/AgentPCAP/internal/redact/redactor.go)) runs regular expressions for Google AI API keys (`AIza*`), OpenAI keys (`sk-*`), Anthropic keys (`sk-ant-*`), GitHub PATs, JWT tokens, AWS credentials, and Bearer tokens.
  3. `agentpcap redact` and `agentpcap inspect-redaction` provide offline verification of sanitize state.
