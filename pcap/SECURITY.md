# Security Policy

The AgentPCAP project treats security and privacy as non-negotiable core invariants. AgentPCAP operates as a local-first developer observability tool and enforces strict defense-in-depth boundaries.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please **do not** open public GitHub issues for security vulnerabilities or potential secret leak exploits.

Instead, please report security vulnerabilities privately via email to:
[security@agentpcap.org](mailto:security@agentpcap.org) (or create a private GitHub Security Advisory).

Include:

- A description of the issue and potential impact.
- Clear reproduction steps or proof-of-concept capture (`.apcap`).
- The version of AgentPCAP and environment details (OS, architecture).

We acknowledge reports within 48 hours and coordinate release of patches prior to disclosure.

---

## Core Security Invariants

1. **Loopback Binding by Default**:
   The web viewer and capture endpoints bind strictly to `127.0.0.1`. Binding to `0.0.0.0` or external network interfaces requires explicit `--listen` configuration and emits high-visibility security warnings.

2. **Metadata-Only Default**:
   Payloads (prompts, model completions, raw tool arguments) are **never** stored by default. Content capture is an explicit, opt-in flag (`--capture-content`) with console warnings.

3. **No Silent TLS Interception**:
   AgentPCAP v1 does not install root certificates or perform MITM decryption on encrypted HTTPS traffic. All proxy interception occurs via standard HTTP or explicit SDK/OTel instrumentation.

4. **Hostile `.apcap` Defenses**:
   Capture files are treated as untrusted input.
   - **Zip-Slip Prevention**: All entry filepaths are normalized and restricted from traversing the target directory root (`..`, absolute paths, symlinks rejected).
   - **Decompression Bomb Bounds**: Individual file extraction is hard-capped at 128 MB, and total bundle extraction is bounded to 256 MB.
   - **Strict Schema Validation**: JSON manifests and events are validated before memory ingestion.

5. **Injection-Safe Child Execution**:
   `agentpcap run -- <command>` uses native `os/exec` slices. Arguments are never interpolated into shell strings. Signals (`SIGINT`, `SIGTERM`) are forwarded cleanly to the process group.

6. **Automated Secret Redaction**:
   Built-in pattern matching scrubs API keys (`sk-*`, `AIza*`, `ghp_*`), authorization headers, session cookies, database connection strings, and private keys from capture payloads.

For full architectural details, see [THREAT_MODEL.md](docs/THREAT_MODEL.md).
