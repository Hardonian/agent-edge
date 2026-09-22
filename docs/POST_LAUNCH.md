# AgentPCAP — Post-Launch Operational Monitoring & Telemetry Guidelines

Following the v1.0.0 public release, development transitions strictly to **Issue-Driven Iteration**. No massive architectural rewrites will occur without direct user evidence.

---

## 1. Key Operational Metrics to Track

The core team monitors the following public signals:

| Metric Category | Target Indicator | Feedback Channel | Priority |
| :--- | :--- | :--- | :---: |
| **Adoption & Downloads** | Unique GitHub cloners, release binary downloads, Homebrew/Go install counts | GitHub Releases / Insights | Informational |
| **Demo Stability** | Reports of `agentpcap demo` failing on specific OS versions (e.g. macOS ARM vs Linux) | GitHub Issues (`label:demo`) | **P0 / Immediate** |
| **MCP Compatibility** | Unhandled JSON-RPC methods, schema variations across MCP servers | GitHub Issues (`label:mcp`) | **P1 / High** |
| **A2A Compatibility** | New agent-to-agent protocol drafts, unexpected payload shapes | GitHub Issues (`label:a2a`) | **P1 / High** |
| **.apcap Specification Feedback** | Third-party parser issues, format ergonomics, schema requests | GitHub Discussions / Spec Issues | **P2 / Normal** |
| **Platform-Specific Quirks** | Port conflicts, loopback binding behavior on Windows/WSL2/macOS | GitHub Issues (`label:platform`) | **P1 / High** |
| **Secret Redaction Leaks** | Novel credential patterns not caught by redactor | Security Disclosure (`SECURITY.md`) | **P0 / Immediate** |

---

## 2. Issue Triage Stance

1. **Crash or Data Race on Capture**:
   - Any crash or panic during `agentpcap run` or `agentpcap open` is treated as a P0 blocker requiring an immediate patch release (v1.0.1).

2. **Protocol Compatibility**:
   - If an open-source MCP server fails normalization, request a sanitized `.apcap` or raw payload snippet, add it to `tests/torture/`, and publish a patch.

3. **Feature Requests**:
   - Feature requests without reproducible agent workflows are triaged to `docs/POST_V1_BACKLOG.md` to preserve the single-binary, local-first footprint.
