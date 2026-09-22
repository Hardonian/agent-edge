# AgentPCAP v1.0 Scope Contract

This document formally specifies the release scope and contractual guarantees for **AgentPCAP v1.0**.

---

## 1. AgentPCAP v1.0 Guarantees

AgentPCAP v1.0 guarantees the following core capabilities and operational behaviors:

1. **Local-First Execution**:
   - Operates 100% offline without external database daemons, internet connections, API keys, or cloud user accounts.
   - All captured data remains on the user's machine in local `.apcap` containers.

2. **Single-Binary Distribution**:
   - Compiles into a single self-contained executable for Linux (`amd64`, `arm64`), macOS (`arm64`, `amd64`), and Windows (`amd64`).
   - The React + TypeScript web frontend is embedded directly via `go:embed` with zero external CDN dependencies.

3. **Embedded Viewer**:
   - Local web viewer binds strictly to `127.0.0.1:9477` by default with zero external network leakage.
   - Real-time updates delivered over Server-Sent Events (SSE).

4. **`.apcap` Read, Write & Validation**:
   - Complete support for the open `.apcap` v1.0 containerized specification (ZIP + `manifest.json` + `events.jsonl` + `metadata.json` + `attachments/`).
   - Strict cryptographic integrity verification using SHA-256 hashes (`agentpcap validate`).
   - Line-by-line streaming recovery from crash-interrupted captures.

5. **MCP Normalization**:
   - Full normalization of Model Context Protocol (MCP) JSON-RPC 2.0 traffic (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `tools/result`, `resources/list`, `prompts/list`).
   - Resilient against 100KB method names, 1MB payloads, and deeply nested argument structures.

6. **A2A Normalization**:
   - Normalization of Agent-to-Agent communication patterns (agent discovery, task creation, hierarchical delegation, cancellation, state progression).
   - Recursion and delegation tracking up to 50 levels deep.

7. **OTLP Ingestion**:
   - Ingestion of OpenTelemetry traces (`/v1/traces`) over HTTP.
   - Automatic translation of OpenTelemetry GenAI semantic conventions (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.prompt_tokens`, `gen_ai.usage.completion_tokens`).
   - Export capability back to standard OTLP JSON (`agentpcap export otlp`).

8. **Model & Tool Event Normalization**:
   - Unified normalization for LLM provider calls (Gemini, Vertex AI, OpenAI-compatible, Anthropic Claude) and tool invocations.

9. **Topology Visualization**:
   - Real-time animated directional graph displaying agents, MCP servers, models, and external tools with pulse animations and edge inspection.

10. **Packet & Event Inspection**:
    - Wireshark-style tabular event browser with filtering, column sorting, duration, token counts, and sanitized preview payloads.

11. **Waterfall Timeline**:
    - Hierarchical child span visualization tracking parent-child task delegations and concurrent executions.

12. **Critical-Path Analysis**:
    - Automatic identification and highlighting of the longest contiguous latency chain dominating wall-clock execution.

13. **Cost & Token Visualization**:
    - Hierarchical flamegraph representations categorized by Time, Cost, Tokens, and Errors.
    - Transparent labeling of measured provider costs versus snapshot catalog estimates (`ESTIMATED`).

14. **Diff Engine**:
    - Regression and comparison engine (`agentpcap diff a.apcap b.apcap`) contrasting latency, token counts, model calls, tool calls, retries, and pathologies in human-readable table or `--json` format.

15. **Deterministic Explain**:
    - Heuristic root-cause analysis (`agentpcap explain`) generating 4-part structured diagnostic reports without invoking external LLMs.

16. **Runtime Pathology Detection**:
    - Deterministic rule-based detection for 8 distinct anomaly types: `RETRY_STORM`, `AGENT_LOOP`, `DUPLICATE_TOOL_CALL`, `EXPENSIVE_FAN_OUT`, `TOKEN_EXPLOSION`, `UNRESOLVED_DISCOVERY`, `DEEP_DELEGATION`, `PROMPT_BLOAT`.

17. **Centralized Redaction**:
    - Automatic regex-based and structural scrubbing of API keys (`AIza*`, `sk-*`, `ghp_*`), JWTs, Bearer headers, and database connection strings.

18. **Metadata-Only Default Capture**:
    - Safe-by-default operation: raw prompts, completions, and tool arguments are omitted unless `--capture-content` is explicitly passed by the user.

19. **Deterministic Local Demo**:
    - Zero-dependency simulation (`agentpcap demo`) demonstrating multi-agent transactions, MCP tool execution, and retry storm pathology offline.

20. **Audited Release Binaries**:
    - Multi-platform release binaries verified against the Go race detector, hostile fuzz suites, and SHA-256 cryptographic checksums.

---

## 2. AgentPCAP v1.0 Does NOT Guarantee

To maintain technical honesty and avoid misleading developers, AgentPCAP v1.0 explicitly does **not** provide:

1. **Transparent Decryption of Arbitrary Encrypted Traffic**:
   - Does not perform kernel-level TLS MITM interception without proxy configuration. Target applications must respect `HTTP_PROXY`/`HTTPS_PROXY`, configure base URLs, export OTLP, or use the Go SDK.

2. **Universal Framework Auto-Detection**:
   - Does not magically attach to unconfigured runtimes without standard proxy or environment variables.

3. **Deterministic Replay of Arbitrary Agents**:
   - While `.apcap` captures provide complete historical records, AgentPCAP does not simulate stateful third-party environments or guarantee deterministic replay of external non-deterministic LLM generations.

4. **Universal Prompt-Injection Detection**:
   - Does not evaluate semantic safety, jailbreak attempts, or prompt injection attacks. It provides transparent forensic evidence of transmitted payloads.

5. **Hosted Observability / SaaS Collaboration**:
   - No multi-tenant cloud dashboards, user authentication, RBAC, remote database connections, or team sharing.

6. **eBPF Payload Decoding**:
   - Does not use kernel eBPF probes for payload reconstruction.

7. **Zero-Instrumentation Support for Every Runtime**:
   - Non-HTTP, proprietary IPC, or unproxied socket communications require explicit OTLP trace emission or SDK integration.
