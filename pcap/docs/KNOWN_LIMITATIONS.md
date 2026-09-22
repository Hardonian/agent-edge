# Known Limitations & Non-Goals

To maintain high architectural integrity, clear developer expectations, and zero bloat, this document explicitly details what AgentPCAP v1.0 does and does **not** do.

---

## 1. Known Limitations in v1.0

1. **No Universal Zero-Instrumentation Capture for Encrypted Traffic**:
   AgentPCAP does **not** perform transparent kernel-level TLS MITM decryption out of the box. To capture HTTPS traffic, target applications must either:
   - Accept standard `HTTP_PROXY` / `HTTPS_PROXY` proxy environment variables.
   - Point their base URLs to an unencrypted local proxy port, or
   - Export traces via OpenTelemetry (`OTEL_EXPORTER_OTLP_ENDPOINT`), or
   - Use the lightweight Go SDK (`pkg/sdk`).

2. **Heuristic Parallelization Findings**:
   The `POSSIBLE_PARALLELIZATION` diagnostic detects independent sibling operations executed in serial sequences. However, because AgentPCAP cannot infer internal business state dependencies without deep domain semantics, parallelization is suggested as an opportunity, never an absolute proof of safety.

3. **Static Catalog-Based Cost Estimation**:
   Unless an LLM provider explicitly reports exact currency cost in response metadata (e.g. some OpenAI/Anthropic headers), token costs are calculated based on an embedded snapshot pricing catalog ([`internal/cost/pricing.go`](file:///c:/Users/scott/GitHub/AgentPCAP/internal/cost/pricing.go)) or custom pricing JSON. All estimated figures are clearly tagged with provenance `ESTIMATED`.

4. **In-Memory Buffer Scaling**:
   The live web viewer ring buffer holds recent events in memory for fast SSE broadcast and responsive UI rendering. For extraordinarily massive captures (> 250,000 events), users should stream directly to disk using `--output` and inspect via `agentpcap open` or pagination.

---

## 2. Non-Goals

1. **Not an Enterprise SaaS / Multi-Tenant Dashboard**:
   AgentPCAP will not include cloud accounts, Stripe billing, user permissions/RBAC, team organization management, or cloud syncing. It is a local-first single binary.

2. **Not a General Network Packet Sniffer**:
   AgentPCAP does not parse raw 802.3 Ethernet frames, TCP sequence numbers, or low-level SYN/ACK handshakes. It is an application- and protocol-level packet capture for agentic protocols (A2A, MCP, LLMs, Tools).

3. **Not a Prompt-Injection Security Scanner**:
   AgentPCAP does not attempt to evaluate prompt injections, jailbreak attempts, or safety red-teaming. It provides transparent forensic evidence of what was transmitted.

4. **Not a Deterministic Replay Engine for Arbitrary Agents**:
   While `.apcap` captures provide complete historical records, AgentPCAP does not simulate stateful third-party environments or guarantee deterministic replay of external non-deterministic LLM generations.
