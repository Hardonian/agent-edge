# AgentPCAP — Post-v1 Backlog & Candidate Roadmap

This document captures architectural explorations, protocol adapters, tooling integrations, and community requests intentionally deferred beyond the v1.0 release freeze.

All items here will be prioritized exclusively based on real-world adoption, verified issue reports, and production user feedback.

---

## 1. Protocol Normalization & Adapters

- [ ] **Expanded Provider Adapters**:
  - Mistral AI native API normalization
  - Cohere native API normalization
  - Bedrock / AWS Converse API adapter
  - Azure OpenAI specific telemetry headers

- [ ] **Extended Agent Framework Handlers**:
  - LangChain / LangGraph direct trace parser
  - AutoGen multi-agent message format adapter
  - CrewAI event listener integration

- [ ] **Streaming Body Chunk Inspection**:
  - Full reconstruction and token-by-token diffing of Server-Sent Events (SSE) streaming responses when `--capture-content` is active.

---

## 2. Advanced Operating System & Network Capture

- [ ] **eBPF Socket & Process Correlation**:
  - Linux eBPF probes for automatic pid/cgroup tracking to map network connections directly to specific agent process IDs without environment variable injection.

- [ ] **Local TLS Interception (Optional Developer Mode)**:
  - Ephemeral root CA generation for transparent local HTTPS proxying when explicit proxy configuration is impossible.

---

## 3. IDE & Developer Tooling

- [ ] **VS Code Extension**:
  - In-editor `.apcap` viewer pane.
  - Jump-to-code from agent stack frames and MCP tool definitions.

- [ ] **Headless Trace Replay**:
  - Mock server simulating recorded agent responses from an `.apcap` file for deterministic regression testing.

- [ ] **Browser Extension**:
  - Live inspector for web-based agent frontends and client-side agent frameworks.

---

## 4. Team Collaboration & CI Tooling

- [ ] **Stateless Static Export**:
  - Self-contained interactive single-file HTML viewers containing embedded capture bundles.

- [ ] **Advanced CI Heuristic Rules**:
  - Token drift regression assertions between pull request branches.
  - Multi-run statistical confidence intervals for non-deterministic model latency.
