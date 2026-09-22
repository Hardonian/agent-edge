# AgentPCAP Roadmap

AgentPCAP focuses on delivering a lean, fast, local-first debugger for AI agents. We intentionally avoid roadmap bloat.

---

## v1.0 (Current Release)

- [x] Pure single-binary distribution with embedded Web UI (`go:embed`).
- [x] Open `.apcap` streaming ZIP container format with JSON schema.
- [x] Protocol parsers for MCP (Model Context Protocol) and A2A (Agent-to-Agent).
- [x] Model adapters for Gemini/Vertex, OpenAI, Anthropic, and generic HTTP endpoints.
- [x] Standard OTLP trace receiver and exporter.
- [x] Live interactive web viewer (Topology, Packets, Waterfall, Flamegraphs, Findings, Diff).
- [x] Offline deterministic analyzer (`agentpcap explain`) and 9 pathology detectors.
- [x] Standalone single-file HTML report export (`agentpcap report`).
- [x] Multi-agent offline simulation demo (`agentpcap demo`).
- [x] Automated secret redaction and metadata-only privacy defaults.

---

## v1.x (Near-Term)

- **Extended Protocol Adapters**:
  - Direct LangChain/LangGraph streaming event adapter.
  - CrewAI and AutoGen event exporters.
  - Native gRPC OTLP receiver (in addition to current OTLP/HTTP).
- **Capture Enhancements**:
  - Streaming size-based file rotation for multi-day long-running test suites.
  - HAR import (`agentpcap import har <file.har>`) to convert browser network captures into `.apcap`.
- **Developer Ergonomics**:
  - VS Code extension to preview `.apcap` files directly within the editor pane.
  - Native Homebrew and Winget package distribution.

---

## Future Research (v2.0+)

- **Linux eBPF Socket Tap**:
  - Optional kernel-level socket tap (`agentpcap tap --pid <PID>`) to measure low-level TCP connection latency and DNS resolution timing without TLS interception.
- **Cross-Run Anomaly Regression Clustering**:
  - Automated statistical clustering of latency regressions across large suites of CI `.apcap` captures.
