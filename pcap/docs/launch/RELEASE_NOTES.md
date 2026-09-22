# AgentPCAP v1.0.0 — Release Notes

> **AgentPCAP is a local-first packet capture and debugger for AI agent systems.**  
> *Capture A2A, MCP, model and tool traffic in one local timeline. No account. No API key. One Go binary.*

---

## Highlights

- **Single Portable Go Binary**: Compiles into one executable embedding a React + TypeScript web viewer via `go:embed`. Zero runtime dependencies on Node.js, Python, Docker, or external databases.
- **Protocol-Aware Capture & Normalization**: Native parsers for:
  - **Model Context Protocol (MCP)**: JSON-RPC 2.0 tool discovery, tool calls, results, and resources.
  - **Agent-to-Agent (A2A)**: Task dispatch, hierarchical delegations, cancellations, and state streams.
  - **OpenTelemetry (OTel)**: Ingests OTLP/HTTP GenAI spans and exports standard OTLP JSON.
  - **Model Providers**: Gemini / Vertex AI, OpenAI-compatible APIs, Anthropic Claude, and generic HTTP.
- **Live Topology Visualization**: Real-time directional graph rendering agents, MCP servers, models, and tools with animated event pulses and edge telemetry.
- **Waterfall & Critical Path**: Interactive Gantt-style timeline tracking causal spans and automatically computing the longest bottleneck on the execution path.
- **Hierarchical Cost & Token Flamegraphs**: Categorized breakdowns across Time, Cost, Tokens, and Errors to pinpoint budget and latency consumption.
- **Deterministic Explain & Pathology Detection**: Heuristic root-cause analysis (`agentpcap explain`) that detects retry storms, recursive agent loops, and duplicate tool calls without invoking external LLMs.
- **Agent Run Diffing**: CLI and JSON diff engine (`agentpcap diff before.apcap after.apcap`) comparing latency, token consumption, error counts, and operational changes between runs.
- **Open `.apcap` Container Standard**: Portable ZIP-compatible bundle format (`manifest.json`, `events.jsonl`, `metadata.json`, `attachments/`) protected with SHA-256 cryptographic hashes.
- **Privacy-Safe Defaults**: Metadata-only capture by default (raw prompts and completions omitted unless `--capture-content` is passed), centralized secret scrubbing (`sk-*`, `AIza*`, JWTs), and strict `127.0.0.1` loopback binding.

---

## Quickstart & Demo

Run the zero-configuration offline simulation:

```bash
agentpcap demo
```

Your browser automatically opens to `http://127.0.0.1:9477`, visualizing a simulated multi-agent transaction exhibiting an intentional retry storm.

To capture your own agent:

```bash
agentpcap run -- ./my-agent
```

---

## Installation

### Pre-Built Binaries

Download the appropriate binary for your platform from GitHub Releases:

- `agentpcap_1.0.0_linux_amd64`
- `agentpcap_1.0.0_linux_arm64`
- `agentpcap_1.0.0_darwin_arm64` (Apple Silicon)
- `agentpcap_1.0.0_darwin_amd64` (Intel Mac)
- `agentpcap_1.0.0_windows_amd64.exe`

Verify the SHA-256 checksum:

```bash
sha256sum -c checksums.txt
```

### Install via Go

```bash
go install github.com/agentpcap/agentpcap/cmd/agentpcap@v1.0.0
```

---

## Verified Protocol Matrix

| Protocol | Specification Version | Capture Mode | Decode | Streaming | Status |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **MCP** | 2024-11-05 & current | Proxy / stdio | Yes | Yes | **Supported** |
| **A2A** | v0.1 & current drafts | Proxy / SDK | Yes | Yes | **Supported** |
| **OTLP / HTTP** | OpenTelemetry GenAI semconv | OTLP Ingest (`/v1/traces`) | Yes | Yes | **Supported** |
| **Google Gemini** | Generative Language REST | Reverse / Forward Proxy | Yes | Yes | **Supported** |
| **OpenAI** | `/v1/chat/completions` | Reverse / Forward Proxy | Yes | Yes | **Supported** |
| **Anthropic** | `/v1/messages` | Reverse / Forward Proxy | Yes | Yes | **Supported** |

---

## Known Limitations

- **No Transparent Encrypted TLS Interception**: Target applications must honor `HTTP_PROXY`, configure endpoint base URLs, export OTLP, or use `pkg/sdk`.
- **Static Pricing Catalog**: Token cost estimations rely on embedded catalog pricing unless explicitly reported by the provider.
- **In-Memory Ring Buffer**: Captures exceeding 250,000 events should stream directly to disk with `--output` and be inspected offline.

---

## Security & Privacy Verification

- **Zero Shell Interpolation**: All commands executed via raw argument slices with `exec.CommandContext`.
- **Zip-Slip & Decompression Bomb Protection**: Enforced bounds of 128 MB per entry and 256 MB per archive; path traversals strictly rejected.
- **100% Offline**: Zero analytics, zero telemetric pingbacks, and strict loopback binding.
