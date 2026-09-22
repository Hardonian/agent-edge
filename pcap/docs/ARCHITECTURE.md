# AgentPCAP Architecture

## 1. Architectural Philosophy

AgentPCAP is engineered as a **local-first protocol-aware packet capture and debugger for AI agent systems**.
The core principle is:
> **One Go binary. No cloud account. No external database. Zero silent network telemetry.**

```text
               agent process
                     │
         ┌───────────┴───────────┐
         │ AgentPCAP             │
         │ Capture Engine        │
         └───────────┬───────────┘
                     │
             Normalize Events
                     │
         ┌───────────┴───────────┐
         │ .apcap Stream Writer  │
         └───────────┬───────────┘
                     │
        ┌────────────┴─────────────┐
        │                          │
   CLI Analysis                Web Viewer
(explain, diff, check)      (embedded React UI)
```

---

## 2. Component Pipeline

### 2.1 Ingestion Layer

1. **HTTP/HTTPS Forward Proxy (`internal/proxy`)**:
   - Intercepts outbound HTTP API requests (e.g. Gemini, OpenAI, Anthropic, REST tools).
   - Supports transparent TCP tunneling (`CONNECT`) for secure endpoints without TLS MITM interception.
2. **OTLP Trace Ingestion (`internal/protocols/otlp`)**:
   - Ingests traces via `/v1/traces` (HTTP/JSON).
   - Maps OpenTelemetry GenAI semantic conventions (`gen_ai.system`, `gen_ai.usage.*`) into canonical events.
3. **Child Process Launcher (`internal/runner`)**:
   - Launches user target commands via `exec.Command` with argument slices.
   - Injects proxy environment variables (`HTTP_PROXY`, `http_proxy`, `OTEL_EXPORTER_OTLP_ENDPOINT`).
   - Propagates OS signals (`SIGINT`, `SIGTERM`) and captures exit codes.
4. **Go SDK (`pkg/sdk`)**:
   - Optional in-code instrumentation for Go agent frameworks.

### 2.2 Normalization Layer

- **MCP Parser (`internal/protocols/mcp`)**: Standards-aware JSON-RPC 2.0 parser extracting tools discovery, calls, parameters, and result status.
- **A2A Parser (`internal/protocols/a2a`)**: Normalizes task creation, streaming updates, and multi-hop delegation chains.
- **Model Provider Adapters (`internal/protocols/model`)**:
  - Google Gemini / Vertex AI (`generateContent`, `streamGenerateContent`).
  - OpenAI-compatible (`/v1/chat/completions`).
  - Anthropic (`/v1/messages`).
- **Tool Normalizer (`internal/protocols/tool`)**: Standardizes tool invocation signatures and generates SHA-256 fingerprints of inputs for duplicate detection without storing sensitive arguments.

### 2.3 Storage & Container Layer (`pkg/apcap`)

- An `.apcap` file is a ZIP-compatible container housing:
  - `manifest.json`: Top-level metadata, protocols seen, and cryptographic SHA-256 hashes.
  - `metadata.json`: Aggregate metrics (total duration, tokens, cost, agent count).
  - `events.jsonl`: Append-only, line-delimited canonical event stream.
  - `attachments/`: Optional sanitized payloads.
- Security Defenses:
  - **Zip-Slip Prevention**: Enforces strict path normalization and rejects path traversals (`..`).
  - **Decompression Bomb Protection**: Bounded entry sizes (128 MB max entry, 256 MB total uncompressed).

### 2.4 Analyzer & Pathology Engine

- **Critical Path (`internal/analyzer`)**: Computes the longest wall-clock execution path across asynchronous tasks to pinpoint latency bottlenecks.
- **Pathology Detection (`internal/pathology`)**: Rule-based offline detection for:
  - `RETRY_STORM`: Rapid consecutive failed attempts on the same operation.
  - `LOOP`: Cyclic delegation patterns (e.g. Agent A -> B -> A).
  - `REPEATED_IDENTICAL_TOOL_CALL`: Multiple calls with identical input fingerprints.
  - `DUPLICATE_DISCOVERY`: Excessive MCP server polling.
  - `MODEL_FALLBACK`: Model cascades.
  - `TOKEN_SPIKE`: Single span consuming >65% of session budget.
  - `SLOW_TOOL` & `POSSIBLE_PARALLELIZATION`.

### 2.5 Presentation Layer

- **Embedded Web Server (`internal/server`)**: Serves embedded React + TypeScript assets from `web.DistFS`.
- **Live Stream**: Server-Sent Events (SSE) pushing packets in real time.
