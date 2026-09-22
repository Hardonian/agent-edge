# Agent Packet Capture (.apcap) Specification

**Version: 1.0.0**  
**Status: Final / Stable**

## 1. Overview

`.apcap` (Agent Packet Capture) is an open, portable, deterministic, containerized file format for recording and analyzing multi-agent executions, LLM calls, tool interactions, and protocol-level traffic (A2A, MCP, OTLP, HTTP).

Think of `.apcap` as:
- **PCAP** for agentic systems: capturing protocol-level exchanges with accurate timing and causality.
- **HAR** for AI operations: capturing request/response metadata, latency, and status.
- **OTel Traces** for agents: capturing parent-child DAG relations, token usage, and cost.

## 2. Container Architecture

An `.apcap` file is a standard, unencrypted ZIP container containing the following canonical structure:

```text
capture.apcap (ZIP container)
├── manifest.json       # Top-level capture metadata, hashes, and protocol index
├── metadata.json       # High-level aggregate metrics (tokens, cost, error counts)
├── events.jsonl        # Line-delimited canonical event stream
└── attachments/        # Optional sanitized payloads, logs, or card definitions
```

### 2.1 Security & Invariants
- **Zip-Slip Protection**: All entry names must be relative without leading slashes or `..` path traversals. Readers MUST reject any entry containing directory traversal elements (`ErrPathTraversal`).
- **Decompression Bomb Protection**: Implementations MUST bound single-entry expansion (default 128 MB) and total archive uncompressed size (default 256 MB).
- **Cryptographic Integrity**: The `manifest.json` file contains a SHA-256 hash map of all other entries in the container, enabling verification of unmodified or completed captures.

## 3. Canonical Event Model

Each line of `events.jsonl` is a JSON object satisfying the following schema:

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `string` | Unique event identifier (UUID or monotonic string) |
| `trace_id` | `string` | Correlation trace ID grouping related operations |
| `parent_id` | `string?` | Optional parent event ID establishing causality |
| `timestamp` | `RFC3339` | UTC event start timestamp |
| `duration_ms`| `float64` | Wall-clock execution time in milliseconds |
| `type` | `enum` | Semantic event category (`AGENT_INVOKE`, `MCP_TOOL_CALL`, `MODEL_REQUEST`, etc.) |
| `protocol` | `enum` | Protocol used: `A2A`, `MCP`, `MODEL`, `TOOL`, `HTTP`, `POLICY`, `OTLP`, `CUSTOM` |
| `operation` | `string` | Normalized operation (e.g. `tools/call`, `chat/completions`) |
| `source` | `Endpoint` | Origin endpoint (`name`, `kind`: agent, model, tool, client) |
| `destination`| `Endpoint` | Target endpoint (`name`, `kind`: agent, model, tool, service) |
| `status` | `enum` | Outcome: `OK`, `ERROR`, `TIMEOUT`, `CANCELLED`, `UNKNOWN` |
| `attributes` | `map` | Normalized protocol parameters (e.g. model name, tool name) |
| `tokens` | `Tokens?` | Input, output, cached, and total token usage |
| `cost` | `Money?` | Monetary cost, currency, and calculation status (`ESTIMATED`, `MEASURED`, etc.) |
| `payload` | `Payload?` | Sanitized preview snippet, length, and redaction indicator |
| `provenance` | `enum` | Data source: `OBSERVED`, `PROTOCOL_PARSED`, `OTEL`, `SDK`, `DERIVED` |

## 4. Privacy & Redaction

### 4.1 Metadata-Only Default
By default, AgentPCAP operates in `metadata_only` mode. Prompts, completions, tool inputs/outputs, authorization headers, cookies, and tokens are omitted. Only lengths, tokens, duration, and protocol metadata are stored.

### 4.2 Content Capture & Redaction
When `--capture-content` is explicitly requested, all payloads undergo strict regex-based and structural redaction before persistence. Credentials, API keys (`sk-*`, `AIza*`, `ghp_*`), JWTs, Bearer tokens, and database connection strings are replaced with `[REDACTED]`.

## 5. Extensibility

Third-party extensions use the `extensions` dictionary in `manifest.json` or prefixed attributes in events:
- `x-agentmesh.*`: Mesh routing and policy governance telemetry.
- `x-modelforge.*`: Hardware, quantization, and deployment plan IDs.
