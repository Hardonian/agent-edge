# APCAP Canonical Public Test Vectors

This directory provides standardized public test vectors for the **Agent Packet Capture (.apcap) v1.0** specification.

Each test vector contains:

1. `<name>.apcap`: The canonical containerized archive.
2. `expected.json`: The expected normalized output after parsing the bundle according to `spec/apcap.schema.json`.

Third-party implementations in Python, Rust, TypeScript, or Go can validate their parsers against these fixtures.

---

## Vectors Overview

| Vector | Description | Primary Invariant Verified |
| :--- | :--- | :--- |
| [`minimal/`](./minimal/) | Single-event agent start / invoke capture. | Minimal valid container structure (`manifest.json`, `metadata.json`, `events.jsonl`). |
| [`mcp/`](./mcp/) | MCP tool discovery (`tools/list`), execution (`tools/call`), and response (`tools/result`). | JSON-RPC 2.0 tool invocation, argument hash, and causality chain. |
| [`a2a/`](./a2a/) | Agent-to-Agent task dispatch, hierarchical delegation, and completion. | Parent-child relationship tracking, delegation depth, and agent identity. |
| [`otel/`](./otel/) | OpenTelemetry GenAI span ingestion via OTLP/HTTP. | GenAI semantic conventions, token metrics, and OTLP trace mapping. |
| [`multi-agent/`](./multi-agent/) | Multi-agent collaboration with model provider calls (Gemini), tool executions, and tokens. | Token usage accounting, model pricing estimation, and DAG topology. |
| [`errors/`](./errors/) | Server failure (503) followed by retry and timeout. | Error status representation, retry event normalization, and pathology detection. |
| [`retries/`](./retries/) | Deterministic 3-attempt retry storm (429 rate limit to 200 OK). | Pathology detection of retry storms, causal parent grouping, and retry latency attribution. |
| [`incomplete/`](./incomplete/) | Archive written during unexpected process crash (SIGKILL mid-stream). | Graceful recovery of all valid events prior to truncation without reader panic. |

---

## Verification

To re-verify all test vectors against the JSON schema:

```bash
go test -v ./spec
```
