# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-04

### Added

- **Core Engine & Single Binary Distribution**:
  - Pure Go binary embedding compiled React + Vite + TypeScript web viewer via `go:embed`.
  - Zero runtime dependencies on Node.js, Python, Docker, or external databases.
  - Safe child runner (`agentpcap run -- <cmd>`) with automated signal propagation and proxy configuration.
- **Open `.apcap` Format**:
  - Portable, streaming ZIP-compatible container specification (`manifest.json`, `events.jsonl`, `metadata.json`, `attachments/`).
  - Formal JSON Schema (`spec/apcap.schema.json`).
  - Hostile archive defenses (Zip-slip traversal protection, 128 MB file extraction limits, 256 MB bundle extraction bounds).
- **Protocol Parsers & Normalizers**:
  - **MCP (Model Context Protocol)**: Full JSON-RPC 2.0 discovery (`tools/list`), tool calls (`tools/call`), tool results, errors, and transport version tracking.
  - **A2A (Agent-to-Agent)**: Task delegation, requests, streaming responses, and delegation graph lineage.
  - **Model Providers**: Adapters for Google Gemini / Vertex AI, OpenAI-compatible endpoints, Anthropic Claude, and generic HTTP LLMs with token usage extraction.
  - **Tool Call Normalization**: Unified tool taxonomy with SHA-256 argument fingerprinting for duplicate detection.
  - **OpenTelemetry Ingestion & Export**: Standard OTLP/HTTP receiver (`/v1/traces`) mapping GenAI semantic conventions and OTLP trace exporter (`agentpcap export otlp`).
- **Deterministic Offline Analyzer & Pathology Detection**:
  - Zero-LLM offline diagnostics (`agentpcap explain`).
  - Critical path DAG identification and latency bottleneck analysis.
  - 9 deterministic pathology detectors: `RETRY_STORM`, `LOOP`, `REPEATED_IDENTICAL_TOOL_CALL`, `DUPLICATE_DISCOVERY`, `MODEL_FALLBACK`, `UNBOUNDED_OR_DEEP_DELEGATION`, `TOKEN_SPIKE`, `SLOW_TOOL`, `POSSIBLE_PARALLELIZATION`.
- **Hierarchical Flamegraphs**:
  - Interactive multi-mode flamegraphs for Cost, Tokens, Wall-clock Time, and Calls.
  - Snapshot pricing catalog for Gemini, GPT-4o, Claude 3.5, and local models.
- **Run Comparison & CI Checks**:
  - Terminal and visual diff engine (`agentpcap diff run1.apcap run2.apcap`).
  - CI assertion engine (`agentpcap check run.apcap`) backed by `.agentpcap.yml` rules.
- **Interactive Live Viewer**:
  - Real-time Server-Sent Events (SSE) streaming.
  - Animated SVG agent topology graph with clickable node and edge inspectors.
  - DevTools-style packet list with multi-field filtering (`protocol:`, `status:`, `agent:`, `duration:`).
  - Waterfall execution timeline with critical path badges.
  - Drag-and-drop `.apcap` file loading.
- **Privacy & Security Defenses**:
  - Strict loopback binding (`127.0.0.1`) by default.
  - Metadata-only capture default (no raw prompts/completions stored without `--capture-content`).
  - Centralized regex redaction engine (`agentpcap redact` & `agentpcap inspect-redaction`).
  - Standalone single-file HTML report export (`agentpcap report run.apcap -o report.html`).
- **Multi-Agent Simulation**:
  - Deterministic offline demo (`agentpcap demo`) orchestrating simulated finance, research, and procurement agents with MCP analytics and Gemini models.
