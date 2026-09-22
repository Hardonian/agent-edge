# AGENTS.md — AgentPCAP Developer & Coding Agent Guide

## 1. System Philosophy & Mental Model

**AgentPCAP** is "Wireshark for AI agents":
- **Local-first**: Operates offline without external database servers, API keys, or cloud accounts.
- **Single-binary**: One Go executable embeds the compiled React + TypeScript frontend via `web.DistFS` (`go:embed`).
- **Open `.apcap` format**: Containerized, ZIP-compatible package (`manifest.json`, `events.jsonl`, `metadata.json`, `attachments/`).
- **Metadata-only privacy default**: Raw prompts, completions, and tool arguments are never persisted unless `--capture-content` is explicitly set. Centralized redaction scrubs credentials and tokens.
- **Protocol-aware normalization**: Native parsers for A2A, MCP (JSON-RPC 2.0), LLM providers (Gemini, Vertex, OpenAI, Anthropic), and OpenTelemetry GenAI semantic conventions.

---

## 2. Directory Structure

```text
cmd/agentpcap/            # CLI entrypoint (run, proxy, demo, open, diff, explain, etc.)
pkg/apcap/                # Standalone .apcap format reader, writer, and security validation
pkg/sdk/                  # Zero-dependency instrumentation SDK for Go agents
internal/
  analyzer/               # Critical path calculations and flamegraph trees
  browser/                # Platform-safe browser opener
  capture/                # In-memory capture session, ring buffer, and live event bus
  config/                 # .agentpcap.yml configuration loader and CI assertion engine
  cost/                   # Token accounting and snapshot model pricing engine
  demo/                   # Multi-agent simulation fixture generator
  diff/                   # Comparison engine between two .apcap captures
  pathology/              # Rule-based deterministic anomaly detectors (loops, retry storms)
  protocols/
    a2a/                  # Agent-to-Agent protocol normalization
    mcp/                  # Model Context Protocol JSON-RPC 2.0 parser
    model/                # Gemini, Vertex, OpenAI, Anthropic adapters
    otlp/                 # OpenTelemetry GenAI trace receiver and exporter
    tool/                 # Unified tool call normalizer
  proxy/                  # HTTP forward proxy with transparent tunneling
  redact/                 # Centralized secret scrubbing and inspection engine
  report/                 # Offline single-file HTML report exporter
  runner/                 # Child process launcher with env injection and signal propagation
  server/                 # Embedded HTTP web server, SSE live stream, and REST APIs
  version/                # Build metadata and version string
web/                      # React + TypeScript + Vite frontend
spec/                     # APCAP format specification and JSON Schema
examples/                 # Sample capture files (.apcap)
docs/                     # Comprehensive documentation
```

---

## 3. Critical Invariants for Developers & Agents

1. **Zero Shell Interpolation**:
   - `agentpcap run -- <command>` MUST use `exec.CommandContext(ctx, cmd[0], cmd[1:]...)` with raw argument slices. NEVER construct command strings via shell interpreters (`sh -c`, `bash -c`, `cmd.exe /c` interpolation).
2. **Path Traversal & Zip-Slip Protection**:
   - Every file entry read from an `.apcap` archive must pass `validateSafePath()`. Any entry starting with `/`, `\`, `..`, or drive letters like `C:` MUST be rejected with `ErrPathTraversal`.
3. **Decompression Bomb Defense**:
   - Uncompressed entries are bounded by `MaxEntrySizeBytes` (128 MB) and total archive read by `MaxUncompressedBytes` (256 MB). Never use unbounded `io.ReadAll` on zip readers.
4. **Loopback Binding by Default**:
   - Web viewer and proxy listeners must bind to `127.0.0.1` by default. Never default to `0.0.0.0`.
5. **Deterministic Analysis**:
   - `agentpcap explain` and pathology detection must NEVER call out to an external LLM or cloud API. All findings must be reproducible, rule-based, and tagged with an analyzer version.
6. **Panic Prohibition**:
   - No malformed network packet, corrupt `.apcap` file, or unexpected JSON payload may trigger a panic. All errors must be handled gracefully.

---

## 4. Testing & Verification Commands

```bash
# Run unit tests
go test -v ./...

# Run race condition checks
go test -race ./...

# Run fuzz tests on archive reader
go test -fuzz=FuzzApcapReader -fuzztime=5s ./pkg/apcap

# Build web frontend
cd web && pnpm build && cd ..

# Compile standalone executable
go build -o agentpcap.exe ./cmd/agentpcap

# Verify environment & binary health
./agentpcap doctor
```
