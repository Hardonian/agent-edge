# AgentPCAP Capture Modes

AgentPCAP provides multiple, complementary capture modes to balance convenience, fidelity, and security.

## Mode 1: Child Process Execution (`agentpcap run -- <cmd>`)

**Recommended for development.**

```bash
agentpcap run -- ./my-agent
```

- **Mechanism**: Spawns the target agent as a supervised child process using `exec.Command` (no shell string interpolation).
- **Injected Environment**:
  - `HTTP_PROXY`: Forward proxy destination (`http://127.0.0.1:<port>`)
  - `OTEL_EXPORTER_OTLP_ENDPOINT`: OpenTelemetry trace collector destination
  - `AGENTPCAP_ACTIVE`: Flag set to `1`
- **Signal Handling**: Forwards `SIGINT` (Ctrl+C) and `SIGTERM` cleanly to the child process and preserves its exit code upon termination.

---

## Mode 2: Explicit Forward Proxy (`agentpcap proxy`)

**Recommended for containers, VMs, and remote agent processes.**

```bash
agentpcap proxy --listen 127.0.0.1:8080
```

- **Mechanism**: Standard HTTP forward proxy.
- **Protocol Inspection**: Automatically sniffs and normalizes Gemini, OpenAI, Anthropic, and REST tool traffic.
- **TLS Tunneling**: Provides transparent `CONNECT` tunneling for HTTPS traffic without performing silent TLS MITM.

---

## Mode 3: OpenTelemetry Ingestion (`agentpcap otlp`)

**Recommended for frameworks with native OTel support (LangChain, LlamaIndex, Semantic Kernel).**

```bash
agentpcap otlp --listen 127.0.0.1:4318
```

- **Mechanism**: Ingests OTLP traces at `/v1/traces`.
- **GenAI Semantic Conventions**: Maps `gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, and `gen_ai.usage.output_tokens` directly into canonical AgentPCAP events.

---

## Mode 4: Zero-Dependency Go SDK (`pkg/sdk`)

**Recommended for Go agent authors desiring granular span control.**

```go
client := sdk.NewClient(sdk.Options{AgentName: "finance-agent"})
span, ctx := client.StartSpan(ctx, "analyze_portfolio")
defer span.End()

span.RecordToolCall("market_data_api", 45.0, false)
```

---

## Mode 5: Multi-Agent Simulation (`agentpcap demo`)

**Deterministic local test harness.**

```bash
agentpcap demo
```

Simulates an entire multi-agent orchestration workflow offline (finance, research, procurement, simulated Gemini, and MCP tools) to evaluate the viewer and capture features without real network credentials.
