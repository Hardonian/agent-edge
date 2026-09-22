# Show HN: AgentPCAP – Wireshark for AI Agents, MCP, and A2A

**Link**: <https://github.com/agentpcap/agentpcap>

I kept debugging multi-agent systems across separate A2A, MCP, and model logs, so I built a local Go tool that captures everything and renders the whole agent graph live in one unified timeline.

It’s called **AgentPCAP**, and we think of it as "Wireshark for AI agents."

```bash
# Run your agent through AgentPCAP
agentpcap run -- ./my-agent
```

Your browser opens immediately to `http://127.0.0.1:9477`. You see:

1. **Live Agent Topology**: Animated nodes for agents, tools, MCP servers, and LLMs with active traffic pulses.
2. **Wireshark-Style Packet List**: Exact timestamps, protocols (A2A, MCP, Gemini, OpenAI, Anthropic), durations, and token counts.
3. **Waterfall Timeline**: Hierarchical child spans with automatic critical path highlighting.
4. **Cost & Token Flamegraphs**: Hierarchical breakdown of where tokens and money were spent.
5. **Deterministic Pathology Detection**: Zero-LLM detection of retry storms, agent loops, repeated duplicate tool calls, and runaway delegation chains.
6. **Open `.apcap` Format**: Standardized, streamable ZIP container bundling `manifest.json`, `events.jsonl`, and metadata.

## Why not OpenTelemetry or hosted observability platforms?

Most existing observability solutions require Docker, an external daemon, a hosted SaaS account, or a database like ClickHouse/Postgres. When iterating locally, you don't want to spin up three cloud services just to see why an agent made 8 repeated calls to an MCP tool.

AgentPCAP is:

- **One single Go binary**: Embedded React/Vite UI via `go:embed`. No Node.js or Python runtime required.
- **Local-first & zero telemetry**: Captures stay on your laptop. No accounts, no API keys, no tracking.
- **Strict privacy defaults**: Metadata-only by default (prompts and model outputs are not stored unless you pass `--capture-content`).
- **Built-in secret redaction**: API keys, bearer tokens, and JWTs are scrubbed automatically.

## How it works

AgentPCAP supports four capture modes:

1. `agentpcap run -- <cmd>`: Starts an in-process proxy/OTLP listener, injects standard proxy env vars (`HTTP_PROXY`, `OTEL_EXPORTER_OTLP_ENDPOINT`), and executes your binary safely.
2. `agentpcap proxy`: Explicit forward HTTP/CONNECT proxy.
3. `agentpcap otlp`: Ingests OpenTelemetry traces (`/v1/traces`) and translates GenAI semantic conventions.
4. `pkg/sdk`: A tiny zero-dependency Go instrumentation library.

## Try the offline demo (no setup required)

If you just want to see it in action without configuring an agent:

```bash
# Download the binary (or `go install github.com/agentpcap/agentpcap/cmd/agentpcap@latest`)
agentpcap demo
```

This launches a simulated multi-agent transaction (finance-agent, research-agent, procurement-agent, simulated Gemini, and an MCP analytics server) that intentionally triggers a retry storm and duplicate discovery finding so you can test all views.

## Limitations

- It does **not** silently decrypt TLS traffic (no custom root CAs). It relies on standard proxy variables, OTLP exporters, or SDK hooks.
- Token costs are estimated against an offline snapshot pricing catalog unless reported directly by the provider.

The format specification and JSON schema are open under Apache 2.0. We'd love feedback on protocol parsing, format ergonomics, and what other agent protocols you'd like to see normalized.
