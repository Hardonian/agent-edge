# Reddit Launch Post (r/LocalLLaMA, r/golang, r/artificial)

**Title**: AgentPCAP – A local-first, single-binary "Wireshark" for AI agents, MCP, and model traffic

**Body**:

Hey everyone,

Whenever I build or test agent workflows combining A2A (Agent-to-Agent), Model Context Protocol (MCP) servers, and LLM APIs, debugging turns into a mess of fragmented console logs, unformatted JSON-RPC dumps, and guesswork over why a task took 12 seconds or burned 40k tokens.

Existing tracing platforms are either heavy distributed tracing systems requiring Docker and ClickHouse, or hosted SaaS platforms requiring cloud API keys.

I built **AgentPCAP**: an open-source, local-first packet capture and protocol analyzer designed specifically for AI agents.

## What it does

- Single static Go binary with an embedded React web viewer. No Node, Python, or database required.
- Ingests traffic via transparent HTTP proxy, OTLP receiver (`/v1/traces`), or a tiny Go SDK.
- Live animated topology graph showing agents, models, tools, and MCP servers.
- DevTools-style packet list + waterfall timeline with critical path calculation.
- Hierarchical cost and token flamegraphs.
- Deterministic offline diagnostics (`agentpcap explain`) that detect retry storms, agent loops, redundant tool calls, and runaway delegations without needing an LLM.
- An open file format (`.apcap`) based on streaming ZIP with JSON manifests and JSONL event records.
- Metadata-only by default: prompts and completions are discarded unless you explicitly pass `--capture-content`. Secrets (API keys, JWTs) are scrubbed automatically.

## Test it in 10 seconds

You can run the simulated offline multi-agent scenario with zero dependencies:

```bash
go install github.com/agentpcap/agentpcap/cmd/agentpcap@latest
agentpcap demo
```

Your browser opens to `http://127.0.0.1:9477` where you can inspect live A2A delegation, tool calls, retry storms, and the cost flamegraph.

Repository & Format Spec: <https://github.com/agentpcap/agentpcap>

I'd really appreciate any feedback on the `.apcap` specification, parser coverage, or analyzer heuristics.
