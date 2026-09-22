# X (Twitter) Launch Post & Thread

## Main Post

I built Wireshark for AI agents.

AgentPCAP captures A2A, MCP, model and tool traffic in one local timeline.

One Go binary. No account.

`agentpcap run -- ./my-agent`

Live topology • Waterfall • Cost flamegraph • Deterministic explain • Open .apcap format

https://github.com/agentpcap/agentpcap

---

## Thread

**2/5**
When your agent makes 15 calls across 3 subagents, 2 MCP servers, and an LLM, finding why a task lagged or blew up tokens usually means hunting through unstructured logs.

AgentPCAP normalizes all agentic protocols into an open `.apcap` format.

**3/5**
Zero-LLM Pathology Detection:
AgentPCAP runs deterministic offline analyzers that flag:

- Retry storms
- Recursive agent loops
- Duplicate tool calls with identical arguments
- Runaway delegation depth
- Token & cost spikes

**4/5**
Privacy by default:

- Metadata-only capture: prompts & completions are never saved unless you pass `--capture-content`
- Automated secret scrubbing for API keys, bearer tokens, and JWTs
- Strictly binds to `127.0.0.1`

**5/5**
Try it right now with our simulated offline multi-agent demo (no config or API keys required):

```bash
go install github.com/agentpcap/agentpcap/cmd/agentpcap@latest
agentpcap demo
```

Full docs, schema & screenshots: <https://github.com/agentpcap/agentpcap>
