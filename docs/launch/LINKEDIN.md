# LinkedIn Launch Post

Debugging multi-agent systems shouldn’t require stitching together disjointed logs across MCP servers, LLM APIs, and agent frameworks.

Introducing **AgentPCAP** — Wireshark for AI agents.

AgentPCAP is an open-source, local-first protocol analyzer and packet capture tool packaged as a single Go binary.

Key highlights:
• Live agent topology, A2A delegation chains, and MCP tool inspections
• Waterfall timeline with automatic critical path calculation
• Hierarchical cost & token flamegraphs
• Offline pathology detection: identifies retry storms, agent loops, and duplicate tool calls with zero LLM dependencies
• Open `.apcap` file format for sharing captures and bug reports
• Local-first: no cloud account, no credit card, no external telemetry

Try it in seconds:

```bash
agentpcap demo
```

Check out the project: <https://github.com/agentpcap/agentpcap>

Tags: #AI #OpenSource #SoftwareEngineering #Go #LLMOps #AgenticAI #DevTools
