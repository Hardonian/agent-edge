# AgentPCAP — 45-Second Silent Product Demo Script

**Visual Tone**: High-framerate, clean terminal, sleek dark-mode UI, smooth camera zooms. No voiceover required.

---

## Storyboard Timeline

| Timestamp | Screen Action | Visual Focus | Caption / Subtitle |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:05** | Developer opens terminal and types: `agentpcap demo` | Terminal window with prompt execution. Fast browser launch popup. | *One command. Local-first. Zero configuration.* |
| **0:05 - 0:12** | Browser opens to `http://127.0.0.1:9477`. Topology graph animates: `finance-agent`, `research-agent`, `analytics-tool`, `simulated-gemini`. | Directed SVG graph with live glowing edges and active pulse animations. | *Live Agent Topology. A2A & MCP visual DAG.* |
| **0:12 - 0:20** | User clicks edge between `research-agent` and `analytics-tool`. Packet inspector slides in from the right. | JSON-RPC 2.0 payload inspection: `tools/call`, sanitized arguments, latency `42ms`. | *Protocol-aware packet inspection. Zero secret leaks.* |
| **0:20 - 0:28** | Screen pulses yellow as a retry storm occurs: `simulated-gemini` returns 429 twice, then 200. Diagnostic finding badge triggers: `RETRY_STORM: 3 calls`. | Findings panel in bottom-left displaying rule-based detection with root cause chain. | *Deterministic pathology detection without LLMs.* |
| **0:28 - 0:36** | User clicks **Waterfall** tab. The full execution timeline unfolds with parent-child task nesting and critical path highlighted in crimson. | Hierarchical Gantt-style spans with critical path metrics. | *Hierarchical waterfall & critical path bottleneck analysis.* |
| **0:36 - 0:45** | Transition to terminal. User runs: `agentpcap diff run_before.apcap run_after.apcap`. Clean ANSI table shows -50% latency, -8k tokens, and 0 retries. | Terminal diff table with green improvements and red regressions. | *Compare agent runs like code diffs. AgentPCAP v1.0.0.* |
