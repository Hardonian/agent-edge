# AgentPCAP Quickstart

Get started with AgentPCAP in under 60 seconds.

## 1. Installation

### Download Precompiled Binary

Download the latest binary for your operating system from GitHub Releases, or compile directly:

```bash
# Clone and build
git clone https://github.com/Hardonian/AgentPCAP.git
cd AgentPCAP
make
```

### Verify Environment

Run the diagnostic check to ensure all components are operational:

```bash
./agentpcap doctor
```

Output:

```text
AgentPCAP Doctor
================
✓ embedded viewer assets: OK
✓ default viewer port 9477: AVAILABLE
✓ local capture engine: READY
✓ OTLP/HTTP receiver: READY
✓ MCP JSON-RPC 2.0 parser: READY
✓ A2A protocol parser: READY
✓ Model adapters (Gemini, OpenAI, Anthropic): READY
✓ Secret redaction engine: READY

○ Cloud accounts / credentials: not required
○ External database server: not required

Status: READY FOR LOCAL OPERATION
```

---

## 2. Launch Local Multi-Agent Demo

To explore AgentPCAP immediately with simulated multi-agent traffic (finance-agent, research-agent, MCP tools, and Gemini calls):

```bash
./agentpcap demo
```

The embedded viewer will open automatically at `http://127.0.0.1:9477`.

---

## 3. Capture Your Own Agent

Launch any agent executable or script as a child process:

```bash
./agentpcap run -- python my_agent.py
```

AgentPCAP will:

1. Start the local capture engine and HTTP proxy.
2. Inject `HTTP_PROXY` and `OTEL_EXPORTER_OTLP_ENDPOINT` into the child process.
3. Open the live web viewer in your default browser.
4. Stream packets, model requests, and tool calls in real time.
5. Save the complete trace to `capture_<timestamp>.apcap` when your agent finishes.

---

## 4. Inspect and Explain a Capture

Analyze execution bottlenecks, token spend, and anomalies offline without calling any LLM:

```bash
./agentpcap explain run.apcap
```

---

## 5. Compare Two Runs

Compare baseline vs optimized captures to measure latency and token deltas:

```bash
./agentpcap diff baseline.apcap candidate.apcap
```
