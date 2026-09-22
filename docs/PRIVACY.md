# Privacy & Data Sovereignty

AgentPCAP is built on strict data sovereignty principles:

## 1. Local by Default
- Captures remain exclusively on your local workstation.
- AgentPCAP requires no accounts, no subscriptions, and no cloud connectivity.
- Zero analytics, telemetry, or phone-home pings are built into the binary.

## 2. Metadata-Only Default
- By default, AgentPCAP does not store:
  - Raw prompts or conversation histories
  - Model completions or outputs
  - Tool arguments or outputs
  - Authorization headers, Bearer tokens, or cookies
- Only structural metadata is recorded:
  - Protocol, operation, destination, duration, token usage, and status.

## 3. Explicit Opt-In Content Capture
To capture sanitized payloads for deep forensic debugging, explicitly provide the flag:

```bash
agentpcap run --capture-content -- ./my-agent
```

Even when content capture is enabled, all payloads undergo automatic centralized regex scrubbing to eliminate API keys and credentials before writing to disk.
