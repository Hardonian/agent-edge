# Security & Boundary Invariants

AgentPCAP is designed to be run safely by developers on their local machines and in automated CI pipelines.

---

## 1. Network Listener Scoping

By default, all listeners (HTTP Web Viewer, SSE stream, Forward Proxy, OTLP receiver) bind to `127.0.0.1`.

- Listening on `0.0.0.0` or any non-loopback interface requires an explicit `--listen` argument.
- When bound to non-loopback addresses, AgentPCAP prints a prominent security alert warning the user that traffic inspection is exposed on the network.

---

## 2. Default Metadata-Only Capture

AgentPCAP adopts a strict privacy posture:

- **Default**: AgentPCAP records timing, protocol metadata, model IDs, tool names, status codes, token counters, and trace parentage. Raw user prompts, LLM completion texts, and raw tool arguments are dropped immediately in memory and are **not** written to disk.
- **Opt-In Content Capture**: The `--capture-content` flag instructs AgentPCAP to capture full payload bodies for deep payload inspection. This requires explicit user intent and triggers high-visibility warnings.

---

## 3. The TLS Interception Boundary

AgentPCAP v1 does **not** install local CA root certificates or silently decrypt TLS traffic.

- Plaintext HTTP proxying and standard TCP tunneling (`CONNECT`) are supported out of the box.
- Encrypted model or tool calls are captured via standard protocol endpoints (e.g. proxy-aware SDK base URLs, OTLP trace exporters, or explicit framework hooks).
- This avoids weakening system trust stores or triggering antivirus/EDR alerts.

---

## 4. Child Process Invocation Safety

When executing commands via `agentpcap run -- <command>`:

- The command is executed using `os/exec.Command` with an argument slice.
- No shell (`sh`, `bash`, `cmd.exe`, `powershell.exe`) is invoked, eliminating shell argument injection vulnerabilities.
- Standard input/output/error streams are connected directly.
- OS signals (`SIGINT`, `SIGTERM`) are trapped and relayed to child process groups to ensure clean teardown.

---

## 5. Hostile File Protections

Because developers often share `.apcap` files for debugging and bug reports, the `.apcap` container reader implements defense-in-depth against malicious archives:

- **Zip-Slip Prevention**: Every entry path inside the `.apcap` ZIP container is cleaned and verified to remain strictly beneath the target extraction directory.
- **Decompression Bomb Defense**: Single entry files are capped at 128 MB. Total extraction across all entries is capped at 256 MB. Exceeding limits halts reading immediately with `ErrDecompressionBomb`.
- **Integrity Verification**: `agentpcap validate <file.apcap>` computes and matches SHA-256 digests against the embedded manifest.
