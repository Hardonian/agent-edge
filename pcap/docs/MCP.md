# Model Context Protocol (MCP) Support

AgentPCAP natively parses and normalizes the Model Context Protocol (JSON-RPC 2.0).

## 1. Supported MCP Methods

| Method | Canonical Event Type | Extracted Metadata |
| :--- | :--- | :--- |
| `initialize` | `MCP_DISCOVER` | Protocol version (`2024-11-05`), client name, capabilities |
| `tools/list` | `MCP_TOOLS_LIST` | Tool count, declared schemas, server identity |
| `tools/call` | `MCP_TOOL_CALL` | Tool name, argument keys, parameter fingerprints |
| Results | `MCP_TOOL_RESULT` | Result status, execution latency, `isError` flags |
| Error codes | `MCP_ERROR` | Error codes, error messages, fault provenance |

---

## 2. MCP Versioning & Warnings

AgentPCAP tracks the negotiated MCP protocol version (e.g. `2024-11-05`, `2024-10-07`).
If an agent system sends unsupported or malformed JSON-RPC payloads, AgentPCAP surfaces warnings in the packet inspector rather than crashing or discarding the packet.

---

## 3. Duplicate Discovery Pathology

Agents frequently poll `tools/list` before every single tool invocation. AgentPCAP flags this anti-pattern as `DUPLICATE_DISCOVERY`:

```text
2. [LOW] Repeated MCP tool discovery against server 'analytics-mcp-server'
   Explanation: MCP tools/list was polled 2 times during the session.
   Suggested: Cache MCP server tool specifications at agent boot rather than re-discovering before every call.
```
