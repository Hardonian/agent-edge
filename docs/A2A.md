# Agent-to-Agent (A2A) Protocol Support

AgentPCAP provides first-class support for Agent-to-Agent communication and delegation topologies.

## 1. Supported Operations

- **Task Dispatch**: `task/dispatch` creates an `A2A_REQUEST` event with caller and callee endpoints.
- **Delegation**: Nested tasks create `DELEGATION` events capturing initiator, parent tasks, and delegation depth (`a2a.delegation_depth`).
- **Task Results**: Completed or failed executions create `A2A_RESPONSE` or `A2A_ERROR` events.
- **Artifact Exchanges**: Number of returned artifacts is recorded in attributes.

---

## 2. Topology Visualization

Agent-to-agent interactions are automatically linked in the live topology view:
```text
[finance-agent] ────(A2A)────► [research-agent]
       │                              │
  (DELEGATION)                      (MCP)
       ▼                              ▼
[procurement-agent]         [analytics-mcp-server]
```

---

## 3. Delegation Loop Detection

Cyclic delegation patterns where Agent A delegates to Agent B, which subsequently delegates back to Agent A (or A -> B -> C -> A), are automatically flagged by the pathology engine with `Severity: HIGH`.
