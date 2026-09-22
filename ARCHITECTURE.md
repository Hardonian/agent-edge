# agent-edge — Architecture

> Part of the [Hardonia Platform](https://github.com/Hardonian/Hardonian).

## Position in the Platform

```
┌─────────────────────────────────────────────────────────────────┐
│                        HARDONIA PLATFORM                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  AUTOPILOT   │  │ AGENT-INFRA │  │ AGENT-EDGE  │             │
│  │             │  │             │  │ ◄── THIS    │             │
│  │             │  │ control-    │  │ mesh-edge/  │             │
│  │             │  │  plane/     │  │ pcap/       │             │
│  │             │  │ mission-    │  │             │             │
│  │             │  │  ledger/    │  └──────┬──────┘             │
│  │             │  │ agent-mesh/ │         │                    │
│  │             │  │ mcpwall/    │         │                    │
│  └─────────────┘  └──────┬──────┘         │                    │
│                          │                │                    │
│                          └────────────────┘                    │
│                    ┌───────────┐                               │
│                    │ MODEL-    │                               │
│                    │ TOOLS     │                               │
│                    └───────────┘                               │
├─────────────────────────────────────────────────────────────────┤
│  COMMERCIAL LAYER                                               │
│  hardonia-store · comfyui-workflow-packs · content-repo          │
└─────────────────────────────────────────────────────────────────┘
```

## What agent-edge does

Edge networking and traffic capture for agent-centric operations:

| Component | Language | Role |
|---|---|---|
| **mesh-edge** | Go | Privacy-first edge layer for Meshtastic mesh networks — smart relay, reliability, observability |
| **pcap** | Go | Wireshark for AI agents — capture A2A, MCP, model, and tool traffic in one local timeline |

## Dependencies on sibling repos

| Dependency | Via | What it provides |
|---|---|---|
| [agent-infra](https://github.com/Hardonian/agent-infra) | agent-mesh | Mesh networking identity and routing consumed by mesh-edge |

## Sibling repos

- [agent-infra](https://github.com/Hardonian/agent-infra) — control-plane, mission-ledger, agent-mesh, mcpwall
