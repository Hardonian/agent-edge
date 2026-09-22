# agent-edge

**Agent edge infrastructure: mesh edge layer and packet capture.**

This monorepo unifies two Hardonian projects for agent-centric edge operations:

| Directory | Project | Description |
|-----------|---------|-------------|
| [`mesh-edge/`](mesh-edge/) | MEL — MeshEdgeLayer | Privacy-first edge layer for Meshtastic mesh networks: smart relay, reliability, observability. |
| [`pcap/`](pcap/) | AgentPCAP | Wireshark for AI agents — capture A2A, MCP, model, and tool traffic in one local timeline. |

## Repository structure

```
agent-edge/
├── mesh-edge/    # MEL-MeshEdgeLayer (subtree)
│   ├── cmd/      # CLI entrypoints
│   ├── internal/ # core packages
│   └── go.mod    # github.com/mel-project/mel
├── pcap/         # AgentPCAP (subtree)
│   ├── cmd/      # CLI entrypoints
│   ├── pkg/      # public packages
│   └── go.mod    # github.com/agentpcap/agentpcap
└── go.work       # Go workspace definition
```

## Getting started

### Prerequisites

- Go 1.22+

### Build all modules

```bash
go work sync
go build ./mesh-edge/...
go build ./pcap/...
```

### Quick links

- **MEL**: [mesh-edge/QUICKSTART.md](mesh-edge/QUICKSTART.md) · [mesh-edge/CONTRIBUTING.md](mesh-edge/CONTRIBUTING.md)
- **AgentPCAP**: [pcap/README.md](pcap/README.md) · [pcap/spec/README.md](pcap/spec/README.md)


## Related Repos

### Platform Monorepos
- [autopilot](https://github.com/Hardonian/autopilot) — ops, finops, growth, support
- [agent-infra](https://github.com/Hardonian/agent-infra) — control-plane, mission-ledger, agent-mesh, mcpwall
- [model-tools](https://github.com/Hardonian/model-tools) — model-forge, inference-api, ollama-router

### Commercial
- [hardonia-store](https://github.com/Hardonian/hardonia-store) — storefront
- [comfyui-workflow-packs](https://github.com/Hardonian/comfyui-workflow-packs) — ComfyUI workflow products
- [content-repo](https://github.com/Hardonian/content-repo) — blog posts and email sequences

## License

Each subproject retains its own license. See [mesh-edge/LICENSE](mesh-edge/LICENSE) and [pcap/LICENSE](pcap/LICENSE).