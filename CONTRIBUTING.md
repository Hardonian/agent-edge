# Contributing to AgentPCAP

Thank you for contributing to AgentPCAP! AgentPCAP is an open-source, local-first packet capture and protocol analyzer for AI agents.

## Development Principles

1. **Local-First & Zero Telemetry**:
   AgentPCAP must never require a cloud account, remote database, or third-party telemetry. Captures stay on the user's machine.

2. **Single-Binary Philosophy**:
   The entire application (CLI, proxy, parser, analyzer, and web viewer) compiles into one standalone static Go binary with embedded frontend assets (`go:embed`). No Node.js or Python runtime is required for end users.

3. **Strict Protocol Fidelity**:
   We model actual protocols (MCP, A2A, OTLP, GenAI HTTP). We do not fake success or invent unsupported features.

4. **Security & Privacy by Default**:
   Metadata-only captures, automated secret redaction, safe child process invocation, and loopback listener binding.

---

## Prerequisites

- **Go**: 1.22+ installed
- **Node.js**: 20+ with **pnpm**: 9+ (only needed if building or modifying the web viewer)

---

## Local Workflow

### Building from Source

```bash
# 1. Install frontend dependencies & compile web assets
cd web
pnpm install
pnpm build
cd ..

# 2. Build the agentpcap Go binary
go build -o agentpcap ./cmd/agentpcap
```

Or simply use the `Makefile`:

```bash
make web     # Build frontend
make build   # Compile Go binary
make test    # Run all tests
make demo    # Launch the multi-agent demo
```

### Running Tests

```bash
# Unit and integration tests
go test -v ./...

# Race condition detection
go test -race ./...

# Fuzz testing
go test -fuzz=FuzzApcapReader ./pkg/apcap -fuzztime=10s

# Frontend verification
cd web
pnpm typecheck
pnpm test
pnpm lint
```

---

## Code Quality Standards

Before submitting a pull request:

- Run `go fmt ./...` and `go vet ./...`.
- Ensure `go test -race ./...` passes without errors.
- Ensure all new public types and methods in `pkg/apcap` and `pkg/sdk` are well-documented.
- Avoid external runtime dependencies unless justified; prefer the Go standard library.

## Pull Request Process

1. Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
2. Add comprehensive unit tests covering happy paths, edge cases, and hostile input.
3. Commit with concise, descriptive commit messages.
4. Open a PR against `main`. Automated GitHub Actions CI will verify compilation, race conditions, fuzzing, and frontend tests.
