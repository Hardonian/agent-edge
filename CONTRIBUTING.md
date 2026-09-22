# Contributing

Thank you for your interest in contributing to the Hardonia platform.

## Toolchain

| Language | Package Manager | Notes |
|---|---|---|
| TypeScript | `pnpm` (>= 9) | Use `pnpm install`, `pnpm build`, `pnpm test` |
| Python | `uv` | Use `uv sync`, `uv run python`, `uv run pytest` |
| Rust | `cargo` | Use `cargo build`, `cargo test` |
| Go | `go` | Use `go build ./...`, `go test ./...` |

## Branch naming

- `feature/<description>` — new features
- `fix/<description>` — bug fixes
- `chore/<description>` — maintenance, CI, docs

## Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scope): add new capability
fix(scope): resolve edge case
chore(scope): update dependencies
docs(scope): clarify setup instructions
```

## Pull requests

1. Create a branch from `main` using the naming convention above.
2. Make your changes with clear, atomic commits.
3. Ensure all tests pass (`pnpm test`, `uv run pytest`, `cargo test`, or `go test ./...`).
4. Open a PR against `main` with a clear description.

### PR template

```markdown
## What

Brief description of the change.

## Why

Motivation or linked issue.

## How

Implementation notes, if non-obvious.

## Testing

How this was verified (tests, manual, CI).

## Checklist

- [ ] Tests pass
- [ ] Documentation updated (if applicable)
- [ ] No secrets or credentials in diff
```

## Code style

- TypeScript: strict ESM, Zod for runtime validation
- Python: type hints, FastAPI conventions
- Rust: `clippy` clean, `rustfmt`
- Go: `gofmt`, `go vet`

## Security

Never commit secrets, API keys, or credentials. Use environment variables and `.env` files excluded by `.gitignore`.

## Questions

Open an issue or start a discussion on the repo.
