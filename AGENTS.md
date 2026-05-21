# Boundary agent instructions

Boundary is a Linux network isolation tool for monitoring and restricting HTTP and HTTPS requests from child processes. This file is only the root entrypoint for agent runtimes. Keep canonical guidance in `docs/`.

## Canonical docs

- Human architecture overview: [docs/architecture.md](docs/architecture.md)
- Agent workflow guide: [docs/agent-guide.md](docs/agent-guide.md)
- E2E test safety guide: [docs/e2e-tests.md](docs/e2e-tests.md)

## Non-negotiable rules

- Read [docs/agent-guide.md](docs/agent-guide.md) before making non-trivial changes.
- Read [docs/e2e-tests.md](docs/e2e-tests.md) before running or changing e2e tests.
- Use `make unit-test` for normal validation. Do not assume `make test` exists.
- Ask before changing privilege escalation, iptables rules, certificate trust behavior, release workflow semantics, or the allow-rule grammar.

## Compatibility links

- `CLAUDE.md` points to this file for Claude-style agent runtimes.
- `ARCHITECTURE.md` points to `docs/architecture.md` for existing links.
- `.claude/docs/BOUNDARY_AGENT_GUIDE.md` points to `docs/agent-guide.md`.
- `.agents/docs` points to `.claude/docs` for agent runtimes that look under `.agents`.
- `e2e_tests/AGENTS.md` points to `docs/e2e-tests.md`.
