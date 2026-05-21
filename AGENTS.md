# Boundary agent instructions

Boundary is a Linux network isolation tool for monitoring and restricting HTTP and HTTPS requests from child processes. It is security-sensitive code that can mutate host networking during e2e tests.

Start here, read [ARCHITECTURE.md](ARCHITECTURE.md) for the human system overview, then read the relevant agent workflow sections in [.claude/docs/BOUNDARY_AGENT_GUIDE.md](.claude/docs/BOUNDARY_AGENT_GUIDE.md).

## Non-negotiable rules

- Do not run host-mutating e2e tests casually. They require Linux, sudo, iptables, network namespaces, and cleanup discipline.
- Do not assume `make test` exists. Use `make unit-test` for normal validation and `make e2e-test` only when a Linux sudo environment is appropriate.
- Do not skip `go fmt` for Go changes.
- Keep changes narrow. Avoid unrelated cleanup in security, networking, privilege, TLS, or audit code.
- Preserve Linux build tags in platform-specific files.
- Ask before changing privilege escalation, iptables rules, certificate trust behavior, release workflow semantics, or the allow-rule grammar.

## Fast commands

| Task | Command | Notes |
|------|---------|-------|
| Dependencies | `make deps` | Downloads and verifies Go modules |
| Build | `make build` | Builds `./boundary` for the current platform |
| Build all | `make build-all` | Builds Linux amd64 and arm64 binaries |
| Unit tests | `make unit-test` | Race-enabled tests excluding e2e packages |
| E2E tests | `make e2e-test` | Linux only, needs sudo, mutates host networking |
| Coverage | `make test-coverage` | Runs `go test ./...`; may include e2e packages |
| Format | `make fmt` | Runs `go fmt ./...` |
| Format check | `make fmt-check` | Uses `gofmt -l .` |
| Lint | `make lint` | Requires `golangci-lint` |
| Clean | `make clean` | Removes build and coverage artifacts |

## Read before editing

- Human architecture overview: [ARCHITECTURE.md](ARCHITECTURE.md)
- Repository map and agent architecture notes: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#repository-map](.claude/docs/BOUNDARY_AGENT_GUIDE.md#repository-map)
- Runtime flow: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#runtime-flow](.claude/docs/BOUNDARY_AGENT_GUIDE.md#runtime-flow)
- CLI and config: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#cli-and-config](.claude/docs/BOUNDARY_AGENT_GUIDE.md#cli-and-config)
- Rules engine: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#rules-engine](.claude/docs/BOUNDARY_AGENT_GUIDE.md#rules-engine)
- Proxy behavior: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#proxy](.claude/docs/BOUNDARY_AGENT_GUIDE.md#proxy)
- Audit logs: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#audit](.claude/docs/BOUNDARY_AGENT_GUIDE.md#audit)
- TLS certificates: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#tls](.claude/docs/BOUNDARY_AGENT_GUIDE.md#tls)
- nsjail backend: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#nsjail-backend](.claude/docs/BOUNDARY_AGENT_GUIDE.md#nsjail-backend)
- landjail backend: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#landjail-backend](.claude/docs/BOUNDARY_AGENT_GUIDE.md#landjail-backend)
- Testing: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#testing](.claude/docs/BOUNDARY_AGENT_GUIDE.md#testing)
- CI and releases: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#ci-and-releases](.claude/docs/BOUNDARY_AGENT_GUIDE.md#ci-and-releases)
- Troubleshooting: [.claude/docs/BOUNDARY_AGENT_GUIDE.md#troubleshooting](.claude/docs/BOUNDARY_AGENT_GUIDE.md#troubleshooting)

## High-risk areas

- `e2e_tests/`: read [e2e_tests/AGENTS.md](e2e_tests/AGENTS.md) first.
- `nsjail_manager/`: Linux namespaces, veth, iptables, dummy DNS, privilege-sensitive cleanup.
- `landjail/`: Landlock restrictions, proxy environment injection, and `NO_PROXY` clearing.
- `proxy/`: transparent proxying, explicit CONNECT, TLS MITM, audit sequencing, session-correlation headers.
- `rulesengine/`: exact and wildcard domain semantics. Grammar changes need broad test coverage.
- `tls/`: local CA lifecycle, generated certificates, ownership, and client trust behavior.
- `.github/workflows/`: release and build workflow changes can affect shipped binaries.

## Compatibility

`CLAUDE.md` should mirror this file for Claude-style agent runtimes. `.agents/docs` points to `.claude/docs` for agent runtimes that look under `.agents`.
