# Boundary agent guide

This guide gives autonomous agents the context needed to change `github.com/coder/boundary` safely. It is intentionally consolidated so agents can load one detailed handbook after reading the root `AGENTS.md`. For a human-facing system overview, read `docs/architecture.md`.

## Architecture and runtime

See [docs/architecture.md](architecture.md) for the repository map, high-level model, startup flow, parent/child process model, policy model, proxy model, backend details, TLS, audit logging, session correlation, and security limitations.

The rest of this guide focuses on agent-specific workflow, change guidance, testing, and troubleshooting.

## CLI and config

The CLI is built with `github.com/coder/serpent` in `cli/cli.go`.

Important config types:

- `config.CliConfig`: serpent values for flags, environment variables, and YAML.
- `config.AppConfig`: runtime config passed into the jail backend and proxy setup.
- `config.SessionCorrelationConfig`: controls session-correlation header injection.
- `config.UserInfo`: resolves the effective user, including sudo scenarios.

Important CLI behavior:

- `--allow` is repeatable and CLI-only.
- YAML `allowlist` is merged with CLI `--allow` rules.
- `--jail-type` defaults to `nsjail`.
- `--use-real-dns` intentionally permits DNS exfiltration. Do not enable it by accident.
- `--disable-audit-logs` disables workspace-agent socket forwarding. It does not remove stderr logging.
- `--enable-session-correlation` requires configured inject targets or a valid fallback from `CODER_AGENT_URL`.
- `--log-proxy-socket-path` defaults to the Coder workspace-agent boundary log proxy socket path.

When changing CLI flags:

- Update README usage if behavior changes.
- Add or update config tests if parsing or validation changes.
- Check environment variable names. Some are shared with the Coder workspace agent.
- Preserve backwards compatibility unless the task explicitly allows breaking it.

## Rules engine

See the Policy model section in [docs/architecture.md](architecture.md) for the allow-rule grammar and matching semantics.

When changing rule parsing or matching:

- Update parser tests in `rulesengine/`.
- Update matcher tests in `rulesengine/`.
- Update README examples if user-visible behavior changes.
- Be careful with percent-encoded paths. Proxy forwarding preserves `RawPath` for cases like scoped npm package names.

## Proxy

See the Proxy model section in [docs/architecture.md](architecture.md) for HTTP, HTTPS, and CONNECT request paths and forwarding/blocking behavior.

Key files: `proxy/proxy.go`, `proxy/connect.go`, `proxy/*_test.go`.

When changing proxy behavior:

- Prefer unit tests with `proxy/proxy_framework_test.go` and `httptest`.
- Avoid live network tests unless the behavior truly requires it.
- Test both allow and deny paths.
- Test both transparent and CONNECT paths when TLS behavior changes.
- Preserve audit behavior for both allowed and denied requests.

## Audit

See the Audit logging section in [docs/architecture.md](architecture.md) for the audit model.

Key types: `audit.Request`, `audit.Auditor`, `audit.LogAuditor`, `audit.SocketAuditor`, `audit.MultiAuditor`, `audit.SequenceCounter`.

When changing audit behavior:

- Check `audit/socket_auditor_test.go` for batching, retry, drop, shutdown, and session ID expectations.
- Preserve the Coder boundary log proxy codec contract.
- Avoid blocking request handling on slow socket forwarding.

## TLS

See the TLS and certificate trust section in [docs/architecture.md](architecture.md) for the CA and certificate model.

When changing TLS behavior:

- Preserve file ownership for the original user when running through sudo.
- Be careful with config directory paths from `config.UserInfo`.
- Consider the impact on curl, git, Python requests, and Node clients.
- Avoid broad certificate trust changes without explicit review.

## nsjail backend

See the nsjail backend section in [docs/architecture.md](architecture.md) for the namespace, veth, iptables, and DNS model.

High-risk details:

- Interface names are constrained by Linux's 15-character interface name limit.
- iptables cleanup must mirror setup rules.
- `--no-user-namespace` changes clone flags and UID/GID mappings.
- `CAP_NET_ADMIN` and sometimes `CAP_SYS_ADMIN` are required.
- Non-HTTP TCP protocols are redirected but the proxy only understands HTTP and TLS-style traffic.

## landjail backend

See the landjail backend section in [docs/architecture.md](architecture.md) for the Landlock and proxy-env model.

When changing landjail:

- Check kernel and Landlock version assumptions.
- Preserve proxy env injection unless a task explicitly changes the model.
- Test that denied direct connections remain blocked.
- Remember that behavior depends on clients honoring proxy environment variables.

## Privilege model

See the Startup flow section in [docs/architecture.md](architecture.md) for how privilege escalation fits into the runtime.

When changing privilege code:

- Ask for review before implementation.
- Test both already-privileged and needs-escalation paths where possible.
- Preserve environment variables needed by child processes and the target command.
- Be cautious with PATH handling and sudo behavior.

## Testing

Normal validation:

```sh
make unit-test
make build
```

Formatting and linting:

```sh
make fmt
make fmt-check
make lint
```

E2E validation:

```sh
make e2e-test
```

Important test facts:

- `make unit-test` runs `go test -v -race $(go list ./... | grep -v e2e_tests)`.
- `make e2e-test` runs `sudo $(which go) test -v -race ./e2e_tests -count=1`.
- `make e2e-test` targets only the root `e2e_tests` package, not all subpackages.
- `make test-coverage` runs `go test -v -race -coverprofile=coverage.out ./...`, so it may include e2e packages.
- The Makefile currently does not define a `test` target. Do not use `make test` unless the Makefile changes.

Testing guidance by area:

- Rules changes: use parser and matcher tests in `rulesengine/`.
- Proxy changes: prefer `proxy/` unit tests with `httptest` and the proxy test framework.
- Config changes: use `config/*_test.go` and explicit environment slices.
- Audit changes: use `audit/*_test.go`, especially socket auditor behavior.
- nsjail and landjail changes: add focused unit tests where possible, then run e2e only on a suitable Linux sudo host.

Avoid adding new sleeps in tests. Prefer readiness checks, channels, contexts, test servers, and explicit process state checks. Existing tests contain sleeps, but that should not become the default pattern for new code.

## CI and releases

CI lives in `.github/workflows/ci.yml`.

Current CI behavior:

- Uses Go 1.25.
- Runs `make deps`.
- Runs `make fmt-check` and `make lint` in the lint job.
- Installs `golangci-lint` before linting.
- Bind-mounts `/run/systemd/resolve/resolv.conf` over `/etc/resolv.conf` before tests on Linux.
- Runs `make unit-test`.
- Runs `make e2e-test`.
- Runs `make build`.

Build and release workflows:

- `make build-all` builds Linux amd64 and Linux arm64 binaries.
- Build and release workflow files include Darwin artifact upload paths even though `make build-all` currently creates Linux binaries only.
- Release archives can be created from local `build/` output or downloaded workflow artifacts.

When changing CI or releases:

- Confirm Makefile targets exist before referencing them.
- Keep README, RELEASES, Makefile help, and workflows aligned.
- Avoid changing binary names or archive names without considering `install.sh`.
- Check whether artifacts are actually produced before uploading them.

## Troubleshooting

### `make test` fails with no rule

Use `make unit-test` for regular tests. The current Makefile does not define `test`.

### E2E tests fail with DNS issues

CI bind-mounts `/run/systemd/resolve/resolv.conf` over `/etc/resolv.conf` so namespace tests can reach upstream DNS instead of the host stub resolver. Local environments may need similar attention.

### E2E tests leave host networking residue

Inspect iptables and veth state. Cleanup should remove rules that setup added. Be careful before deleting unrelated host rules.

### Boundary cannot escalate privileges

Check that `sudo` and `setpriv` exist and that the current user can use sudo. The default nsjail backend needs capabilities for network setup.

### Port conflicts

Default proxy port is `8080`. Default pprof port is `6060`. Use CLI flags or environment variables when running multiple instances.

### HTTPS clients reject certificates

Check the CA path in the user config directory and the environment variables injected into the child process. Different clients use different CA variables.

### Rules do not match as expected

Check exact vs wildcard domain semantics first. `domain=github.com` and `domain=*.github.com` are different rules.

## Agent failure catalog

### Symptom: agent runs `make test`

Cause: generic Go habit or stale README/help references.

Fix: inspect the Makefile and run `make unit-test` for normal validation. Use e2e only when appropriate.

### Symptom: agent runs e2e tests in an unsuitable environment

Cause: treating e2e tests like normal unit tests.

Fix: stop and verify Linux, sudo, iptables, namespace support, required tools, and cleanup expectations.

### Symptom: proxy tests miss CONNECT or transparent TLS paths

Cause: testing only one request path.

Fix: add coverage for the path affected by the code change. TLS, HTTP, and CONNECT can differ.

### Symptom: allow-rule change breaks subdomain behavior

Cause: confusing exact domain and wildcard domain matching.

Fix: update tests for base domain, subdomain, and unrelated domain cases.

### Symptom: audit socket changes block request handling

Cause: doing synchronous socket work in the request path.

Fix: keep queueing and batching behavior. Preserve drop and retry tests.

### Symptom: workflow uploads artifacts that were never built

Cause: workflow artifact paths drift from `make build-all` outputs.

Fix: align Makefile, workflow uploads, RELEASES, and install script expectations.

## Review checklist

Before opening a PR:

- [ ] The change is narrow and avoids unrelated cleanup.
- [ ] `go fmt` or `make fmt` was run for Go changes.
- [ ] Focused tests were run for the changed area.
- [ ] `make unit-test` was run unless the change is docs-only and the user agreed to skip it.
- [ ] E2E tests were only run on a suitable Linux sudo host.
- [ ] README, Makefile, workflows, and release docs are aligned when commands or binaries change.
- [ ] Privilege, TLS, iptables, and rule grammar changes received explicit review.
