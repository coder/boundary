# Boundary agent guide

This guide gives autonomous agents the context needed to change `github.com/coder/boundary` safely. It is intentionally consolidated so agents can load one detailed handbook after reading the root `AGENTS.md`.

## Repository map

| Path | Purpose |
|------|---------|
| `cmd/boundary/main.go` | Binary entrypoint. Creates the CLI command and exits with errors. |
| `cli/` | Serpent CLI, flags, environment variables, YAML config loading, privilege gate. |
| `config/` | App config, user info, session correlation config, header names. |
| `run/` | Platform dispatch. Linux runs a jail backend, non-Linux returns unsupported. |
| `proxy/` | HTTP and HTTPS filtering proxy, CONNECT support, TLS detection, audit, session correlation. |
| `rulesengine/` | Allow-rule parser and matcher. Default-deny policy. |
| `audit/` | Log auditor, socket auditor, multi-auditor, sequence counter. |
| `tls/` | Local CA creation/loading and per-host certificate generation. |
| `nsjail_manager/` | Default Linux namespace backend. Parent and child process orchestration. |
| `nsjail_manager/nsjail/` | Low-level veth, iptables, dummy DNS, env, and command runner code. |
| `landjail/` | Landlock backend using proxy env vars rather than transparent iptables routing. |
| `privilege/` | Linux privilege escalation through `sudo` and `setpriv`; non-Linux stubs. |
| `dnsdummy/` | Dummy DNS server used to prevent DNS exfiltration in namespace mode. |
| `log/` | slog setup to stderr or files. |
| `e2e_tests/` | Linux sudo tests that can mutate host networking. |
| `.github/workflows/` | CI, build, and release workflows. |

## Architecture overview

Boundary runs a target command in a restricted environment and sends its HTTP and HTTPS traffic through a local filtering proxy. Requests are evaluated against allow rules. Anything that does not match an allow rule is denied.

Core concepts:

- Default deny: no rule means no outbound HTTP or HTTPS request is allowed.
- Parent process: sets up proxying, audit, TLS, and jail infrastructure.
- Child process: runs inside the selected jail backend and executes the target command.
- Proxy: parses requests, evaluates allow rules, audits decisions, forwards allowed traffic, and blocks denied traffic.
- Auditor: logs every request decision to stderr and optionally to the Coder workspace-agent socket.
- TLS manager: creates a local CA and per-host certificates so HTTPS can be inspected.

Boundary has two jail backends:

- `nsjail`: default. Uses Linux network namespaces, veth pairs, iptables NAT and REDIRECT rules, and optional user namespaces.
- `landjail`: uses Landlock network restrictions. It relies on proxy environment variables instead of transparent iptables redirection.

## Runtime flow

High-level flow:

1. `cmd/boundary/main.go` calls `cli.NewCommand(version)`.
2. `cli/cli.go` parses flags, environment variables, and optional YAML config into `config.CliConfig`.
3. `config.NewAppConfigFromCliConfig` builds `config.AppConfig` and validates session-correlation config.
4. If jail type is `nsjail`, `privilege.EnsurePrivileges()` re-execs through `sudo` and `setpriv` when needed.
5. `run.Run` generates a boundary session UUID and dispatches to `nsjail_manager.Run` or `landjail.Run`.
6. The selected backend decides whether the current process is a parent or child by checking `CHILD=true`.
7. The parent parses allow rules, builds the rule engine, sets up auditors, creates TLS config, starts the proxy, then starts the child process.
8. The child applies jail-specific network setup and runs the target command.
9. The proxy evaluates each HTTP or HTTPS request and audits the result.
10. The parent stops the proxy and cleans up host resources when the target command exits or a signal is received.

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

`rulesengine/` parses and evaluates allow rules.

Rule grammar uses key-value tokens:

```text
method=GET,POST domain=github.com path=/api/*
```

Supported keys:

- `method`: one or more HTTP token values, comma-separated. `*` matches all methods.
- `domain`: hostname pattern. `*` can be a full label.
- `path`: one or more path patterns, comma-separated.

Important matching semantics:

- No matching allow rule means denied.
- `domain=github.com` matches only `github.com`.
- `domain=github.com` does not match `api.github.com`.
- `domain=*.github.com` matches subdomains like `api.github.com`.
- `domain=*.github.com` does not match the base domain `github.com`.
- To allow both a base domain and its subdomains, use two rules.
- Path wildcards are segment-based. A wildcard must be the entire segment.
- A path pattern ending in `*` can match additional path segments.

When changing rule parsing or matching:

- Update parser tests in `rulesengine/`.
- Update matcher tests in `rulesengine/`.
- Update README examples if user-visible behavior changes.
- Be careful with percent-encoded paths. Proxy forwarding preserves `RawPath` for cases like scoped npm package names.

## Proxy

`proxy/` contains the filtering proxy. It handles both transparent proxy traffic and explicit HTTP proxy traffic.

Main files:

- `proxy/proxy.go`: server lifecycle, TLS detection, HTTP and HTTPS processing, forwarding, block responses.
- `proxy/connect.go`: HTTP CONNECT tunnel support.
- `proxy/*_test.go`: proxy tests and framework.

Request handling paths:

1. Transparent HTTP: connection is not TLS, request is read directly, then evaluated.
2. Transparent HTTPS: first byte looks like TLS, boundary terminates TLS with a generated certificate, reads the HTTP request, then evaluates it.
3. Explicit HTTP proxy: client sends an absolute URL in the HTTP request.
4. Explicit HTTPS proxy: client sends CONNECT, boundary establishes a TLS tunnel, then reads HTTP requests inside the tunnel.

Important proxy behavior:

- Every request is audited before allow or deny handling completes.
- Audit sequence numbers are per proxy server instance and come from `audit.SequenceCounter`.
- Denied requests get a 403 response with suggested allow rules.
- Allowed requests are forwarded with a new upstream request.
- For GET and HEAD, forwarded request bodies are set to nil.
- Upstream responses are read fully so `Content-Length` can be set explicitly.
- Responses are normalized to HTTP/1.1 before writing back to the downstream client.
- Optional session-correlation headers are injected only when the request URL matches configured inject targets.

When changing proxy behavior:

- Prefer unit tests with `proxy/proxy_framework_test.go` and `httptest`.
- Avoid live network tests unless the behavior truly requires it.
- Test both allow and deny paths.
- Test both transparent and CONNECT paths when TLS behavior changes.
- Preserve audit behavior for both allowed and denied requests.

## Audit

`audit/` provides request auditing.

Key types:

- `audit.Request`: request decision payload.
- `audit.Auditor`: interface implemented by all auditors.
- `audit.LogAuditor`: writes structured logs through slog.
- `audit.SocketAuditor`: batches and forwards logs to the Coder workspace-agent socket.
- `audit.MultiAuditor`: fans out to multiple auditors.
- `audit.SequenceCounter`: atomic counter for per-request sequence numbers.

Important behavior:

- `SetupAuditor` always includes the log auditor.
- Socket forwarding is skipped when audit logs are disabled, the socket path is empty, or the socket does not exist.
- Socket auditor queues logs, batches them, retries connection failures, and reports drops.
- Allowed audit entries include the matching rule.
- Denied audit entries do not include a rule.
- Sequence numbers start at zero.

When changing audit behavior:

- Check `audit/socket_auditor_test.go` for batching, retry, drop, shutdown, and session ID expectations.
- Preserve the Coder boundary log proxy codec contract.
- Avoid blocking request handling on slow socket forwarding.

## TLS

`tls/` generates and loads certificates used for TLS interception.

Key behavior:

- A local CA is stored in the user's boundary config directory.
- Existing CA files are reused when possible.
- Per-host server certificates are generated on demand.
- The CA path is injected into child process environments so tools can trust boundary's generated certificates.

When changing TLS behavior:

- Preserve file ownership for the original user when running through sudo.
- Be careful with config directory paths from `config.UserInfo`.
- Consider the impact on curl, git, Python requests, and Node clients.
- Avoid broad certificate trust changes without explicit review.

## nsjail backend

`nsjail_manager/` is the default backend.

Parent flow:

1. Parse allow rules.
2. Build rule engine.
3. Set up audit.
4. Set up TLS and write CA certificate.
5. Create `nsjail.LinuxJail`.
6. Start the proxy.
7. Launch a child boundary process with `CHILD=true`.
8. Configure host-to-namespace communication after child PID exists.
9. Wait for child exit or signal.
10. Stop proxy and clean up iptables and veth state.

Child flow:

1. Wait for the jail-side veth interface.
2. Configure namespace networking.
3. Start dummy DNS and redirect DNS unless `--use-real-dns` is enabled.
4. Run the target command.

Low-level networking behavior:

- Host-side address: `192.168.100.1/24`.
- Jail-side address: `192.168.100.2/24`.
- Fixed subnet: `192.168.100.0/24`.
- TCP traffic from the jail is redirected to the local HTTP proxy with iptables.
- Non-TCP forwarding rules allow return traffic for non-TCP flows.
- Dummy DNS prevents DNS exfiltration by redirecting DNS to local dummy responses.

High-risk details:

- Interface names are constrained by Linux's 15-character interface name limit.
- iptables cleanup must mirror setup rules.
- `--no-user-namespace` changes clone flags and UID/GID mappings.
- `CAP_NET_ADMIN` and sometimes `CAP_SYS_ADMIN` are required.
- Non-HTTP TCP protocols are redirected but the proxy only understands HTTP and TLS-style traffic.

## landjail backend

`landjail/` uses Linux Landlock network restrictions.

Differences from nsjail:

- It does not set up transparent iptables routing.
- It sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` for the child.
- It clears `NO_PROXY` and `no_proxy` so clients do not bypass boundary.
- It configures CA-related environment variables for common clients.
- It restricts TCP connect to the proxy port.

When changing landjail:

- Check kernel and Landlock version assumptions.
- Preserve proxy env injection unless a task explicitly changes the model.
- Test that denied direct connections remain blocked.
- Remember that behavior depends on clients honoring proxy environment variables.

## Privilege model

`privilege/` handles Linux privilege escalation for the default nsjail backend.

Behavior:

- If needed, boundary re-execs through `sudo` and `setpriv`.
- It keeps the original user's UID/GID where possible.
- It adds ambient and inheritable capabilities required for network namespace and iptables work.
- Non-Linux builds use stubs.

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
