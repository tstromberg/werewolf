# Test probes

## Summary
One Zig runner executes validated YAML workflows inside a disposable test image.
Tests use the existing console protocol and SSH iteration transport.

## Background
Forms need HTTP, filesystem, process-policy and client checks without a guest shell.
Native drivers remain useful for protocols and attacks requiring custom code.

## Goals

- Reuse fixed probes and keep production service policies and bytes unchanged.
- Report independent failures with the case, step, source line and got/want values.
- Edit YAML and rerun in the same VM with `howl test --iterate`.

## Non-Goals

- A scripting language, shell, general guest agent or production test endpoint.
- Counting native escape hatches toward the YAML coverage target.

## Detailed design
On the host, `plan.zig` and `steps.zig` validate `forms/FORM/test/tests.yaml`
and a scenario's `test/scenarios/NAME/tests.yaml` (lib/yaml.zig's plan dialect)
and emit JSON for howl and `tools/native-tests.zig`, which builds one cached runner
per architecture and source digest.
The test stage invokes root suites directly and named-user suites through leash.
Native sources use the same stage and result contract. See
[the authoring guide](../../docs/testing-native.md) for the schema and examples.

| Module | Responsibility |
| --- | --- |
| `probes.zig` | Ordered cases, captures, readiness, assertions and diagnostics. |
| `fetch.zig` | libcurl transport, verified TLS, framing and case-local cookies. |
| `exec.zig` | Explicit argv, concurrent stdin/output, deadline and child cleanup. |
| `system.zig` | File metadata, service identities/connect rules, listeners and mounts. |
| `match.zig` | Structural equality, JSON Pointers and explicit comparisons. |
| `regex.c` | Keep libc's private `regex_t` layout behind a small C ABI. |
| `platform.zig` | Shared boot, confinement, service restart and reboot checks. |
| `udp.zig` | DNS source-port impersonation refusal and service recovery. |
| `tree.zig` | Bounded audits of directory trees, never following links. |
| `tcp.zig` | Text conversations over TCP, TLS or a Unix socket. |
| `write.zig` | Write-opens that must be refused; one that is not is undone. |
| `process.zig` | Service members' comm and cmdline as matchable text. |
| `host.zig` | Host suites, which `test/native-host.zig` runs on the build host. |
| `scenario.zig` | A scenario's keys: the form it boots, its skips, console lines, address. |

Clean boots run declared readiness, startup checks, lifecycle checks and application
suites in order. Readiness probes are read-only; failed readiness blocks restart
attacks. A planted child must die with its service; a run-specific data marker
must survive reboot. The host rejects
reformatting on the second boot. Existing form exclusions remain explicit; unknown
exclusions fail. SSH iteration uses only the selected form suite.

Limits are 256 KiB of YAML, 32 suites, 256 cases per suite and 64 steps per case.
Responses allow 1 MiB of body and 64 KiB of headers; clients allow 1 MiB stdout and
64 KiB stderr. Regex patterns allow 512 bytes. A tree walks 100,000 entries, 64
levels and 256 MiB of content at most; a conversation's reply holds 1 MiB, its
literal text 4 KiB; service text 1 MiB. Probes default to a 10-second request
deadline; `timeout: 45s` overrides one fetch, exec, tree or tcp call (1s..300s).
`await` retries read-only operations within its declared budget; transport and parse
failures do not silently satisfy a refusal assertion. The existing launcher and
console also impose whole-suite/boot deadlines.

Cases stop at their first failed step; independent cases continue. Captures and
cookie sessions reset for every case and boot phase. Fixture values and captured
responses are redacted in diagnostics. Every emitted result is bounded.

Run `make _test/probes _test/test/native/system.zig` for host contracts and
`make check-native-tests-gatus check-native-tests-postgresql` for VM checks.
`build/host/form-coverage --probes` accounts for the fixed migration inventory;
`--mapping` lists each old case. Renamed or split cases need explicit replacements.

## Drawbacks
Plans use a strict subset of YAML, without inline maps. HTTP suites add libcurl and
its locked dependencies to their test image. Root probes can mask permission bugs.

## Alternatives Considered
### Handwritten HTTP or guest shell commands
A maintained protocol library handles TLS, framing and cookies. A shell would add
unnecessary image drift and make process, timeout and quoting behavior less explicit.
### All tests in YAML
Use a native source when computation or protocol state cannot be expressed as
ordered fixed probes. Do not add loops, branches or shell expansion.

## Security Considerations
Auth and confinement tests select the tested user and leash policy. Root suites
inspect the existing VM; they do not change production service grants or enforcement.
Probes gain no privilege: the seal drops `CAP_SYS_PTRACE`, so no step reads another
user's environment. Writes that succeed are undone; `squat` restores its service even
when it fails. Clean test images add no shell, BusyBox or SSH. Iteration uses the
existing developer SSH key and `sh-shim`; it is not release evidence. Shipping images
omit test payloads.

## Reliability Considerations
Reject malformed plans before boot. Reject absent, duplicate, stale or failed
results. Mutations run once. Explicit read-only polling has a deadline; timeouts are
failures. Client input and both output pipes drain concurrently. Kill the client
process group and reap the direct child on completion or failure.
`test/probe-tests.zig` covers real HTTP/TLS, capture types, cookies, polling, output
limits and commands hanging after closing pipes. Compare test and shipping payloads
before boot and hash the run's inputs and logs.
