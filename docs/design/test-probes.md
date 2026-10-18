# Standard test probes

## Summary
Run YAML workflows and native drivers with shared probes and explicit test identities.

## Background
The [730949c inventory](https://github.com/werewolf-linux/werewolf/tree/730949c)
has 113 forms, 722 legacy form cases and nine native plans. HTTP, file/policy, service
and client checks dominate. Native ports duplicate HTTP code; failures lack diagnostics.

## Goals

- Standard probes cover at least 578/722 baseline cases (80%); estimate: 80–90%.
- Map every case to YAML, a native driver or a host check; preserve its full assertion.
- One `howl test --with FORM` path for clean runs, CI and existing `--iterate` use.

## Non-Goals

- A general scripting language, universal guest tools, or 99% YAML at any cost.
- Replacing VM orchestration, production acceptance or specialized protocol clients.

## Detailed design
`forms/FORM/test/tests.yaml` replaces authoring `native.json`. The host validates it
and generates the existing immutable launch plan plus typed probe data. Reject duplicate
keys, unknown fields, tags, aliases, ambiguous scalars and unresolved references.
The guest parses no YAML. A root runner with test-only grants runs probes; suites can
select a user, groups and leash policy. One plan defines cases/steps or native sources.
Reject old/new plans together. YAML and Zig share probes; cache builds per architecture.

| Probe | Contract and examples |
| --- | --- |
| `fetch` | HTTP(S), status/headers/body/JSON; nginx, Gatus, login, uploads, WebDAV. |
| `file` | Content, type, owner, mode, size, links, entries; config and data. |
| `exec` | Declared client path + argv, stdin, env, exit/output; psql, LDAP, Valkey. |
| `service` | Process identities, caps, seccomp, cgroup limits and compiled connect rules. |
| `listeners` | Expected TCP/UDP addresses and ports, IPv4/IPv6; detect extra listeners. |
| `mount` | Filesystem type, source and required/forbidden mount flags. |

`fetch` uses pinned test-only libcurl for TLS, framing, compression and HTTP/2/trailers.
Support methods, literal paths, fixture bodies, form/multipart fields and named cookie
sessions. Verify certificates with declared trust; explicit address mappings retain SNI.
Disable ambient proxies and automatic redirects; follow only explicitly declared steps.
Assertions use equality, membership, absence, counts, numeric bounds, regex or JSON
Pointers. All assertions must hold; missing fields and parse errors fail. File reads
distinguish absence from denial; refusal cases require the intended error.
`exec` uses pinned clients with argv; no shell or lookup. Scripts count as custom code.

```yaml
# Case within a suite declaring TCP/8000 and a password fixture.
name: login-and-list
phases: [seed, verify]
steps:
  - name: login
    fetch:
      url: http://127.0.0.1:8000/api/token/
      method: POST
      json: {username: admin, password: {fixture: password}}
    expect: {status: 200}
  - name: list-documents
    fetch:
      url: http://127.0.0.1:8000/api/documents/
      bearer: {step: login, json: /token}
    expect: {status: 200, json: {'/results': []}}
```

Each case is an ordered workflow; steps reference prior responses using typed selectors.
Missing/ambiguous captures fail; sessions and captures stay within a case/phase.
Allow cookies, CSRF/token capture and read-only polling; use Zig for branching or
computation. No loops or functions. PostgreSQL uses `psql`; expose a built-in run ID.
The host retains run ID and disks for reboot; verify reads state before setup writes.
Use existing native drivers for Greenbone GMP/OSP, inference, WebSockets, MQTT/NATS
concurrency, malformed/fragmented packets and security attacks needing custom fixtures.
Host drivers retain SSH/SFTP/Git, config rotation, power cuts and protected updates.
Console checks and app fixtures share the result contract; test empty carriers too.

Track case mappings in `test/form-coverage`, excluding custom code from the 80% target.
Port fetch/file, then system/client checks. Test nginx, Gatus, PostgreSQL, Paperless and
Greenbone on both architectures/reboot; delete legacy dispatch only after full parity.

## Drawbacks
YAML/libcurl add dependencies; root can mask access bugs. Keep complex cases in Zig.

## Alternatives Considered
### Only Zig drivers
Shares helpers too, but data edits require compilation; YAML suits ordered workflows.
### Shell commands or a growing HTTP shim
Shell adds guest drift; maintaining another HTTP/TLS implementation adds avoidable bugs.

## Security Considerations
Privileged tests preserve production policies, hidepid and package bytes.
Peer-auth/access probes run as child processes with the tested user's groups and policy.
Refusals must reach the intended control. No su/setuid or global enforcement changes.
Clean tests add no BusyBox/shell/SSH; iteration uses SSH. Releases omit test payloads.

## Reliability Considerations
Bound output and time; `await` polls only read-only readiness/completion predicates.
Mutations run once; timeouts never prove refusal. Kill/reap timed-out children.
Report source line, operation/input, got/want and diffs; redact secrets and captures.
Stop dependent steps on failure; continue independent cases. Blocked cases cannot pass.
Reject missing/duplicate/stale results; hash inputs. Test failures and shipping images.
