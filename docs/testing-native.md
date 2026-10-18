# Writing form tests

Use `forms/FORM/test/tests.yaml` for fixed probes and ordered HTTP workflows. The host
validates YAML and builds the existing native test image; the guest parses only JSON.
Keep custom Zig drivers for protocol state, computation and security attacks. See [the
design](design/test-probes.md) and [runner internals](../test/native/README.md).

Run the clean test image and shipping-image checks with:

```sh
howl test --with gatus
```

Every clean run includes shared platform checks for networking, immutable root,
encrypted data, service cleanup, privilege separation and persistence after reboot.
The form's existing `check.skip` exclusions still apply. Iteration omits this suite.
Foundations with a zero-case coverage exception can use `suites: []`; service forms
must declare application suites as well.
Retained `test/checks` or `checks-again` always keep the legacy DEV path active.
`legacy: true` can request it explicitly. Remove them only after their assertions have
replacements; shared supplied-code fixtures live under `test/`. The targeted clean
path is `make check-native-tests-gatus`.

For iteration, edit YAML and rerun one suite in the same disposable SSH VM:

```sh
howl test --with gatus --iterate --driver test-gatus
howl test --with gatus --iterate --driver test-gatus --phase verify
howl test --with gatus --iterate --stop
```

Only changed runner sources need recompilation; YAML uploads as data. Changes to
packages, fixtures, identity, policy or production inputs require rebuilding the VM.
Iteration results do not replace clean release checks.

## A small plan

```yaml
version: 1
suites:
  - name: web
    cases:
      - name: health
        steps:
          - fetch: {url: 'http://127.0.0.1:8080/health'}
            await: 60s
            expect: {status: 200, json: {'/status': UP}}
      - name: process-policy
        steps:
          - service: gatus
            expect: {user: gatus, capabilities: [], no_new_privileges: true}
```

Suite names gain the `test-` prefix. Cases run in both `seed` and `verify` unless
`phases: [seed]` or `phases: [verify]` selects one. Steps run in order, stopping the
case on failure; independent cases continue. Name a step to capture its response.

## Probes and assertions

| Probe | Request | Expected fields |
| --- | --- | --- |
| `fetch` | HTTP(S) request map | `status`, `headers`, `cookies`, `body`, `json` |
| `file` | Absolute path | `exists`, `type`, `uid`, `gid`, `mode`, `size`, `body`, `json`, `link`, `entries` |
| `exec` | `argv`, optional `stdin`, `env`, `readonly` | `exit`, `stdout`, `stderr`, `json` |
| `service` | Service name | `user`, `uid`, `groups`, `capabilities`, `bounding_capabilities`, `no_new_privileges`, `seccomp`, `processes`, `pids_max`, `connect_rules` |
| `listeners` | `tcp`, `udp`, or `all` | `contains`, `absent`, `equals` lists of protocol/address/port maps |
| `mount` | Exact mount path | `type`, `source`, `flags`, `absent_flags` |

Scalar and array assertions mean equality. Matcher maps support `equals`, `contains`,
`absent`, `one_of`, numeric `min`/`max`, `matches` (POSIX ERE), `count` and `type`.
For text, `occurrences: {literal: 3}` counts exact, non-overlapping occurrences.
Use `equals` to compare a literal object containing a matcher key. All comparisons
in a map must hold. JSON assertions map JSON Pointers to comparisons; missing fields
and malformed JSON fail. Response header names use lowercase; `server: null` requires
that header to be absent. File owners accept
names or numeric IDs; quote octal mode strings, for example `'640'`.
Use `listeners: tcp` with `expect: {absent: [{port: 5432}]}` to reject that port on
any address. `contains` and `absent` accept partial patterns; `equals` requires all
three fields so overlapping patterns cannot hide an extra listener.
Service assertions cover every member of the service cgroup, not just its first PID.
`user` checks the account; `uid: {min: 65536}` also checks its numeric ID range.
Capabilities accept Linux names such as `[net_raw, net_admin]`. Groups accept names
or IDs, either an exact list or `contains`/`absent`; `pids_max` is a string.

## HTTP workflows

`fetch` accepts `url`, `method`, `headers`, `bearer`, `session`, `ca`, `resolve` and
one of `body`, `json`, `form`, `multipart`. Multipart fields are strings or maps with
`file`, optional `filename` and `type`. TLS verifies both the CA and hostname.
Declare local CA files with `ca`; redirects and ambient proxies are disabled.
An expected status is checked before JSON assertions, so a starting proxy can be
polled through an empty 502. Malformed JSON at the expected status fails immediately.
Paths are sent literally, including traversal probes. `session` names a cookie jar
scoped to the current case. Header and cookie captures must be unambiguous.
Cookie assertions use case-sensitive names from the cookie jar; `VW_ADMIN: null`
requires absence. Duplicate names are ambiguous, never absent. Without `session`,
the jar belongs to that one request.

```yaml
# Inside a suite with fixtures: {password: /run/config/app/password}
name: login-and-list
steps:
  - name: login
    fetch:
      url: http://127.0.0.1:8000/api/token/
      method: POST
      json: {username: admin, password: {fixture: password}}
    expect: {status: 200}
  - fetch:
      url: http://127.0.0.1:8000/api/documents/
      bearer: {step: login, json: /token}
    expect: {status: 200, json: {'/results': []}}
```

References select an earlier step's `json` pointer, `header`, `cookie`, or `body: true`.
For `exec`, JSON assertions and captures parse stdout after checking the expected exit.
`{fixture: NAME}` reads a declared `/run/config/` fixture, trimming terminal newlines.
Use `{fixture: NAME, raw: true}` to preserve every byte, including binary HTTP bodies.
`{run: true}` supplies the shared run ID. References preserve types; putting an object
in a bearer token or argv fails the case. Captured values are not string templates.
`await: 60s` polls read-only GET/HEAD/OPTIONS requests or an explicitly `readonly: true`
client operation. Never poll a mutation or use a timeout as evidence of refusal.

`service.connect_rules` reads explicit fence connect declarations for each process's
effective UID, including global grants. Rules use form syntax (`tcp/443 public`) and
are sorted lexically. DNS resolver grants are separate; test actual refusals too.

## Identity and native drivers

Suites default to root for inspecting the VM. Use `user`, optional `groups` and
`policy: {pledge: ..., read: [...], connect: [...], run: [...]}` to run through leash
under the tested account. Root observation must not stand in for a permission test.
`exec` always requires its absolute client path in `policy.run`; no PATH or shell
expansion occurs. List extra client packages under the top-level `packages`.
PostgreSQL's SQL cases use the real `psql`, its stdin and `PGAPPNAME` for the run ID;
its refusal suite runs as `nobody`. No su, setuid helper or injected shell is needed.

For custom code, a suite declares `source: driver.zig`, `mode`, `user`, `policy` and
`cases: {seed: [...], verify: [...]}` instead of probe cases. Sources sit beside the
plan and use `test/native/driver.zig` for context and result records. PostgreSQL keeps
native descriptor-policy attacks; Greenbone retains its GMP/OSP protocol clients.
Native suites can declare `fixtures` too. For leashed clients, they appear under
`/run/svc/SUITE/`; root clients read the declared `/run/config/` paths directly.
Existing `native.json` plans remain readable, but a form cannot contain both formats.

## Migration and evidence

Preserve every old assertion, including refusals and reboot behavior. Seed writes a
run-specific value; verify reads it before setup can recreate it. Keep case names
stable or record split/renamed replacements in `test/form-probe-baseline.json`.
`python3 test/form-coverage --probes` reports progress against 722 baseline cases;
`--mapping` shows their current implementations. Native code does not count as YAML.
The 80% target remains a migration target, not a claim about the initial ports.

The harness compares production policies, accounts and runtime bytes before boot,
then records kernel, image, plan and log hashes. Clean tests add no BusyBox, shell
or SSH. A form may already ship a restricted shell adapter as part of its own contract.
Run both boot phases and the actual shipping-image check before retiring old coverage.
