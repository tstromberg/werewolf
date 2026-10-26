# Writing form tests

Author probes and workflows in `forms/FORM/test/tests.yaml`. A form ships its own Zig
only for what YAML cannot express; a new step type needs at least 3 forms that use it.
The host validates YAML; the guest parses JSON ([design](design/test-probes.md), [runner
internals](../test/native/README.md)). `howl test --with gatus` runs the clean test
image and shipping-image checks, and `make check-native-tests-gatus` the clean one.

Every clean run has shared platform checks for networking, immutable root, encrypted
data, service cleanup, privilege separation and persistence after reboot. `readiness:
true` suites run read-only probes first, and their failure blocks restart attacks;
platform checks, then application suites, follow. The form's `check.skip` exclusions
still apply. Iteration omits these shared suites. The host runs `test/config` before
seed and optional `test/config-again` before verify, keeping the data disk and key;
verify cases use the updated configuration. Foundations with a zero-case exception can
use `suites: []`; services need app suites. Retained `test/checks` or `checks-again`,
removed only once their assertions have replacements, keep the legacy DEV path active,
as `legacy: true` does. Shared supplied-code fixtures are in `test/`.

`howl test --with gatus --iterate --driver test-gatus` reruns one suite in the same
disposable SSH VM after YAML edits (`--phase verify` for verify; `--iterate --stop` ends
it). Only changed runner sources recompile; YAML uploads as data. Changes to packages,
fixtures, identity, policy or production inputs rebuild the VM. A small plan:

```yaml
version: 1
suites:
  - name: web
    fixtures:
      password: /run/config/app/password
    cases:
      - name: login-and-list
        steps:
          - name: login
            fetch:
              url: http://127.0.0.1:8000/api/token/
              method: POST
              json:
                password:
                  fixture: password
            expect:
              status: 200
          - fetch:
              url: http://127.0.0.1:8000/api/documents/
              bearer:
                step: login
                json: /token
            await: 60s
            expect:
              json:
                /results: []
```

Plans use a strict YAML subset (lib/yaml.zig): block maps and lists, `[a, b]` lists of
scalars, quoted or `/pointer` keys, one-line strings with `\n` `\t` `\r`, `|` blocks.
Inline maps are refused; `{a: b}` here stands for a block map. Plain `true`, `false`,
`null` and numbers are typed; quote what YAML 1.1 types, such as `yes`, `01` or dates.
Suite names gain the `test-` prefix. Cases run in both `seed` and `verify` unless
`phases: [seed]` or `phases: [verify]` selects one. Steps run in order, stopping the
case on failure; independent cases continue. Name a step to capture its response.

## Probes and assertions

| Probe | Request | Expected fields |
| --- | --- | --- |
| `fetch` | HTTP(S) request map | `status`, `headers`, `cookies`, `body`, `json` |
| `file` | Absolute path | `exists`, `readable`, `type`, `uid`, `gid`, `mode`, `size`, `body`, `json`, `link`, `entries` |
| `exec` | `argv`, optional `stdin`, `env`, `readonly` | `exit`, `stdout`, `stderr`, `json` |
| `service` | Service name | `user`, `uid`, `groups`, `capabilities`, `bounding_capabilities`, `no_new_privileges`, `seccomp`, `processes`, `pids_max`, `connect_rules`, `comm`, `cmdline` |
| `listeners` | Protocol string or `{protocol: tcp, port: 636}` | `contains`, `absent`, `equals` address/port maps |
| `mount` | Exact mount path | `type`, `source`, `flags`, `absent_flags` |
| `tree` | Absolute root, or `{roots: [...], allow: [...]}` | `entries`, `files`, `type`, `path`, `name`, `mode`, `content` |
| `write` | Absolute path, or `{path: ..., existing: true}` | `errno` |
| `tcp` | `connect: HOST:PORT` or `unix: PATH`, `tls`, `ca`, `readonly`, `exchange` | none: its `exchange` expects |
| `squat` | DNS service name | none |

Scalar/array assertions mean equality; `not_equals` checks literal inequality, even of a
binary body (`''` proves it nonempty); types must match. Matchers support `equals`,
`contains`, `absent`, `one_of`, `min`/`max`, regex `matches`/`not_matches`, `count` and
`type`; `contains_all`/`contains_none` require each match/refusal. Regexes are POSIX
ERE: `^`/`$` anchor the whole text, and YAML `"\n"` supplies a literal newline. For
text, `occurrences: {literal: 3}` counts exact, non-overlapping occurrences. `equals`
compares a literal object holding a matcher key. All comparisons in a map must hold.
JSON assertions map JSON Pointers to comparisons; missing fields and malformed JSON
fail. Response headers are lowercase; `server: null` requires that header's absence.
File owners accept names or IDs; quote modes such as `'640'`. `readable` attempts a
nonblocking read-open as the suite's user: only permission denial proves `false`;
missing paths and other I/O errors fail. Check existence and ownership as root when a
protected parent hides metadata. `listeners: tcp` with `expect: {absent: [{port:
5432}]}` rejects that port on any address. `contains` and `absent` take partial
patterns; `equals` needs all three fields, so no pattern hides an extra listener.
`listeners: {protocol: tcp, port: 636}` checks only that port's whole address set.
Service assertions cover every member of its cgroup, not just its first PID. `user`
checks the account; `uid: {min: 65536}` also its numeric range. Capabilities take names:
`[net_raw, net_admin]`. Groups take an exact list or `{contains: group}`/`{absent:
group}` with names or IDs; `pids_max` is a string; `seccomp` is `none`, `strict` or
`filter`. `comm` and `cmdline` (arguments joined by spaces) see all members as sorted
text lines, one per member.

`tree` walks its roots, bounded and never following symbolic links; unreadable entries
fail. `entries` and `files` count what it found; each entry's `type`, `path` (from its
root), `name` and `mode` must hold, a link having no mode. An `allow` regex exempts, but
still counts, the paths it matches. `content: {absent: X}` or `{contains_none: [...]}`
refuses literal or fixture bytes in each regular file; `mode: {not_matches: '[2367]$'}`
refuses world-writable entries. `write` opens its path for writing as the suite's user,
creating it exclusively, or with `existing: true` untruncated; `errno` is `EACCES`,
`EPERM`, `EROFS` or `one_of` them, and leashed (`wpath`, a `read` grant) only `EROFS`:
its own sandbox refuses the rest. Success removes its file and fails. A `tcp` `exchange`
lists `send` (text or reference), `pause: 1s` (to `60s`), `expect` and a last `close`.
An `expect` waits until the reply since the last send holds its `prefix`, `contains`
and `matches`, failing once it cannot or the stream ends. `close: eof`, `reset` or both
needs the server to close with no byte past what the last `expect` saw: anchor it with
`$`. `tls: verify` checks `ca` (else the system's CAs) and the host; `insecure`,
neither. `squat: SERVICE` (root, `/usr/bin/sv`, `/usr/bin/drill` in `policy.run`) stops
a DNS service, proves its port cannot send off the VM, restores it and awaits an answer.

## HTTP workflows

`fetch` takes `url`, `method`, `path`, `headers`, `bearer`, `authorization`, `session`,
`ca`, `resolve` and one of `body`, `json`, `form`, `multipart`. Multipart fields have
`file`, optional `filename` and `type`, or a string value. TLS verifies CA and hostname.
`authorization` takes `scheme` and `credentials`; `bearer` is the Bearer shorthand.
Declare local CA files with `ca`; redirects and ambient proxies are disabled. An
expected status is checked before JSON assertions, so a starting proxy can be polled
through an empty 502. At that status, malformed JSON fails at once. Use `path: [api,
{step: create, json: /id}]` under a fixed origin; each value stays one escaped segment.
Literal URLs still send traversal probes unchanged. `session` scopes cookies to a case;
without it, the jar belongs to that one request. Header and cookie captures must be
unambiguous. Cookie assertions use case-sensitive names from the jar; `VW_ADMIN: null`
requires absence. Duplicate names are ambiguous, never absent. References select prior
`json`, `header`, `cookie`, `body: true`, or `regex` captures. `{step: form, regex:
'name="csrf" value="([^" ]+)"'}` requires one nonempty group in one unambiguous
body/stdout match (512-byte POSIX ERE); it returns raw text. `exec` JSON assertions and
captures parse stdout after the expected exit. `{fixture: NAME}` reads a declared
`/run/config/` fixture, trimming terminal newlines. Raw `{fixture: NAME, raw: true}`
preserves bytes; file captures need a body assertion. `{run: true}` supplies the shared
run ID. References keep types: an object in a bearer token or argv fails the case;
captures are not string templates. Top-level `timeout: 1200s` bounds each phase (default
`300s`, range `1s..1800s`). `await: 60s` polls GET/HEAD/OPTIONS or a `readonly: true`
client or `tcp` within that budget. Never poll mutations or accept timeouts as refusals.
A step's `timeout: 45s` caps one fetch, client, tree or tcp call without retries
(default `10s`, maximum `300s`). Clean runs and SSH iteration, readiness and native
drivers included, share the phase budget. Unknown matchers fail validation before an
image is built. `service.connect_rules` reads each process's explicit fence connect
declarations by effective UID, global grants included, in form syntax (`tcp/443
public`); lists compare unordered. DNS grants are separate; test real refusals too.

## Identity and native drivers

Suites default to root to inspect the VM. Use `user`, optional `groups` and `policy:
{pledge: ..., read: [...], connect: [...], run: [...]}` to run through leash as the
tested account. Root observation never stands in for a permission test. `exec` needs its
absolute client path in `policy.run`; no PATH or shell expansion occurs. List extra
clients in the top-level `packages`; `prune: [usr/bin/scp]` drops what they bring that
no test runs. PostgreSQL's SQL uses the real `psql`, its stdin and `PGAPPNAME` for the
run ID; its refusals run as `nobody`, with no su, setuid or shell. Custom code declares
`source: driver.zig`, `mode`, `user`, `policy`, `cases: {seed: [...], verify: [...]}`
and optional `fixtures` beside its sources. `test/native/driver.zig` reports results;
`driver.fetch.Client` speaks HTTP. Unit-test parsers on rendered fixtures before a VM
build. Leashed clients read `/run/svc/SUITE/`; root reads declared `/run/config/` paths.
Native setup can save generated IDs as JSON on `/data`, for `file` steps to capture.
[Bugsink](../forms/bugsink/test/tests.yaml) keeps project IDs on reboot.

## Migration and evidence

Preserve every old assertion, including refusals and reboot behavior. Seed writes a
run-specific value; verify reads it before setup can recreate it. Keep case names stable
or record split/renamed replacements in `test/form-probe-baseline.yaml`.
`build/host/form-coverage --probes` reports progress toward 80% of 722 baseline cases;
`--mapping`, their implementations. Native code does not count as YAML. SSH logins run
from the host in [host suites](testing-host.md); Jellyfin keeps `legacy: true` for its
in test/boot. Keep old coverage, supplied-code gates too, until both phases and the
shipping-image check pass. The harness compares production policies, accounts and
runtime bytes, then records kernel, image, plan and log hashes. Clean tests add no
BusyBox, shell or SSH client; a form may ship a restricted shell adapter of its own.
