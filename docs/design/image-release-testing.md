# Testing and publishing the images users run

Design, 2026-10-15. PostgreSQL's native clients, shim checks, two-boot persistence and
CLI dispatch are implemented ([test/native/](../../test/native/),
[cmd/howl/test.zig](../../cmd/howl/test.zig)) on the local QEMU check profile; the
Greenbone suite passes locally; HTTPS login, scans and publication remain proposed.

## Scope

One host test command, native boot-time drivers and an unmodified release-image run;
passing form/architecture/provider/profile targets publish independently through one
workflow, with signed evidence and package/PR history. **3–6 engineer-weeks for the
four core forms**, contingent on the gaps below; shell-suite ports and export are extra.

## Current state

`howl test` runs DEV integration tests and a separate production boot. The
[form-images](../../release/form-images) pipeline builds only `minimal`, `prod-ssh`
and `playground` in
secure-boot and legacy-boot profiles, compares independent builds, runs coverage and
`howl test`, and keeps inventories, notes and a signed R2 catalog. It publishes a target
only once its exact bundle passes the [lifecycle
test](../../test/check-published-lifecycle). QEMU uses the production owner channel for
all three published forms; Lima currently uses SSH for playground. Compatibility images
have separate exact-disk and direct-boot checks. The earlier stock-disk publisher is
retired; both profiles share one release flow.

## Coverage contract

`howl test --with FORM` owns the run: prepare fixtures, build the candidate and a test
variant from the same pinned inputs, boot both, collect results, return one status.
Private services use local native clients, public ones the same contract plus host
probes; export is optional, never the test transport.

| Run | Subject | Purpose |
| --- | --- | --- |
| Unit/component | Existing tests, disposable fault fixtures | Parsers, confinement, updater/TPM state machines |
| Native integration | Production payload plus compiled drivers | Live SQL, peer auth, permissions, persistence |
| Release acceptance | Unmodified signed candidate | The artifact's boot, behavior, lifecycle guarantees |

The variant adds only declared test executables, their dependencies and launch
metadata: no DEV, shell, compiler or sshd. Production programs are the same bytes in
both variants and the filesystem, package and policy delta is checked against an
allowlist; added tests change hashes and PCRs, so results name the variant. Drivers
are small Zig executables sharing a result protocol, preferring existing clients (psql)
run with argument arrays; each suite pins its clients, lives beside its form and keeps
its own permissions. They are built into the variant's verified root under isolated
test authority with Secure Boot, IPE, verity and enforcement on; one that needs the
seal or a service's confinement relaxed is refused. Publication rejects variants by
manifest identity as well as payload delta. The [fourteen protected
gates](../../release/prepare-protected) stay; moving an exact-image assertion to shared
fixtures needs a policy review and validator tests.
Exact-image runs boot a verified writable copy with no DEV, ssh, test agent or extra
privilege; slots are never installed by hand; vendor keys stay in signing jobs and
unhealthy fixtures on disposable authority; storage is observed, never repaired.

## Triggering tests and collecting results

The host boots each variant with normal configuration and a fresh run ID. A fixed
launcher starts only the compiled suite plan after seal and fence; drivers await
readiness with deadlines, finish once, and take no console command, arbitrary path or
downloaded code; host retries cannot hide a failed assertion. A private service is
tested locally as allowed and denied identities, a public one in its protocol with host
probes, persistence by writing in one phase and reading after a host-driven transition,
the protected lifecycle by the host driving channel, VM and TPM fault points. Each
driver carries its own confinement; production identities and limits stay; one-shot
tests join neither the health set nor commitment. Drivers emit bounded records (run
ID, suite, phase, case, result) ending in a completion record; the host requires the
expected case set and fails on a missing or duplicate result, panic or timeout. Results
are diagnostics, not attestation, since other guest processes can write the console:
they are correlated with console offsets and boot/TPM observations. The host keeps
QEMU/Lima control, channel changes, power cuts and TPM observation through the Python
orchestration and monitor/TPM proxy. Reports bind descriptor and disk hashes, target,
inputs, harness and policy revision, tools, configuration and run identity, and each
assertion its expected and observed values and hashed logs; secrets are redacted.

## PostgreSQL and Greenbone

PostgreSQL ([forms/postgresql/test/](../../forms/postgresql/test/)): the variant alone
adds pinned `postgresql-client`; the driver runs `psql -X -w -A -t -v
ON_ERROR_STOP=1 -P pager=off` as postgres on the Unix socket with fixed SQL, bounded
output and a deadline, checking locale, UTF-8 writes and rollback, while a separately
confined identity must fail peer login; the server's policy and exposure stay. Phase one
writes a unique row; the next boot of the same disk, and the boot after P → C, read it
before any setup write. The unmodified candidate boots and updates separately, proving
measured identity, readiness, commitment and no public SQL. Greenbone's clients check
GMP/OSP, target persistence, ordinary database roles, Valkey ACLs and read-only shares.
HTTPS login, P → C and a fixture scan remain proposed; repeatable scans need a pinned
feed cache and 8 GiB RAM.

## Remaining lifecycle gaps

**QEMU control and health:** the production host-private virtio owner port exposes
only fixed updater operations and status through the existing updater broker role.
It adds no shell or network listener. Storage write errors prevent commitment; the
real deadman and loader must recover the retained signed release. Owner rollback uses
the normal authenticated `try` operation. Lima still needs this driver for forms
without ordinary SSH. **Distinct releases:** test P → C and a real
successor where C's updater or retirement must run; renamed serials do not count;
fixture-only successors are never promoted; power-cut runs keep real TPM state.

## CLI and publication

`howl forms`, `howl forms FORM` and `howl test --with FORM` stay, the last running both
suites; `--dev` stays for debugging; a proposed `howl test --image BUNDLE` tests an
artifact without injecting code. form-images.yml becomes the sole image orchestrator
and GitHub writer (APKs apart): pinned inputs, two builds, a gate per target; change
detection covers trust, tools and test policy; only supported passing targets advance,
and evidence never crosses providers or architectures. Immutable R2 objects go up
before signed heads, public bytes are verified, serial floors kept; drafts stay private
until parity, a receipt makes retries idempotent, nothing falls back to legacy trust.
Notes compare each image with its last passing inventory and list the merged PRs and
commits; missing history holds publication.

## Staged delivery

Next: complete native drivers and evidence, expand lifecycle coverage to Lima, then
run fresh-consumer publication checks. Where an
exact-image assertion cannot be observed safely, keep the previous image and scope the
gap; a dormant runner in every image or an unsigned test disk would add attack surface.
