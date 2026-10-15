# Testing and publishing the images users run

Proposed, 2026-10-15. This describes remaining work, not deployed behavior.

## Scope

Use one host test command and native boot-time drivers for public and private services, plus an unmodified release-image run. Publish passing form/architecture/provider/profile targets independently through one workflow, with signed evidence and package/PR history.

The change is mainly in the host harness, evidence validator and release pipeline. Estimate **3–6 engineer-weeks for the four core forms on both architectures**, contingent on resolving the lifecycle gaps below. Converting all existing shell suites to native drivers and implementing export are additional work; this is a planning estimate.

## Current state

[`howl test`](../../cmd/howl/test.zig) runs DEV integration tests and a separate production boot. The working-tree [`form-images`](../../release/form-images) pipeline adds independent-build comparison, actual signed qcow2 boot, inventories, package notes and an R2 catalog. Its `uefi-ipe/1` profile lacks protected TPM enrollment; these local additions are not evidence of deployment.

The [protected workflow](../../.github/workflows/protected-images.yml) builds playground, prod and prod-ssh for x86_64 QEMU but publishes only playground through an [SSH-dependent lifecycle test](../../test/check-published-lifecycle). Legacy release.yml is another publisher; form-images.yml would add a third. Protected GitHub notes lack package and PR history.

Success means tested minimal, prod, prod-ssh and playground downloads on aarch64/x86_64, then all other supported form targets. Unsupported architectures and failed attempts stay visible. Each successful head identifies its image, evidence and predecessor; failures retain the previous passing image.

## Coverage contract

`howl test --with FORM` owns the whole run: prepare ordinary fixtures, build the candidate and a test variant from the same pinned inputs, boot both, collect results and return one exit status. Private services use local native clients; public services use the same driver contract plus host probes where external reachability matters. Export is optional, not the test transport.

| Run | Subject | Purpose |
| --- | --- | --- |
| Unit/component | Existing tests and disposable fault fixtures | Parsers, confinement and updater/TPM state machines |
| Native integration | Production payload plus explicit compiled test drivers | Live SQL, peer authentication, permissions, service behavior and persistence |
| Release acceptance | Unmodified signed candidate | Actual artifact boot, externally observable behavior and required lifecycle guarantees |

The integration variant adds only declared test executables, their minimal dependencies and launch metadata. It does not enable DEV or introduce a universal busybox, shell, compiler or SSH server. Compile production programs once and reuse identical bytes in both variants; verify the filesystem/package/policy delta against an explicit allowlist. Added tests change root hashes, PCRs and runtime load, so their results must identify the test variant and cannot claim byte-identical release coverage.

Native drivers are small target-architecture Zig executables sharing a result protocol. Prefer existing service clients such as psql, invoked directly with argument arrays; use protocol libraries only where useful. Declare and pin each suite's client dependencies without enabling DEV, adding a shell or replacing production libraries. Existing Zig unit tests are not automatically integration tests. Keep suites alongside forms and compose them with explicit overrides for changed inherited behavior; each driver retains its own permissions.

Build drivers into the test variant's verified root and sign it with isolated test authority while keeping Secure Boot, IPE, verity and normal enforcement active. Refuse drivers that require relaxing the machine-wide seal or an existing service's confinement; split such experiments into explicitly scoped component fixtures. Publication must reject test variants by manifest identity as well as inspecting the allowed payload delta.

Keep the current [fourteen protected gates](../../release/prepare-protected) enforced while migrating. Any change assigning a formerly exact-image assertion to shared fixture coverage needs an explicit policy review and validator tests. This design does not authorize dropping a gate to make more forms publish.

## Triggering tests and collecting results

The host launches each variant with normal configuration and a fresh run ID. A fixed boot-time launcher starts only the compiled suite plan after the normal seal/fence setup; drivers await service readiness with deadlines. No console command interpreter, arbitrary executable path or downloaded test code is accepted. Drivers finish once; host failure/retry policy cannot hide a failed assertion.

| Scenario | Driver action | Evidence |
| --- | --- | --- |
| Private service | Connect locally under declared allowed/denied identities | Named assertions and driver termination |
| Public service | Use its normal protocol; host separately probes exposed ports | Authenticated responses and expected application state |
| Reboot/update persistence | Write in one phase; read after host-orchestrated transition | Phase-bound assertions, boot identity and preserved values |
| Protected lifecycle | Host controls signed channel, VM and TPM fault points | Measured identity, updater/keeper outcomes and recovery |

Use existing confinement machinery for each driver's own declaration. A PostgreSQL client can run as postgres; a separate client tests rejection as an unauthorized user. Production service identities, exec rules, capabilities and resource limits stay unchanged. Root-only security probes require separate narrowly declared drivers; no universal root runner receives all sockets, keys and broker handles. One-shot tests must not join the production service-health set or become a prerequisite for slot commitment.

Each driver emits bounded structured records containing run ID, suite, phase, case and result, ending with a completion record. The launcher reports abnormal exits; the host requires the expected case set, rejects missing/duplicate results and treats panic, timeout or missing completion as failure. Results are diagnostic evidence, not attestation: other guest processes can write console text. Correlate fresh console offsets with boot/TPM observations; use a dedicated result channel only if stronger writer isolation proves necessary.

The host retains QEMU/Lima lifecycle control, signed-channel changes, power cuts and TPM observation; a guest driver cannot verify its own platform fully. Reuse the Python orchestration and current monitor/TPM proxy. For multi-boot tests, an explicit phase in ordinary test configuration selects a fixed compiled phase; it grants no new operation. The host expects that phase and checks existing data before creating any new fixture state.

Reports bind descriptor/disk hashes, target identity, inputs, harness/policy revision, firmware/tools, configuration hashes and run identity. Each assertion records expected/observed results, status and hashed logs; transitions name every participating release. Required assertions fail on missing results or timeout. Preserve bounded diagnostics, redact secrets and clean up only owned resources.

## Preserve production behavior

Boot a verified writable copy of the candidate; ordinary enrollment and runtime writes are expected. Do not inject DEV packages, SSH, a test agent, extra privileges or altered confinement/health deadlines into exact-image runs. Fault-mutated copies have separate identities and evidence. Never install slots by hand to simulate an updater pass.

Vendor keys stay in authorized signing jobs. Owner and test TLS credentials are separate. Preserve private candidate authorization until admission passes. Deliberately unhealthy code fixtures use disposable authority and cannot publish. Observe storage only while stopped or through a consistent snapshot; never repair the original as part of inspection.

## PostgreSQL example

Today, [DEV checks](../../forms/postgresql/test/checks) exercise SQL, UTF-8/C locale, transaction rollback, peer rejection, sh-shim and absent TCP listeners. The [production console test](../../forms/postgresql/test/console) checks cluster creation/readiness. The stock form intentionally has no TCP listener and its client package is DEV-only.

1. Add pinned `postgresql-17-client` only to the test variant. The Zig driver invokes `/usr/bin/psql` directly as postgres against the existing Unix socket, checking locale, UTF-8 writes and transaction rollback. A separately confined unauthorized identity must fail peer login. Declare psql execution in the driver's policy; leave PostgreSQL's policy, socket permissions and TCP exposure unchanged.
2. In the first phase, write a unique row through the live server and report success. The host restarts the same machine/data disk; the next boot's driver reads the expected row before any setup writes. Repeat across the test-variant P → C update, preserving data and testing actual client sessions.
3. Retain native sh-shim and listener checks, with explicit privileges where needed. A failed client or absent result fails the suite; server-ready text cannot substitute for successful SQL.
4. Separately boot and update the unmodified release candidate with normal import/configuration. Require measured identity, readiness, commitment and absence of public SQL exposure. Attribute live private-SQL results to the matching test variant, not to this uninstrumented boot.

This needs no export or general-purpose guest shell. [Export](data-export.md) remains useful for recovery and independent data inspection. Port existing shell cases incrementally, retaining their coverage until native equivalents pass; PostgreSQL major-version migrations remain separate tests.

Invoke [psql](https://www.postgresql.org/docs/17/app-psql.html) with `-X -w -A -t -v ON_ERROR_STOP=1 -P pager=off -h /run/svc/postgres -U postgres -d postgres`, supplying fixed SQL through `-c` arguments or stdin. Use a controlled environment, bounded captured output and a deadline; inspect exit status and expected values before emitting case results. Avoid shell escapes, backticks and program pipes. The shared runner remains Zig; the database client remains psql.

## Greenbone example

Today, [DEV tests](../../forms/greenbone/test/checks) inspect credentials, capabilities, sockets/cache permissions and the login page. `greenbone-published` accepts HTTP 200, 401 or 403 for `admin/admin`, which does not establish authentication behavior. The [production console test](../../forms/greenbone/test/console) checks refusal when password/domain configuration is missing.

1. Port missing-config and internal isolation checks to native drivers with explicit identities and permissions. Separately boot the same candidate with ordinary domain/password configuration and an isolated data disk; do not expose GMP, PostgreSQL, Valkey or scanner control ports.
2. Use a native protocol driver or host browser through Caddy HTTPS, under the same case/result contract. Require configured-password login and access to an authenticated resource; wrong/default passwords must not obtain that access. Verify TLS using a normal trusted domain or a separately established fixture CA; do not count disabled verification as success.
3. Create and read back a uniquely named target/task through the UI. Restart, log in and read it again; repeat after P → C. This tests Caddy → gsad → gvmd → PostgreSQL, including live database persistence, without export.
4. Run a task from the configured test variant against an isolated host-controlled service with a known compatible feed. Require completion and an expected harmless service observation. Restrict the host test network to fixture targets and required infrastructure; an empty report or listed scanner is insufficient.
5. While the UI works, verify private ports 5432/6379/9391/9392 remain externally inaccessible. Retain local socket/UID/capability tests: external probes cannot prove their internal properties.

The mutable community feed is separate from pinned OCI image inputs. Deterministic scans need a versioned cache prepared through normal synchronization and restored through supported owner operations; export may help implement that later. Record feed identity, test cached operation during a host-induced feed outage, and separately test live refresh. Until repeatable setup exists, scan coverage remains incomplete; boot-time drivers alone do not solve feed reproducibility. Feed failure is not automatically an unhealthy-service/rollback test. Plan for 8 GiB RAM and several GiB of cache.

## Remaining lifecycle gaps

**Shell-free control:** use autonomous checks and supported update policy with an authenticated mirror. Minimal needs explicit networking. The root-only guest update socket is not a host interface; do not bridge it just for tests. Preserve trust, channel identity and normal timers.

**Rollback and health:** playground can use existing SSH; prod-ssh retains hardware-key authentication. Minimal/prod need a supported owner rollback operation. Host boot selection is a different assertion. Power loss before commit proves interrupted-trial recovery, not failed-health recovery; use a real dependency fault only if it demonstrably prevents commitment. Otherwise that gate remains blocked.

**Distinct releases:** test P → C and a legitimate successor where needed to exercise C's updater/retirement. Renaming serials is insufficient. Pin all fixture inputs, provide a bootstrap fixture for first releases, and never promote fixture-only successors. Owner-isolation runs retain separate machine secrets and TPM state; power-cut runs preserve actual persistent TPM state.

## CLI and publication

Keep `howl forms`, `howl forms FORM` and `howl test --with FORM`; the latter orchestrates both native integration and release acceptance. A build-only test mode may be internal; `--dev` stays for interactive debugging. Proposed `howl test --image BUNDLE` tests an existing artifact without injecting code; deeper private-interface checks require its separately built, provenance-matched test variant. Discovery links guides, profiles, evidence and latest passing/failed attempts. No image-mutation test flag is required.

Make release.yml the sole image orchestrator and GitHub writer; APK publication stays separate. Resolve pinned inputs, build twice independently, then gate each target. Change detection includes trust, tools and test-policy revision, so strengthened requirements invalidate old receipts. Only supported, passing targets advance; provider/architecture evidence is never interchangeable.

Publish immutable R2 objects before signed heads and catalog snapshots; verify public bytes, preserve serial floors and reject collisions. Keep GitHub drafts private until parity succeeds. R2/GitHub are not one transaction: persist a receipt and retry the same snapshot/notes idempotently after partial publication. Identical published artifacts create no duplicate release.

GitHub attaches passing core-form artifacts and links the full catalog, labeling updated, unchanged, failed-with-previous-retained and unavailable targets. Retained images keep original provenance. Default protected downloads never fall back to `uefi-ipe/1` or legacy trust.

Notes compare each image with its previous passing inventory: package additions/removals/version or same-version content changes, OCI digests, and separate build/test inputs. Group identical source ranges; list associated merged PRs and direct commits with comparison links and accurate attribution. Handle pagination, first-release baselines and divergent history explicitly. Missing history holds publication rather than claiming nothing changed.

## Staged delivery

| Step | Completion criterion | Estimate |
| --- | --- | --- |
| Inventory | Map every gate/interface; prototype shell-free boot/update; identify blockers and runner costs | 2–4 days |
| Harness/evidence | Native driver contract and launcher; preserve playground coverage; reject mismatched/incomplete evidence | 4–7 days |
| Core targets | Four forms, both architectures, all required lifecycle assertions pass | 4–8 days, contingent on inventory |
| Publication/notes | One writer; package/PR history; partial-failure and retry tests | 3–5 days |
| Cutover | Shadow-run comparison, fresh-consumer fetch/run/update, retire old automatic writers | 2–4 days |

Start with native Linux QEMU; qualify Lima separately. Expand service coverage by the assertion checklist. Export is a separate proposal, not a hidden prerequisite for all host tests. If required exact-image assertions cannot be observed safely, retain previous images and scope the missing capability explicitly.

Boot-time native drivers provide local clients without a universal shell. They necessarily instrument the image, so retain unmodified acceptance and verify the exact allowed delta. A dormant runner shipped in every production image would add permanent attack surface; an unsigned executable test disk would bypass verified execution. Neither is required for one consistent test command.
