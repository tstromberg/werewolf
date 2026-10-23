# Authority for domain-age evidence

Status: planned. Age decisions remain offline; see the
[domain-age design](unwound-age.md).

## Request provenance

Each external check stores its first triggering QNAME, qtype, DNS ID,
UDP/TCP transport, source label, service UID, compiled policy namespace and
generation, local request ID, timestamps, cause and provider outcomes. The
policy namespace comes from the kernel-constrained source label and compiled
UID map, not a process-supplied field. A scheduled refresh has no triggering
DNS request. Coalesced requests retain their normal DNS audit records.
The request fields in `age_check` are immutable after insertion. A cached
domain may pin only a check for that same registered domain; completion and
provider-result fields may be updated when the external check finishes.

The schema has nullable PID, process start time, executable and network
namespace inode fields. `provenance=uid_only` requires them to be NULL. A
DNS socket does not identify the individual process that sent a datagram,
and this image has no BPF syscall or tracing support. Do not infer a PID by
racing `/proc` or trusting a self-reported name. Exact process attribution
requires a separate kernel-backed provenance path, tested with fork/exec and
socket handoff, before those fields may be filled.

## SQLite authority

The writer runs as a dedicated non-root account, owns a 0700 directory and
uses Landlock to limit its writes to that directory. The frontend and fetcher
have no database descriptor. This isolates a compromised DNS or RDAP process.
SQLite's WAL, shared-memory and main files all need the same protection.

`tools/checkout-unwound-sqlite` verifies the official SQLite 3.54.1 source
archive by SHA3-256 before extracting its amalgamation into `out/`. The age
writer will link it statically. `cmd/unwound/age_db.zig` opens the schema with
foreign keys, trusted schema disabled and WAL requested. Its host test uses
the pinned SQLite code; run `make check-unwound-age-store`. The writer process,
transactions and IPC are still to be built.

`test/check-unwound-age-mount` demonstrates one workable mount boundary:
start the writer in a private mount namespace before a read-only bind covers
its directory in the main namespace. SQLite can create its database, WAL and
shared-memory files through the writer's normal path, while root in the main
namespace gets `EROFS` for those paths. With `CAP_SYS_PTRACE` removed from
root's bounding set, the fixture also denies paths through the writer's
`/proc/PID/root` and `/proc/PID/fd`; init already drops that capability.
With it retained, root reached the writable namespace through `/proc/PID/root`.
A retained directory descriptor alone did not work with SQLite's file opening
and WAL behavior in the Linux lab.

Landlock restricts a task and its descendants; it cannot impose a new rule
on another root task. Fence currently permits writes under `/data`, and a
sufficiently privileged root process can bypass ordinary file ownership.
This design does **not** claim a root-proof SQLite cache. Before enforcement,
native tests must demonstrate that root login and every service cannot
replace the database or its WAL files, or the worker needs a separate
read-only mount view or stronger trusted storage. The namespace boundary still
needs native boot checks for the capability drop, mount broker calls, and
forms that retain `CAP_SYS_ADMIN`. An integrity or
generation failure makes age unknown, never mature.
