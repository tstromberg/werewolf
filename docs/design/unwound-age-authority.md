# Authority for domain-age evidence

Status: implemented with a protected mount view and checked in native
fixtures and booted images. See the [domain-age design](unwound-age.md).

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

Decided 2026-10-23: attribution stops at the kernel-bound socket UID and
policy namespace. A socket can be inherited or passed to another process;
its service identity does not identify the current sender. Do not infer a
PID by racing `/proc` or trusting a self-reported name. The image keeps BPF
and tracing disabled and adds no kernel extension for process attribution.

The schema retains nullable PID, process start time, executable and network
namespace inode fields for compatibility. The writer always records
`provenance=uid_only` and leaves all four fields NULL. Integration tests pass
UDP and TCP sockets to another UID after their creator exits, then check
the exact DNS request, original socket UID, source label and policy namespace
in SQL. Storage tests refuse invented process fields and later changes to
the recorded identity.

## SQLite authority

The writer runs as a dedicated non-root account, owns a 0700 directory and
uses Landlock to limit its writes to that directory. The DNS frontend has no
database descriptor. The authority also performs the HTTPS check, so it is
the one process trusted to handle both network evidence and SQLite.
SQLite's WAL, shared-memory and main files all need the same protection.

`tools/checkout-unwound-sqlite.zig` verifies the official SQLite 3.54.1 source
archive by SHA3-256 before extracting its amalgamation into `out/`. The age
writer links it statically. `cmd/unwound/age_db.zig` opens the schema with
foreign keys, trusted schema disabled and WAL requested. It records a check's
first request, then atomically stores the provider result and cache row. A
late response cannot replace newer evidence. Reads recompute the age verdict
from dated evidence. Its host test uses the pinned SQLite code; run
`make check-unwound-age-store`. The observe-only child logs `age_observe` with
DNS ID, QNAME, qtype, transport, source label, UID and policy generation.
A full channel increments `age_lost`; assigned system domains and explicit
grants bypass it.

The separate authority splits its work so no process holds more than it
needs. The supervisor never opens the database. It restarts the writer, and
for each check the writer asks for it forks a fetch child, kills it after 10
seconds whatever it is doing, and relays its fixed 26-byte record. The writer
holds SQLite and unwound's channel; Landlock leaves it no TCP connect, and its
seccomp filter no socket, fork or signal. A fetch child keeps one pipe, reads
only `/etc` and the resolver state, connects only to TCP 53 and 443, and its
filter allows DNS, HTTPS and that pipe. A crashed or stalled fetch is recorded
as an RDAP outage and refused; unwound keeps running. At most four checks run
at once, one per service, taking each service's oldest question in turn, and
questions for a domain already being checked wait on that check.

The frontend independently derives the PSL boundary and refuses a mature
reply naming another registered domain. An immutable image marker,
`/usr/share/werewolf/age-enforce`, selects the DNS wait path. The native
`check-unwound-age` fixture exercises cached maturity, young and unknown
refusal, and the assigned-domain bypass. The authority fixture also checks a
live RDAP lookup, its audit row and read-only root view.

`test/check-unwound-age-mount.zig` demonstrates one workable mount boundary:
start the writer in a private mount namespace before a read-only bind covers
its directory in the main namespace. SQLite can create its database, WAL and
shared-memory files through the writer's normal path, while root in the main
namespace gets `EROFS` for those paths and cannot replace the listener socket.
It also checks that root without `CAP_SYS_ADMIN` cannot remount that view.
With `CAP_SYS_PTRACE` removed from
root's bounding set, the fixture also denies paths through the writer's
`/proc/PID/root` and `/proc/PID/fd`; init already drops that capability.
With it retained, root reached the writable namespace through `/proc/PID/root`.
A retained directory descriptor alone did not work with SQLite's file opening
and WAL behavior in the Linux lab.

Landlock restricts a task and its descendants; it cannot impose a new rule
on another root task. Fence currently permits writes under `/data`, and a
sufficiently privileged root process can bypass ordinary file ownership.
Init starts the protected writer before the seal, because the seal refuses
new mount namespaces. It gets a private writable mount view; init then binds
the age directory read-only in the main view before runit starts services.
Its listening socket is also on an immutable path in the main view so
root cannot replace the age authority on an unwound restart. The writer and
its supervisor must be non-dumpable and have no surviving mount capability.

The native mount fixture proves that root without `CAP_SYS_ADMIN` cannot
replace the database, WAL or socket through its normal filesystem view. The
shared native image check also tries root writes and remounts on boot and
reboot, and refuses extra mounts exposing the age directory. Init protects
the age mount before constructing OCI roots; image composition reserves its
service name. `make check-adhoc` boots an OCI nginx service, confirms its data
bind exists, and tries to bind and write the age cache as root. The cache is
not protected against tampering before this boot;
unknown or expired evidence never gives a mature verdict.
