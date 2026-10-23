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

Landlock restricts a task and its descendants; it cannot impose a new rule
on another root task. Fence currently permits writes under `/data`, and a
sufficiently privileged root process can bypass ordinary file ownership.
This design does **not** claim a root-proof SQLite cache. Before enforcement,
native tests must demonstrate that root login and every service cannot
replace the database or its WAL files, or the worker needs a separate
read-only mount view or stronger trusted storage. An integrity or generation
failure makes age unknown, never mature.
