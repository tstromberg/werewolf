# Host test library

## Summary
Zig that host-side tests share, built as module `host`
(`-Mhost=test/host/host.zig`). It runs on the build host, never on a machine.

## Background
Checks boot machines, serve them update channels and mirrors, and attack them.
They need HTTPS servers with a private authority, which Zig's standard library
lacks: it has a TLS client and no server.

## Goals

- Serve HTTP/1.1 and HTTPS from a test with no interpreter or OpenSSL CLI.
- Mint the authority and server certificates a test's clients trust.
- Record what a client asked, in order, for checks on request order.

## Non-Goals

- A general TLS implementation, or anything a machine or howl links.
- TLS 1.2, resumption, HelloRetryRequest or client certificates.

## Detailed design

| Module | Responsibility |
| --- | --- |
| `tls.zig` | `Authority` mints ECDSA P-256 certificates; `Connection` serves TLS 1.3. |
| `http.zig` | `Server` serves a `Handler` per connection; `Files` serves a directory. |
| `qmp.zig` | `command` runs a QEMU monitor operation; `StorageFault` fails a disk's writes. |
| `netns.zig` | `Lab` enters namespaces, wires a veth peer, mounts, and spawns fixtures. |
| `dnswire.zig` | `query`, `parse` and `Message` write and read DNS messages, allocating nothing. |
| `sqlite.zig` | `Db` runs SQL through the vendored SQLite; its users link it and libc. |
| `check.zig` | `Check` is one check's run: logs, environment, `run`, `must`, `fail`. |
| `qemu.zig` | `Machine` runs QEMU, its console piped to a log, with deadlines; `clean`. |
| `swtpm.zig` | `Proxy` cuts a TPM floor increment; `interpose` points QEMU's TPM at it. |
| `evidence.zig` | Judges boot evidence against `evidence.yaml`: credentials, posture, UKI. |
| `provider.zig` | `Provider` runs an A/B fixture on QEMU, Lima, a cloud, bhyve or Proxmox. |
| `consumer.zig` | A source-free howl user: refused builds, one SSH key, a mirror's roots. |
| `pem.zig` | Writes an identity's chain and EC key, and reads a bundle's certificates. |

`tls.Connection` speaks TLS_AES_128_GCM_SHA256 with x25519 and
ecdsa_secp256r1_sha256, which curl, OpenSSL, libcurl and Zig's client all offer.
It refuses other ClientHellos with an alert, and agrees ALPN `http/1.1` when
offered. `Authority.init` makes a CA valid from an hour ago for two days;
`issue` certifies DNS names or IP literals; `pem` writes the CA for clients.

`http.Server.start` listens (127.0.0.1, any port, by default) and serves each
connection concurrently through `Io`. `stop` cancels them all. A handler gets
the request and a `Response`: `send` adds `Content-Length` unless the headers
name one, so a test can promise more than it sends and set `close`. `Files`
serves GET and HEAD under its root, refuses `..`, and keeps every path asked.

`qemu.Machine` reads QEMU's output as it comes, so a guest never stalls on a
full pipe, and `until` waits for a console predicate or a deadline. `stop`
asks, then kills. `clean` drops kernel records, `[` seconds `]` to the end of
their line, wherever they start, so a userspace record they split joins again.
`swtpm.Proxy` passes QEMU's control channel to swtpm and keeps the data channel
QEMU hands over, holding an armed `NV_Increment` before or after the TPM runs
it; a check run as `qemu-system-ARCH` through `PATH` calls `interpose` first.
`evidence.yaml` is the table people edit: the updater's credentials and the
posture checks protected boots must pass. host does not import lib/form.zig, so
a check passes it to `evidence.load`. `provider.Provider` takes a `Runner`, which
the tests replace to check its commands and its cleanup of what it alone made.

A Linux check is a static program run as root, which `netns.Lab.enter` starts
again under `unshare`; it plays its own fixtures and the client fence confines.
`Lab.spawn` forks by hand: a child gets descriptors 3 and up, or a uid with no
groups, as the programs under test expect. A forked child that must not run
`Io` (it may have been copied mid-operation) uses the raw socket helpers,
`dnswire` and fixed memory alone. `sqlite.Db` seeds and reads unwound's age
store through the amalgamation the age writer links.

Run `make _test/test/host/host.zig` for the unit tests, which drive the server
with Zig's own TLS client, QEMU's monitor and the TPM proxy over socket pairs.
