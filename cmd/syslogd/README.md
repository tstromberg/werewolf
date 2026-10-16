# syslogd

## Summary

syslogd receives local UNIX datagrams on `/dev/log`. It writes escaped JSON
records to the console, `/data/log`, or both, with gzip after one day and a
90-day minimum retention age for stored records.

## Background

runit sends service stdout and stderr to the console. Application syslog is
a separate UNIX socket protocol. The kernel `syslog` syscall and its pledge
do not deliver application messages to this daemon.

## Goals

- Collect local messages without retaining root or allowing network traffic.
- Bound memory, disk use, message size and work per sender.
- Preserve unexpired files under pressure and recover interrupted compression.

## Non-Goals

Remote input, kernel logs, stdout capture, selectors, hooks and authenticated
audit storage. A compromised receiver can submit false records to its writer.

## Detailed design

Init makes `/run/syslog` and links `/dev/log` to its `dev-log` socket. Root
setup locks the directory, binds the socket and opens a separate nonblocking
console descriptor. It reads `/run/config/syslog.conf`, else
`/etc/werewolf/syslog.conf`, once. Missing configuration uses these defaults:

```text
console yes
file yes
max-mib 1024
```

The parser accepts each key once; `max-mib` ranges from 16 to 1048576.
When `/data` is RAM or unavailable, the daemon reports console-only operation.
Configuration changes require a service restart.

The receiver becomes `_syslog` (75), chrooted to `/var/empty`, without
capabilities, under Landlock and a descriptor-specific seccomp filter. It
receives kernel PID/UID/GID credentials, closes and refuses passed descriptors,
and rejects truncated messages. Input is at most 2048 bytes, at most 100 messages
per UID per second, with 256 sender slots. Control and non-ASCII bytes become
JSON escapes. Priority and sender tags remain untrusted claims.

An inherited nonblocking socketpair feeds `_logfile` (76), chrooted to its
private `/data/log`, without capabilities. Landlock grants that directory
alone; seccomp permits its file operations but no exec or new sockets. Buffers
are allocated before confinement. Neither worker can open configuration again.
Leash waits for readiness and grants socket resolution; clients still declare
`unix connect` in their pledge. OCI roots receive the socket directory too.

`messages` is active. Rotate at 4 MiB, after 24 hours, on restart or shutdown:
`messages.2026-10-16T18:30:00Z.001`. The UTC RFC 3339 time is the closing time,
never a sender timestamp or inode birth time. Try suffixes 001 through 999
without replacing either a plain or compressed file. Backward clock changes
cannot give a file a closing time earlier than its last write.

Every minute, process closed files oldest first. Delete only those at least
90 days old. Gzip at most 16 eligible files per pass, after 24 hours; write
and sync `.gz.tmp`, publish `.gz` exclusively, sync the directory, then remove
the plain source and sync again. Recovery discards partial temporaries only
when their source remains, and verifies duplicate gzip content before unlink.

The budget includes stored bytes and 8 MiB reserved for compression scratch.
There are at most 8192 closed segments, plus bounded recovery files. Exhaustion
drops new file records without evicting younger archives. File errors suspend
file output and retry each minute while the console continues. The console
has a separate 64 KiB queue. Loss counters are cumulative and rate limited.

## Drawbacks

Unlimited ingestion needs unlimited storage. Local retention depends on a
trustworthy system clock and durable `/data`. Bytes above ASCII are escaped
individually; consumers must interpret them as the original encoded bytes.

## Alternatives Considered

- zstd or external logrotate: gzip encoding is already available in Zig.
- Number-only names or birth time: closing times survive compression and make
  age meaningful even when a file has received messages for a whole day.
- Evict oldest on pressure: violates the requested 90-day minimum.

## Security Considerations

Log directories are 0700, files 0600. Refuse symlinks, hardlinks, non-regular
files and unexpected names. Open files relative to the pinned directory;
messages never select paths. Locks exclude simultaneous daemon instances.

## Reliability Considerations

Sync active writes each second. Shutdown stops applications first, then gives
the logger five seconds to drain and sync before unmounting `/data`. Abrupt
power loss can lose recent unsynced messages. Unit tests cover naming, age,
quotas, escaping and compression recovery; `make check-syslog` boots Linux to
verify the real daemon, confinement, credentials, retention and shutdown.
