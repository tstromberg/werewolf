# syslogd

## Summary

syslogd collects `/dev/log` datagrams and `/dev/kmsg` records. It writes escaped
JSON to the console and/or `/data/log`, with gzip after one day and a 90-day
minimum retention age for stored records.

## Background

runit sends service stdout and stderr to the console. Application syslog uses
a UNIX socket; the kernel `syslog` syscall does not send application messages.

## Goals

- Collect local messages without retaining root or allowing network traffic.
- Bound memory, disk use, message size and work per sender.
- Preserve unexpired files under pressure and recover interrupted compression.

## Non-Goals

Remote input, stdout capture, selectors, hooks and authenticated audit storage.
A compromised receiver can submit false records to its writer.

## Detailed design

Init links `/dev/log` into root-owned `/run/syslog`. Setup locks the directory,
binds the socket and opens nonblocking console and read-only kernel descriptors.
Read `/run/config/syslog.conf`, else `/etc/werewolf/syslog.conf`, once.
Defaults: `console yes`, `file yes`, `max-mib 1024`.
The parser accepts each key once; `max-mib` ranges from 16 to 1048576.
RAM `/data` means console-only. Restart to change configuration.

The receiver becomes `_syslog` (75), chrooted to `/var/empty`, without
capabilities, under Landlock and a descriptor-specific seccomp filter. It
receives kernel PID/UID/GID credentials, closes and refuses passed descriptors,
and rejects truncated messages. Datagrams are at most 2048 bytes, with 100 per
UID per second and 256 sender slots. Escape controls, quotes, backslashes and
non-ASCII bytes. `source: syslog` and credentials belong to the receiver;
sender text cannot set metadata. Remap claimed kernel priorities to LOG_USER.

Read kernel records in bounded batches, without merging fragments. Facility
zero gets `source: kernel`; userspace-injected kmsg gets `source: kmsg`. Keep
sequence and monotonic time; count overwritten records and read errors. Never
echo kernel input to console or write to kmsg. Restarts replay the retained ring.

An inherited nonblocking socketpair feeds `_logfile` (76), chrooted to its
private `/data/log`, without capabilities. Landlock grants that directory
alone; seccomp permits its file operations but no exec or new sockets. Buffers
are allocated before confinement. Neither worker can open configuration again.
Leash waits for readiness and grants socket resolution; clients still declare
`unix connect` in their pledge. OCI roots receive the socket directory too.

Rotate `messages` at 4 MiB, after 24 hours, on restart or shutdown into
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
file output and retry each minute. The console has its own 64 KiB queue.
`/run/syslog/status` reports file/kernel health, loss counts and a boottime
heartbeat each second. `ready` means the receiver is serving, including degraded
mode. Counters restart with the daemon; external monitoring must detect stale
status and alert on losses. Console loss summaries are rate limited.

## Drawbacks

Unlimited ingestion needs unlimited storage. Retention trusts the clock and
durable `/data`. Non-ASCII escapes represent original bytes, not decoded UTF-8.

## Alternatives Considered

- zstd or external logrotate: gzip encoding is already available in Zig.
- Number-only names or birth time: closing time keeps record age across rotations.
- Evict oldest on pressure: violates the requested 90-day minimum.

## Security Considerations

Log directories are 0700, files 0600. Refuse symlinks, hardlinks, non-regular
files and unexpected names. Open files relative to the pinned directory;
messages never select paths. Locks exclude simultaneous daemon instances.
Pin and verify console/kmsg devices; seccomp permits only reads on the kmsg fd.

## Reliability Considerations

Sync new file and directory entries, then active writes each second. Shutdown
stops applications first and gives the logger five seconds to drain before
unmounting `/data`. Abrupt power loss can lose recent unsynced messages.
`make check-syslog` boots Linux to test confinement, origins, feedback, storage
pressure and shutdown. `make fuzz-syslog SYSLOG_FUZZ_RUNS=100000` runs four
coverage-guided targets for framing, kernel input, policy and gzip recovery.
