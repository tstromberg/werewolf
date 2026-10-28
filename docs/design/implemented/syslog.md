# Local syslog and retention

**Status:** Implemented
[2026-10-16](https://github.com/werewolf-linux/werewolf/commit/936b2fb0)

## Summary
Collect `/dev/log` and kernel messages, with console and file outputs.
Keep timestamped files for at least 90 days and gzip files older than one day.

## Background
Service stdout and stderr inherit runit's console. The `syslog` pledge permits
kernel-log reads; application syslog uses a UNIX socket instead.

## Goals
- Receive local datagrams without root, network listeners or helper programs.
- Select console, file, or both outputs; keep each output independent.
- Rotate automatically by size or elapsed time; compress after 24 hours.
- Never delete a file younger than 90 days to admit new messages.
- Bound memory, file count and disk use, and report dropped messages.

## Non-Goals

Remote logging, stdout capture, hooks, selectors and authenticated audit storage.
Delivery, including DNS decision logging, is best effort without acknowledgements.

## Detailed design

`syslogd` is a supervised Zig program. Init creates the root-owned socket
directory and `/dev/log` link. The daemon binds before dropping privileges.
Leash grants socket resolution on that directory without granting file writes;
clients still need their declared UNIX socket promises.

The receiver runs as `_syslog`, chrooted to `/var/empty`, with no capabilities.
It receives credentials with `SO_PASSCRED`, rejects truncated datagrams and
closes any received descriptors. Each bounded record has receive time, kernel
UID/GID/PID, priority and escaped message text. Sender tags are untrusted text.
Allow 1,000 messages per kernel PID per monotonic second, with no UID quota.
Track 1,024 PIDs; reuse idle slots after 60 seconds once pending drops are reported.
Forked processes have separate allowances. The console is nonblocking.
Escape controls, quotes, backslashes and non-ASCII bytes inside message text.
Datagrams always get `source: syslog`; remap claimed LOG_KERN to LOG_USER.
Receiver-generated `flood` notices name UID/PID and suppressed counts. Emit an
initial notice, then at most one summary per PID per minute, even after it stops.
These bypass sender limits, with four notices/second globally and round-robin
reporting. A full sender table refuses new PIDs and reports aggregate overflow.

Open `/dev/kmsg` read-only before dropping privileges. Facility zero gets
`source: kernel`; userspace-injected records get `source: kmsg`. Keep sequence
and monotonic time, count gaps, and never merge fragments. Kernel input never
returns to console or kmsg, preventing feedback. The descriptor filter permits
only kmsg reads. Restarts replay the retained kernel ring.

A second process, `_logfile`, owns only `/data/log` and is chrooted there.
It receives bounded records through an inherited socketpair. Its seccomp
allowlist permits local file operations, but no execution or socket creation.
The receiver cannot read, alter or delete archives. Neither process retains
root. A full writer queue drops new file records without blocking the console.

`messages` is the active plain file. Rotate at 4 MiB, after 24 hours, or on
restart/shutdown into `messages.2026-10-16T18:30:00Z.001`. The UTC RFC 3339 time
is the closing time; suffixes 001 through 999 avoid collisions without replacing
plain or compressed files. Retention uses this closing time, so every record
gets its full interval regardless of size rotation or compression's inode age.

Closed files remain plain for at least 24 hours after closing. Then
[Zig's existing gzip compressor](../../../lib/package.zig) writes a temporary file.
Sync it, publish `.gz` exclusively, sync the directory, then remove the source.
An interrupted compression leaves its source; duplicate archives are verified;
recovery never replaces a source with an incomplete archive. Gzip needs no
external process, library or dictionary. Compression is bounded by segment size.

Delete only closed files whose closing time is at least 90 days old, whether
plain or compressed. Backward clock changes postpone expiry. Retention depends
on a trustworthy receive clock; message timestamps never drive deletion.

Default storage budget: 1 GiB, including active files, archives and compression
scratch space; reserve room for one compression before admitting new records. Bound
closed segments to 8192, allowing recovery scratch. Never assume data compresses. If
the budget, file limit or filesystem fills, preserve unexpired files and drop new
file records, reporting counts through the console. A strict minimum age for stored
records cannot also promise lossless ingestion at an unlimited rate.

Use console-only mode when persistent `/data` is unavailable. Do not quietly
claim 90-day retention on a RAM filesystem. Console/file selection and the byte
budget come from a small root-owned configuration read once at startup.
Expose current storage/kernel health, loss counters and a boottime heartbeat in
the root-owned `/run/syslog/status`, updated each second. Readiness means the
receiver is serving, including degraded operation. Counters reset on restart;
external monitoring must detect stale status, drops and unavailable storage.

## Drawbacks

Compression takes CPU and temporary space. Stored logs can contain secrets.

## Alternatives Considered

- zstd: already used for images, but gzip encoding is already in the Zig tree.
- External logrotate and gzip: require execution, scheduling and broader paths.
- Keep 90 rotated files: wrong when rotation also happens by size or restart.
- Delete oldest on pressure: violates the requested minimum retention age.
- Compress the active file: complicates tailing and recovery after a power cut.

## Security Considerations

Directories are private; files are 0600. Open relative to a pinned directory,
refuse symlinks, hardlinks and non-regular files, and create archives exclusively.
No message selects a path. Only the writer can mutate logs. A compromised
receiver can submit false records; this is not a signed audit system.

## Reliability Considerations

Tests cover hostile messages, credentials, truncation, overflow, rotation at
size and time boundaries, exact compression/expiry ages, restart numbering,
compression interruption, disk pressure, link attacks and confinement.
Four coverage-guided fuzz targets exercise framing, kernel parsing, policy and
gzip recovery validation; their seed corpora also run with the unit tests.
Shutdown stops application services first, then drains and syncs the logger
within a deadline before unmounting `/data`. Recent unsynced writes can be lost
on abrupt power failure; sync new file/directory entries before accepting data.
Gzip CRCs detect corruption, not malicious changes.
