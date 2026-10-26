# syslogd(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

syslogd — collect local syslog and kernel messages as JSON

## SYNOPSIS

**syslogd**

## DESCRIPTION

The Werewolf **syslogd** daemon receives local syslog datagrams and kernel records. It
writes escaped JSON to the console and, when persistent storage is available, to
/data/log. It accepts no remote input and does not capture service standard output.

Configuration is read once at startup from the boot configuration, falling back to the
image configuration. The keys and defaults are:

- **console yes|no**

  Enable console output; default yes.

- **file yes|no**

  Enable persistent file output; default yes. Temporary /data storage always selects
  console-only operation.

- **max-mib** *number*

  Storage budget in MiB, from 16 through 1048576; default 1024.

Repeated keys are refused. Restart the service to change configuration. The
unprivileged _syslog receiver obtains sender credentials from the kernel; message text
cannot supply them. A separate _logfile worker can write only its private log
directory. Neither worker can execute programs or open network sockets.

Datagrams are limited to 2048 bytes and 1000 per process per second. Kernel records
retain sequence and monotonic time and are not echoed to the console. Sender controls
and non-ASCII bytes are escaped.

Files rotate at 4 MiB, after 24 hours, and on restart or shutdown. Closed files are
compressed after a day and retained for at least 90 days. The budget includes
compression scratch. Exhaustion drops new file records rather than evicting younger
archives. File errors suspend that output and retry each minute.

## FILES

- `/dev/log`

  Local syslog socket, linked into /run/syslog.

- `/dev/kmsg`

  Kernel log input.

- `/run/config/syslog.conf`

  Machine configuration, preferred when present.

- `/etc/werewolf/syslog.conf`

  Image configuration.

- `/data/log/messages`

  Active log; timestamped siblings hold closed segments.

- `/run/syslog/status`

  Health, loss counters and a boottime heartbeat, updated each second.

## SEE ALSO

leash(8), runit-stage(8), unwound(8)

## CAVEATS

Delivery is best effort. Counters reset on restart; monitoring must detect stale
status and losses. Retention depends on the clock and durable storage. Power loss can
lose recent unsynced messages. The log is not authenticated audit storage.
