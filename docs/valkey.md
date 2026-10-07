# Valkey

The `valkey` form is `prod` with Valkey 9.1, a cache or queue for the
application on the same machine, as `postgresql` is its database.

| | |
| --- | --- |
| Listens | a UNIX socket, `/run/svc/valkey/valkey.sock`, mode 660 for the `valkey` group, and nothing else: `port 0`, and the form declares none |
| Sends | nothing |
| Runs as | `valkey` (uid 210), leashed: it reads the image and writes only its own directories |
| Keeps | RDB snapshots in `/data/svc/valkey`; the append-only log is a line away (`appendonly yes`) |
| Limits | `maxmemory 192mb` under the leash's 256 MiB, `noeviction`: a full store refuses writes rather than being killed for them. A cache sets `maxmemory-policy allkeys-lru` |

The application's form includes `valkey` and puts its user in the `valkey`
group (gid 210) to reach the socket; `valkey-cli -s
/run/svc/valkey/valkey.sock` is the operator's client, in the image.

## Defaults

- **The default user may do all but administer the server:** `+@all
  -@admin`. No `CONFIG`, `DEBUG`, `MODULE`, `REPLICAOF`, `SHUTDOWN`,
  `MONITOR` or ACL changes, so the old attack, `CONFIG SET dir` to a key
  directory and then `SAVE`, fails at its first word, and would find
  Landlock holding the process to `/data/svc/valkey`, and no sshd. Lua
  stays: Sidekiq and BullMQ are built on it, and a sandbox escape lands in
  a leashed process that can start nothing.
- `enable-module-command no`, `enable-debug-command no`,
  `enable-protected-configs no`, as they ship, and said so in the file.
- A form that serves the network adds `port 6379`, `listen tcp/6379` to
  its service file and `.net`, and then a password is required: an ACL
  file from the config. TLS when the config brings a certificate.

## A shell in the image

Wolfi's `valkey-9.1` depends on `posix-libc-utils`, whose `ldd` is a bash
script, so this image carries bash and posture's `programs-no-shell` fails
on it by that dependency alone ([test/posture-known](../test/posture-known)).
Nothing runs it: Valkey is leashed to its own program, and there is no
login. It goes when Wolfi drops the dependency, and the check will say so.

## Checked

`make check-valkey` runs [test/checks-valkey](../test/checks-valkey): the
socket answers `PING`, is `valkey:valkey` 660 and refuses `nobody`; a key
is set, read and a Lua script runs; every `@admin` command above is
`NOPERM`, `SHUTDOWN` among them, and the server is still there; nothing
listens on `:6379`; and `BGSAVE` lands in `/data/svc/valkey`.
