# Valkey - Hardened VM

A cache or queue for the other services on this machine: [Valkey](https://valkey.io)
9.1, on a UNIX socket. The form's manifest is [form.yaml](form.yaml). The same server
on a reachable port is [valkey-tcp](../valkey-tcp/README.md).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/valkey/index.html).

## Security Posture

The server runs as its own user. There is no shell. Landlock and seccomp hold it to
its socket and to `/data/svc/valkey`. The root is read-only.

- No TCP. The socket is mode 660 for the `valkey` group. A client's service joins
  that group.
- The default user may do everything except administer the server. `CONFIG`, `DEBUG`,
  `MODULE`, `REPLICAOF`, `SHUTDOWN`, `MONITOR` and ACL changes are refused.
- Modules, debug, and protected config changes are off. Lua stays, for Sidekiq and
  BullMQ, inside this leash.
- `maxmemory` is 192 MB, under the leash's 256 MB, and a full store refuses writes.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create valkey --with valkey
```

Nothing answers on the network. A form takes this one `with` and puts its service in
group `valkey`. The client is `valkey-cli -s /run/svc/valkey/valkey.sock`. Commands
are in [Valkey's command reference](https://valkey.io/commands/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create valkey --with valkey --on gcp --allow-from me
```

`--allow-from` opens no port: there is no listener. Keep the store on the same
machine as the service that uses it.

### Exporting and importing data

Use a physical archive from the same image and architecture. The service scope is
`valkey`; full transfer also includes companion service data. The destination
must have empty selected data and remains stopped after import. See
[data storage](../../docs/data.md) for supported adapters and consistency
requirements.

```sh
howl export source --service valkey --output backup.tar.zst
howl import replacement backup.tar.zst
```

[valkey-tcp](../valkey-tcp/README.md) exposes port 6379. Its memory cap is
`--maxmemory`; `0` removes it.

### Known Quirks

- The append-only log is off. A form that must not lose a job sets `appendonly yes`.
- A cache sets `maxmemory-policy allkeys-lru`. This one keeps every key until it is
  full, then refuses writes. To raise or drop the 192 MiB cap, use
  [valkey-tcp](../valkey-tcp/README.md).
- A second start uses the existing `dump.rdb`; import refuses an occupied store.
