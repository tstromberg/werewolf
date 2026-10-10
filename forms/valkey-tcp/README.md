# Valkey TCP - Hardened VM

[Valkey](https://valkey.io) 9.1 on TCP port 6379: [valkey](../valkey/README.md) with a reachable listener. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The server runs as its own user. There is no shell. Landlock and seccomp hold it to its socket, to port 6379, and to `/data/svc/valkey`. The root is read-only.

- The socket remains. A client on the network needs the password. `nopass` does not leave the machine.
- The default user may do everything except administer the server. `CONFIG`, `DEBUG`, `MODULE`, `REPLICAOF`, `SHUTDOWN`, `MONITOR` and ACL changes are refused.
- There is no cgroup memory cap. The socket form's 256 MiB is what keeps a cache from taking the application down. This machine is the store.
- `--maxmemory` is the cap, in MiB. `0` removes it. Leave the flag off and the cap is off: the image's 192 MiB does not apply here.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 | tr -d '\n' >password
howl create valkey-tcp --with valkey-tcp --maxmemory 256 --valkey-password password
```

The server answers on port 6379 of ADDRESS. The client is `valkey-cli -h ADDRESS -p 6379 -a "$(cat password)"`. Commands are in [Valkey's command reference](https://valkey.io/commands/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 | tr -d '\n' >password
howl create valkey-tcp --with valkey-tcp --on gcp --allow-from me \
	--maxmemory 1024 --valkey-password password
```

`--allow-from me` admits your address to port 6379. `--maxmemory` is mebibytes. `--maxmemory 0` removes the cap. A form that must also keep a cgroup cap restates this service with `memory:` set above that number. The cgroup is in the image, so it cannot follow the flag.

### Migrating data in

`--import` copies `dump.rdb` once, before the first start. Take it from the old server with `valkey-cli --rdb dump.rdb`. The password and the cap are the same flags as a fresh install.

```sh
openssl rand -base64 24 | tr -d '\n' >password
howl create valkey-tcp --with valkey-tcp --maxmemory 1024 \
	--valkey-password password --import ./dump
```

A cloud cannot attach the disk. Import where a second disk can be attached, then keep that data.

### Known Quirks

- The password file has no newline. A space or a `#` in it is refused.
- The append-only log is off. A form that must not lose a job sets `appendonly yes`.
- A second start that finds `dump.rdb` keeps it. `--import` does not replace a store that exists.

### Network Exposure

tcp/6379
