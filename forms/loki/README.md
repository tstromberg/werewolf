# Loki

The `loki` form keeps the logs your machines push to it, for 31 days on
`/data`: Loki 3.7 on loopback, behind Caddy, which serves its push and
query APIs over HTTPS for your domain to one user alone, each on a leash
of its own ([design/forms-catalog.md](../../docs/design/forms-catalog.md)).
Loki has no authentication of its own; Caddy's is the door.

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >loki-password
howl create loki --with loki --domain logs.home.arpa --loki-user alloy --loki-password loki-password
```

Point the name at the address howl prints and open `https://logs.home.arpa`. Shippers push to `/loki/api/v1/push` as `alloy`, with that password. Logs are kept 31 days.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >loki-password
howl create loki --with loki --on gcp --allow-from me \
	--domain logs.example.com --loki-user alloy --loki-password loki-password
```

`--allow-from me` admits your address to ports 80 and 443. Caddy gets a certificate once the name resolves.

### Migrating data in

This machine starts empty and takes logs from here on. The old history stays where it is. There is no copy of it into `/data`.

### Network Exposure

tcp/80 tcp/443


## Run your own

You need a domain name you can point at the machine.

```sh
openssl rand -base64 24 >loki-password      # its user's; keep it
howl create logs --with loki --on gcp --allow-from 0.0.0.0/0 \
	--domain logs.example.com --loki-user alloy --loki-password loki-password
```

Point `logs.example.com` at the address howl prints. Shippers push to
`https://logs.example.com/loki/api/v1/push`, and Grafana queries
`https://logs.example.com`, as `alloy` with that password (basic auth).
Caddy gets the certificate once the name resolves to the machine, and
retries until it does.

| Flag | |
| --- | --- |
| `--domain NAME` | required. Caddy's site, with a certificate from Let's Encrypt |
| `--loki-user NAME` | required. The one user Caddy lets through, to push and to query |
| `--loki-password FILE` | required. Its password, 12 to 72 bytes, never printed or logged |

To change a running machine's flags, run its create line again: howl
replaces its config and restarts it; the logs on `/data` stay.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Loki on loopback; the ACME CA |
| Loki | `loki` | its own gRPC on loopback, nothing else |

- **One door.** Loki listens on loopback alone. Caddy asks every request
  for the user, by a bcrypt hash `loki-auth`
  ([cmd/loki-auth](cmd/loki-auth/loki-auth.zig)) writes before it
  starts, from the config's password, whose copy it then removes.
- **No usage reports.** Loki sends Grafana Labs statistics unless told
  not to; [its configuration](rootfs/etc/loki/loki.yaml) says not to, and
  fence lets it reach nothing to send them to.
- **One tenant**, one process: no ring of machines, no object store.
  Chunks, the TSDB index and the compactor's work are in `/data/svc/loki`.
- **31 days**, by the compactor's retention; samples older than a week
  are refused, and each push is held to 4 MB/s, 8 in a burst.
- **No ruler API.** Loki evaluates no rules and takes none over HTTP.

## Drawbacks

- One user for pushing and reading: a machine that may push may also
  read every other machine's logs. Give the shippers their own `loki`
  machine if that matters.
- 31 days on the machine's disk, with no copy elsewhere.

## Checked

`make check-loki` boots it with its test config ([test/config](test/config)),
domain `localhost`, for which Caddy's own CA signs: Loki is ready on
loopback, a stranger's query and push get 401 through Caddy, a line
pushed to Loki comes back through Caddy to its user, fence has no line
for Loki but its own gRPC, and `loki-auth` wrote a hash and removed the
password's copy. `make check-shellfree-loki` boots it as it ships, with
no config: Loki runs, and Caddy parks, saying it has no password, before
anything is written or bound.
