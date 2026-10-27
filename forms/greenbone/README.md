# Greenbone - Hardened VM

Vulnerability management: [Greenbone](https://greenbone.github.io/docs/) gvmd and
gsad, the scanner, and the community feed, behind Caddy, with PostgreSQL and Valkey.
The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/greenbone/index.html).

## Testing status

`howl test --with greenbone` runs native GMP clients and the existing DEV checks. The
native suite checks configured and refused logins, target persistence across two
boots, the gsad socket bridge, OSP version, manager-to-scanner verification, socket
permissions and private listeners. Read-only psql checks cover the ordinary database
roles and installed extensions. The suite adds no shell or SSH server and compares
production policies and payloads first. PostgreSQL includes a pinned build of the
required [pg-gvm
extension](https://github.com/greenbone/gvmd/blob/main/INSTALL.md#configure-postgresql-database-backend).
The scanner uses a group-restricted Unix socket shared with gvmd. Authenticated HTTPS
and a repeatable fixture scan remain additional coverage gaps. Local QEMU integration
results are separate from protected release qualification.

On 2026-10-15, ARM64 passed 24 seed and 23 reboot assertions, retained DEV checks
(including frontend assets), and the plain image's posture and console checks.
The drivers and pg-gvm package also build for x86-64; its VM run is still pending.

## Security Posture

- gsad listens on loopback. Caddy is what the network sees. The scanner serves gvmd
  over a Unix socket, mode 0660; gvmd's mount of its directory is read-only.
- The administrator is `admin`. The password is the config's, applied at every start.
  `admin` / `admin` is refused.
- gvmd's socket is mode 0660, group `_oci-gvmd`. gvm-link keeps that group after it
  drops to `_glink`. The socket it gives gsad is mode 0660, group `_oci-gsad`. A
  command on it still needs the administrator password.
- The scanner is the one service that keeps `CAP_NET_RAW` and `CAP_NET_ADMIN`. These
  capabilities can bypass Fence's routing policy. Isolate the machine from management
  networks and services it must not scan.
- The feed directories under `/data/share/gvm` are owned by the feed, mode 02750.
  gvmd is in that group and may only read it. The scanner may write the plugin
  directory and only read the rest. Nothing else on the machine is in the group.
- PostgreSQL takes one role over loopback. Fence's ordinary route permits only
  Valkey, but a compromised scanner can bypass that route with its retained
  capabilities.
- The scanner may read Valkey's configuration with `CONFIG GET`; `CONFIG SET`
  and other administrative commands remain denied.
- The image's bash runs one script, then the program. The host has no shell. rsync
  and Python stay inside the feed and scanner images.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create greenbone --with greenbone \
	--domain scan.home.arpa --admin-password admin-password
```

Open `https://scan.home.arpa` and sign in as `admin`. The password is in
`admin-password`. Give the machine 8 GB. The feed cache is several gigabytes and the
first sync takes a long time; the UI is up while it runs. Tasks and targets are in
[Greenbone's documentation](https://greenbone.github.io/docs/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create greenbone --with greenbone --on gcp --allow-from me \
	--domain scan.example.com --admin-password admin-password
```

Sign in at `https://scan.example.com`. A scan from this machine reaches the targets
you name, including private addresses. Replies come back to the machine's own local
ports. Its service ports stay closed unless this form listens on them.

### Importing data

The database starts empty. The feed fills the cache on `/data` from the community
server. This form does not import a Greenbone dump.

### Known Quirks

- gvmd listens on a Unix socket, not a TCP port. gvm-link, as `_glink` in the group
  `_oci-gvmd`, copies it into gsad's directory. Both sockets are mode 0660.
- The scanner's socket is `/run/ospd/ospd.sock` in both images, backed by
  `/data/share/gvm/ospd`. Only the scanner writes that directory; gvmd joins its
  group.
- The first feed sync is large. An 8 GiB disk is tight once PostgreSQL and the cache
  share it. A later sync keeps the last good copy when the server is unreachable.
- gvmd connects as an ordinary login with the `dba` owner role. PostgreSQL installs
  its extensions offline; the application has no database superuser role.
- Twelve characters at least, and not `admin`.

### Network Exposure

- listen: tcp/80 tcp/443 *
- connect: the scanner, any TCP port, so a scan can reach a target; the feed, public
  tcp/873; the resolver
