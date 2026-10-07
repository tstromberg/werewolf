# OCI images

Proposed, 2026-10-06.

A werewolf machine should run an OCI image named in its config the way it
runs any other service: as its own user, on a leash, unable to run anything
written since boot. It should need no container runtime, and no reboot to
start the image. Running a different image takes a reboot.

## Shape

The design follows the two traditions werewolf already borrows from.

From OpenBSD: privileged work happens at boot and is then given up for
good, as `securelevel` gives it up. Whatever parses the network runs with
nothing. Input is refused whole at the first thing that is not understood,
and nothing is guessed. There are no knobs.

From Unix and Plan 9: one program, one job, and text a person can read with
`cat`. Do a small subset of the specification completely, not all of it
partly. The image's configuration becomes a leash service file, the format
every other service already uses, and that file is the whole of what runs.

That rules out:

- **A daemon.** Nothing stays running to manage the image: it is pulled
  and unpacked at boot, and then it is a service like any other.
- **Tags.** A tag can point at different code tomorrow. A reference names
  a digest, so the config says exactly what runs.
- **Root.** The image runs as `_oci`, whatever its `User` says.
- **Anything but the entrypoint.** The service may execute its entrypoint,
  the programs its config names, and their ELF loaders. A `/bin/sh` in the
  image is there, but it cannot be run.
- **A new image while the machine runs.** After boot, no process can make
  an executable mount (fence.md, Files), and this design adds no way to.

## The config

An `oci` file in the config tar, in the grammar of a service file
(shell-free.md):

```
# What this machine runs.
image   ghcr.io/acme/api@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
args    serve --port 8080
listen  tcp/8080
connect tcp/443 udp/53 tcp/53
env     LOG_LEVEL=info
secret  API_TOKEN api-token
auth    registry-auth
```

| Line | Means |
| --- | --- |
| `image REF@sha256:HEX` | what runs; required. The reference names its registry, so there is no default `docker.io`. A tag alone is refused |
| `args WORD...` | replaces the image's `Cmd`, as `docker run IMAGE ARGS` does |
| `listen`, `connect` | as in a service file; also `_oci`'s network policy (below) |
| `env NAME=VALUE` | added after the image's `Env`, so it wins |
| `secret NAME FILE` | a variable read from another file in the config tar |
| `auth FILE` | `user:token` for a private registry, from another file in the config tar |

Whoever sets the config is root on the machine already ([cloud.md](../cloud.md)),
so nothing here gives them more than they have.

## At boot

init does the following after the network is up and the config is found
(the config can come from `cloud-metadata`), and before fence:

1. Mounts a tmpfs at `/oci`, read-write, `nosuid,nodev,noexec`, at most
   half of RAM.
2. Runs `/usr/lib/werewolf/oci-pull` with the `oci` file on its standard
   input. oci-pull fills `/oci` and writes `/run/werewolf/oci/service`
   and `/run/werewolf/oci/net`.
3. Once oci-pull has exited, bind-mounts the few things the image needs
   from the machine, at fixed places beneath `/oci` (The root, below).
4. Remounts `/oci` read-only and executable, still `nosuid,nodev`. A file
   still open for writing makes the remount fail with `EBUSY`, and init
   then refuses the image. The tree is never writable and executable at
   the same time.
5. Hands over to fence, as it does now.

If oci-pull fails, or the image is refused, init unmounts `/oci` and says
why on the console and in `/run/werewolf/oci/failed`. The machine boots
without the image. The `oci` service parks, since it has no service file,
and a slot still commits: a registry being down is no reason to undo an
update of the OS.

## oci-pull

oci-pull is three processes, as `cloud-metadata` and the updater are
([programs.md](../programs.md)). It starts as root, opens what it needs,
and has given root up before it reads a byte from the network.

| Process | As | Reaches | Does |
| --- | --- | --- | --- |
| fetcher | `_pull`, chrooted to a directory holding copies of the resolver's files; the CA bundle read before the chroot, as the updater's fetchers do | TCP to 443 and 53; no files | Speaks HTTPS: the token exchange, manifests, blobs. Follows redirects to any HTTPS host, since only the digest matters. Hands the parent at most the size it was asked for |
| parent | `_pull` | the blob cache; its two output files; pipes | Checks every digest and size, and only then parses. Chooses the platform. Maps the image's config to a service file |
| unpacker | `_pull`; Landlock writes beneath `/oci` alone; no network | `/oci`; the verified blobs | Inflates gzip or zstd and applies the tar entries, layer by layer |

### The digest chain

Every byte that is parsed has first been checked against a digest that
comes, through this chain, from the config:

1. The config names the top digest. The fetcher gets that manifest or
   index, and the parent checks its sha256 before it parses it.
2. An index is searched for `linux` and the machine's architecture
   (`amd64`, or `arm64` with variant `v8` or none). The manifest it names
   is checked in the same way.
3. The manifest names the config blob and the layers, each with a digest
   and a size. Each blob is fetched to the cache, must be exactly its
   declared size, and must hash to its declared digest before the unpacker
   is given it.

Accepted media types: the OCI image index and manifest, Docker's v2
manifest list and manifest, and layers that are plain tar, tar with gzip,
or tar with zstd. Everything else is refused, including schema 1,
non-distributable layers, and an index that is nested more than one level
deep.

Blobs are kept in `/data/svc/oci/blobs/<hex>` when `/data` is a disk, and
hashed again as they are read on every boot, so a later boot fetches
nothing. A blob the image no longer names is removed once a pull succeeds.
When `/data` is a tmpfs, blobs are removed once they are unpacked.

### Unpacking

Layers are applied in order. For each entry:

| Entry | Does |
| --- | --- |
| directory, regular file | made, mode kept but for setuid, setgid and sticky, which are cleared; no write bits for anyone |
| symlink | made as given; it is resolved only inside the chroot, so a target outside the tree means nothing |
| hard link | to an entry already in the tree, beneath `/oci`; otherwise refused |
| `.wh.NAME` | removes NAME, from earlier layers |
| `.wh..wh..opq` | empties its directory, of earlier layers |
| device, FIFO, anything else | refused |
| a name with `..`, an absolute name, a name through a symlink | refused (a leading `./` is dropped) |

PAX `path`, `linkpath` and `size` are honoured. Extended attributes are not
applied, so file capabilities in `security.capability` are dropped. Files
are owned by `_pull`. That does not matter: once mounted read-only beneath
fence's rules, the tree cannot be written by anyone, root included.

The image is refused whole, with the entry that failed, at the first
refusal.

### Limits

Fixed, with no knobs: a manifest or index of 4 MiB at most, a config blob
of 1 MiB, 128 layers, 500,000 entries, names of 4,096 bytes and components
of 255 bytes. The unpacked tree must fit in the tmpfs. A pull gets four
tries over a minute to reach the registry, and the whole pull has five
minutes.

## What is taken from the image

| Image config | Becomes |
| --- | --- |
| `Entrypoint`, `Cmd` | `exec`, resolved against the image's `PATH` inside the tree to an absolute path. It must be an ELF for the machine's architecture. A `#!` script is refused, because its interpreter would have to be executable too |
| `Env` | `env`, before the config's own |
| `WorkingDir` | `dir` |
| `User` | ignored: always `_oci` |
| `ExposedPorts` | ignored: the config's `listen` lines decide |
| `Volumes` | ignored: `/data` is the one place to keep anything |
| `StopSignal`, `Healthcheck`, `Shell`, `OnBuild`, `Labels` | ignored |

The parent writes the result as an ordinary service file, which can be
read with `cat`:

```
# ghcr.io/acme/api@sha256:9f86d081…, from oci-pull
root    /oci
exec    /app/server serve --port 8080
dir     /app
user    _oci
listen  tcp/8080
connect tcp/443 udp/53 tcp/53
env     PATH=/usr/local/bin:/usr/bin:/bin HOME=/data
env     LOG_LEVEL=info
secret  API_TOKEN /run/config/api-token
```

## The root

What the image sees as `/`:

| Path | Is |
| --- | --- |
| `/` | the image, read-only and executable |
| `/proc` | a procfs of its own, with `hidepid=invisible` |
| `/sys/devices/system/cpu` | the machine's, read-only, so it can count CPUs |
| `/dev/null`, `zero`, `full`, `random`, `urandom` | the machine's devices, bound |
| `/etc/resolv.conf` | the machine's, bound, so it follows DHCP |
| `/etc/hosts` | `localhost` and the hostname |
| `/tmp` | `/run/svc/oci`, `noexec` |
| `/data` | `/data/svc/oci`, `noexec` |

The unpacker makes each of these as an empty directory or file, replacing
whatever the image had at that path. init then opens each one beneath
`/oci` with `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, and
refuses anything that is not the empty directory or file it expects.
Nothing writes to the tree between those two steps, so the race that
runc's CVE-2021-30465 was built on does not exist here.

## Running it

The `oci` form's `/etc/sv/oci/run` is a link to leash, and
`/etc/sv/oci/service` is a link to `/run/werewolf/oci/service`. Root can
change that file, which gives root nothing new: whatever the file names can
execute only beneath `/oci` and `/usr`, and root can already run those.

leash gains two directives:

| Directive | Means |
| --- | --- |
| `root DIR` | Paths in the service are the image's. leash opens them beneath DIR without leaving it (`RESOLVE_IN_ROOT`), builds the ruleset, then `chroot`s to DIR before it gives root up. |
| `dir DIR` | The working directory, inside the root; otherwise `/data` |

For a service with a root, leash's floor is: read everything beneath the
root; read and write its `/tmp` and `/data`; the five devices. It may
execute only `exec`, `run` and their loaders, as for any service. With no
capabilities and `no_new_privs`, the service cannot leave the chroot.

Restarting the service is runsv's job, as for any service. It pulls
nothing and mounts nothing.

## The network and the machine's rules

Two changes, both to fence, which reads them before it applies anything:

- **Files.** Execute is allowed beneath `/oci`, and write beneath
  `/oci/tmp` and `/oci/data`. Landlock judges a path by the mounts it
  crosses, not by where a bind came from, so `/data`'s rule does not reach
  `/oci/data`, and the two binds need rules of their own. Only `/oci` is
  added to execute; `/usr` keeps its rule.
- **Ports.** fence reads `/run/werewolf/oci/net` after the image's policy
  and refuses any line in it for a user other than `_oci`. `_oci`'s
  policy is fixed at boot rather than at build; every other user's policy,
  root's included, is still fixed at build. This is the one invariant this
  design relaxes. It gives nothing to anyone who did not already have it,
  because whoever sets the config is root.

`_oci` never reaches the metadata server: no `metadata` line can name it.

## What it guards against

| Attacker | Can | Cannot |
| --- | --- | --- |
| Whoever sets the config | run any image, open ports for `_oci` | nothing more: they are root on the machine already |
| The registry, a CDN, the network | withhold the image: the machine boots without it | change a byte: every byte is checked against the config's digest before it is used |
| A hostile image | run as `_oci`; read its own files and the world-readable files of the machine; use its declared ports | run anything but its entrypoint; write its own root; bind an undeclared port; reach the metadata server; see other users' processes; keep anything but `/data/svc/oci` |
| A bug in the unpacker or a decompressor | spoil the image, which is then refused | write outside `/oci`; reach the network |
| root, after boot | stop the service; read `/oci` | replace `/oci`; make any mount, executable or not; run anything it wrote |

## Checked

`posture` adds:

- `oci-mount`: `/oci` is read-only, `nosuid` and `nodev`, and its only
  writable places are `/oci/tmp` and `/oci/data`, both `noexec`.
- `oci-user`: the service runs as `_oci`, not as uid 0, with no capability
  but `CAP_NET_BIND_SERVICE` for a port below 1024.
- For information: the image's digest and size, and any shells or
  interpreters it carries. They are not judged, since `_oci` cannot run
  them.

`make check` gets a stand-in registry, as `test/metadata` stands in for the
metadata server. It serves an image built by the test, with a whiteout, an
opaque directory, a symlink, a hard link, a setuid file and a `/bin/sh`.
The checks:

- The service runs as `_oci` and serves its port.
- `/bin/sh` in the image cannot be executed by the service.
- A write beneath `/oci` is refused, root's included.
- A blob with the wrong digest is refused, and `/oci` is not mounted.
- A tag without a digest is refused.
- An entry with `..`, an absolute name, a device or a hard link out of the
  tree is refused.
- An image whose `/tmp` is a symlink to `/etc` gets its own `/tmp`.
- A second boot fetches nothing.

## Logging

One line per pull, one per refusal:

```
oci-pull: {"time":"2026-10-06T17:02:11Z","event":"pull","image":"ghcr.io/acme/api","digest":"sha256:9f86d081884c7d65","arch":"arm64","layers":4,"fetched":2,"cached":2,"bytes":28311552,"files":1840,"ms":3110}
oci-pull: {"time":"2026-10-06T17:02:11Z","event":"refused","image":"ghcr.io/acme/api","why":"layer 3: dev/sda: a device"}
```

## Rejected

- **containerd, runc, crun.** They need `mount`, `pivot_root` and usually
  user namespaces. Under fence's Landlock domain they could not mount at
  all, so they would have to run outside it with `CAP_SYS_ADMIN`, like the
  mount broker. That means a large daemon with root's powers and an API,
  where the broker is a few hundred lines that take one word. It would
  also bring in some 100 MB of Go and runc's history (CVE-2019-5736,
  CVE-2024-21626).
- **overlayfs.** Its writable upper layer over an executable lower one is
  the thing werewolf forbids: what is written can run.
- **Pulling after boot**, or a mount broker word for `/oci`. Either gives
  root back a way to make an executable mount of what it wrote.
- **Unpacking to `/data` and binding it beneath `/oci`.** Root could
  change what runs underneath the bind, and the change would survive a
  reboot. The threat model's "keeps only `/data`, which nothing executes"
  would no longer be true.
- **User namespaces, rootless.** They are off on werewolf
  ([lockdown.md](lockdown.md)).
- **Signatures (cosign).** The digest already proves the image is the one
  the config's author named, and that author is root. A key would add
  infrastructure for no new guarantee until verified boot.

## Not covered

- **Images larger than half of RAM.** Later: build an erofs from the
  unpacked tree on `/data` at boot, and mount it through dm-verity with a
  root hash computed at boot. dm-verity is in every form, and
  `lib/verity.zig` makes the tree. A change to the file on `/data` then
  fails its reads, rather than running.
- **Verified boot.** IPE judges a file by its filesystem's dm-verity root
  hash or signature, and a tmpfs has neither, so IPE would refuse `/oci`.
  Running images from the config under IPE means trusting a key that the
  config's author holds. That decision belongs to
  [verified-boot.md](verified-boot.md).
- **More than one image.** One machine, one image. A second would need a
  second user and root, and nothing in the design prevents that later.
- **Resource limits.** There are no cgroups. The image shares the machine,
  as its one workload.
- **Namespaces.** The image shares the machine's hostname, addresses and
  PID space. `hidepid`, Landlock's scoping and fence's per-user rules stand
  in for namespaces.
- **`/dev/shm`, GPUs and other devices.**
- **`_oci` in the image's `/etc/passwd`.** It is not there, so a program
  that looks up its own user gets nothing.

## Order

1. The unpacker, with test fixtures for whiteouts, links and every
   refusal. Unit tests, no network.
2. The parent and the fetcher: the digest chain, and a stand-in registry
   in `make check`.
3. init's tmpfs, binds and remount; fence's `/oci` rules and `_oci`'s
   lines; leash's `root` and `dir`.
4. The `oci` form, posture's checks, and a `prod-oci` release form, so a
   stock signed image runs whatever the config names.
5. Later: erofs under dm-verity for large images.
