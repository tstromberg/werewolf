# OCI images

Proposed, 2026-10-06. Half built, 2026-10-08, by [adhoc.md](adhoc.md):
images baked into the verified root by `howl --oci` (cmd/howl/oci.zig,
cmd/init/oci.zig, leash's `root` and `dir`). Not built: pulling at boot.

## Summary

A werewolf machine runs an OCI image as any other service: as its own
user, on a leash, unable to run anything written since boot, with no
container runtime. Baked, the image is part of the signed root; pulled,
for a fleet on one signed base, the config tar would name its digest.

## Background

People arrive with images, not forms. A container runtime needs `mount`,
`pivot_root` and usually user namespaces, all of which werewolf takes away.
So the design follows OpenBSD (privileged work at boot, then given up;
input refused whole at the first thing not understood; no knobs) and Unix
(a small subset done completely, into a service file one can `cat`).

## Goals

- An image runs as its own user, never root, and runs only the programs
  its service names and their ELF loaders: its `/bin/sh` cannot run.
- A reference names a digest, so what runs is exactly what was named.
- No daemon, and no new way after boot to make an executable mount.

## Non-Goals

- Namespaces: `hidepid`, Landlock's scoping and fence's per-user rules
  stand in. Limits beyond leash's cgroup; `/dev/shm`, GPUs; the image's
  user in its `/etc/passwd`, so a lookup of itself finds nothing.

## Detailed design

**Baked (built).** howl pins a tag to its digest once and prints it.
`crane export REF@sha256:…` verifies every blob and flattens the layers
into one tar; `howl _unpack` writes it to `rootfs/oci/NAME` with no
environment, confined on Linux by Landlock to that directory. It refuses
the whole image at the first entry it does not accept, and keeps no
setuid bit or file capability. The image's config becomes a service file
(cmd/howl/adhoc.zig) whose entrypoint must be ELF: a `#!` script's
interpreter would have to run too. The refusals, limits, mapping and the
root's contents are in [forms.md](../forms.md#forms-from-the-command-line).
At build howl makes each bind point empty, replacing links too; before
fence, init binds the service's `/proc`, devices and own `noexec`
directories (cmd/init/oci.zig), and the mount tool opens each target
without following links. The tree is in the dm-verity root, so no link
appears in between, the race runc's CVE-2021-30465 used.

**Pulled at boot (proposed).** An `oci` file in the config tar names
`image REF@sha256:HEX`, never a tag, and a service's lines. Before fence,
init mounts a `noexec` tmpfs at `/oci`, runs `oci-pull`, binds as above,
and remounts `/oci` read-only and executable; a file still open for
writing fails that (`EBUSY`), so the tree is never writable and executable
at once. On failure the machine boots without it, and a slot commits.
`oci-pull` is three processes: a fetcher (`_pull`, chrooted, TCP 443 and
53); a parent that checks each digest, chained from the config's, before
it parses a byte; an unpacker with no network. Blobs cached in
`/data/svc/oci/blobs` are hashed again when read. fence takes `_oci`'s
ports from oci-pull: the one invariant this relaxes (policy fixed at
build), for someone who is root already.

## Drawbacks

- Baked: a new image is a new build and reboot; the build needs crane and
  the network. Stock images whose entrypoint is a script are refused.
- Pulled: boot waits on the registry; images fit in half of RAM; IPE under
  verified boot would refuse a tmpfs ([verified-boot.md](verified-boot.md)).

## Alternatives Considered

- **containerd, runc, crun**: they need mounts and user namespaces (off,
  [lockdown.md](lockdown.md)), so would run outside fence with
  `CAP_SYS_ADMIN`, with runc's history (CVE-2019-5736, CVE-2024-21626).
- **overlayfs**: what is written to its upper layer could run.
- **Pulling after boot**, or a broker word for `/oci`: root could mount
  what it wrote, executable.
- **Unpacking to `/data`**: root could change what runs, and keep the
  change past a reboot.
- **Signatures (cosign)**: the digest names the image, and its author is
  root already; a key adds nothing until verified boot.

## Security Considerations

| Attacker | Can | Cannot |
| --- | --- | --- |
| whoever writes the form or config | run any image | more: they are root already |
| registry, CDN, network | withhold the image | change a byte, checked against the digest |
| a hostile image | run as its user, read world-readable files, use its ports | run anything but its entrypoint; write its root; bind another port; see other users' processes; keep anything outside `/data/svc/NAME` |
| a bug in the unpacker | spoil the image | write outside its directory (Landlock, on a Linux host) |
| root, after boot | stop the service; read the tree | replace it, mount anything, or run what it wrote |

## Reliability Considerations

- A failed bind never stops a boot: init logs it, and the service parks.
- posture's `processes-image-roots`: each image runs in its root, and its
  `/tmp`, `/run` and `/data` are `noexec`, `nodev`.
- The build prints each image's digest, and the service file names it.
