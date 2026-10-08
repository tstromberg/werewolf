# Ad-hoc machines

**Note for reviewers**: Does this fit our principles? Are there unexplored
concerns? Could it be simpler? Are there other alternatives?

Proposed, 2026-10-08; revised the same day after review for shape (Pike),
trust (de Raadt) and operation (Venema). Nothing built.

## Summary

A werewolf machine from a command line alone: forms to combine, Wolfi
packages to add, OCI images to run, mixed freely. The flags generate a form
directory ([forms/README.md](../../forms/README.md)), which the existing
build builds and `form -o` keeps, so a one-shot machine and a reproducible
one are the same files. Policy comes from the operator alone; every
refusal is a line to paste.

```sh
# Wolfi packages: a Python application, with the libraries it imports
howl run python --app ./api --packages py3.13-flask,py3.13-psycopg

# Forms: a site with its cache and database, each on its own leash
howl run caddy --with valkey,postgresql --domain shop.example.com

# OCI images: your own code, as two containers; the worker reaches the web
howl run --oci web=ghcr.io/acme/web@sha256:9f86d0… \
             --oci worker=ghcr.io/acme/worker@sha256:3a7bd3… \
             --web.listen tcp/8080 --link worker:web

# Mixed: containers for your code, forms for the infrastructure under them
howl create shop --on gcp --oci web=ghcr.io/acme/web:1.4 --with postgresql,valkey \
    --link web:postgres,valkey --web.listen tcp/8080 --web.secret 'DB_PASSWORD db.pass'

# Keep what any of those generated; build it from the tree from then on
howl form caddy --with valkey,postgresql -o forms/shop/
howl create shop edge --on gcp --domain shop.example.com
```

## Background

A machine is a form: `apko.yaml`, `form.yaml`, `rootfs/` with a leash
`service` a program ([forms.md](forms.md)), built by `make`, deployed by
`howl` ([cli.md](cli.md)). Writing one is the right first step for a
fleet and the wrong one for trying something: five files before the first
boot. Bundles (`with:`) already combine forms; [oci.md](oci.md) designs
running one image from the config at boot, and is not built. People
arriving from Docker have a list of images, not a form.

## Goals

- Any of the three inputs, or all, boots in one command with no file
  written first. What it generated is shown first; `-n` shows and stops.
- `form -o DIR` writes the same directory; a machine built from it is
  byte-identical to the one-shot. One build path, `_dist-form`.
- Nothing an image, a registry or an index says becomes policy. The
  operator declares; the generator makes declaring a paste.
- Every refusal on the host, before apko runs, naming both sides and the fix.
- Several images a machine, reaching each other and the forms by name.
- `make check` boots one machine of each kind and one mixed.

## Non-Goals

- A compose file, a DSL, positional `a+b`, or prompts.
- Running a package by itself: packages add files; forms and images run.
- Port remapping, namespaces, cgroups, a container runtime (oci.md).
- Pulling at boot (oci.md's path); it stays open for fleets, sharing the unpacker.
- Shell entrypoints. `#!` is refused as oci.md refuses it.
- Changing any existing form, verb, policy line or check (below).

## Detailed design

### The generator

`build`, `run`, `create` and `form` take the flags below; `pack` takes the
generated directory as it takes any form. FORM is the base, `prod` when
omitted. **A form is named after its directory**, as an out-of-tree form
is: `create NAME` generates `build/adhoc/NAME`, `build -o DIR` and `form -o
DIR` the basename of DIR, `run` the directory `run`. No hash, no state.

The generator writes `form.yaml` (`base`, `with`, `net`), `apko.yaml`
(packages; an account an image, uid written down), `rootfs/` (a service an
image, its tree at `/oci/NAME`, `/etc/hosts`), prints the result, then runs
`make FORM=build/adhoc/NAME`. Everything that governs behaviour is written
out, not left to a default (`memory`, `user`, ports, `exec`), so a kept
form means the same next year. Its first line is its provenance: the
generating command with paths, never values, the howl version, the
date. `--print` shows the *effective* machine, the chain merged: every
service, every `net` line, who writes where. `-n` prints and builds nothing.

| Flag | Generates |
| --- | --- |
| `--with FORM,...` | `with:`; refused if two forms serve one port or declare one config name |
| `--packages PKG,...` | `apko.yaml` packages, each checked against the APKINDEX first |
| `--oci NAME=REF` | an account `_oci-NAME`, the tree at `rootfs/oci/NAME`, a service (below) |
| `--link A:B,...` | A may reach B: a `connect` to B's `loopback` port, or B's UNIX socket bound into A; `B` in A's `/etc/hosts` |
| `--SERVICE.DIRECTIVE 'WORDS'` | one line in image SERVICE's service file, checked by leash's own parser (`lib/`): `--web.listen tcp/8080`, `--web.write /var/cache/web`, `--web.env K=V`, `--web.secret 'NAME FILE'`, `--web.exec '/app/server --port 8080'`, `--web.memory 1024` |

The last is the whole grammar for images: the argument is the line as it
would stand in the file. A form's own flags (`--domain`,
`--authorized-keys`) work unchanged, and a form's services are not edited
from the line; keep the form and edit the file. A one-shot's `--web.secret
'DB_PASSWORD db.pass'` packs the file and declares `config db-password`,
so the kept form's flag is `--db-password FILE`; the generator prints the
command to run next time, with that flag and the digests.

### Images: baked on the host, by three processes

An image is baked into the verified root at build, not pulled at boot: no
tmpfs executed, no policy fixed after boot, no boot cost; a new image is a
new build and a `create`, as `--app` is. The host resolves a tag to a
digest once and prints the `--oci NAME=REF@sha256:…` to use next time;
`form -o` refuses to write a form that still names a tag.

The pull keeps oci.md's shape on the host: `howl _fetch` speaks HTTPS
and holds the registry token and nothing else; the parent checks every
size and digest before parsing; `howl _unpack DIR` inflates and applies
layers beneath one directory, with no network, no environment and none of
the operator's credentials, sealed on Linux (seccomp, Landlock), a plain
child on macOS, which is said. oci.md's refusals and fixed limits apply
(links out, devices, `..`, setuid stripped; 128 layers, 500,000 entries, 4
MiB manifests). Blobs cache in `build/oci/blobs/HEX`, hashed as read.

### Operator policy; the image's words are a checklist

`ExposedPorts` and `Volumes` are the image author's declarations, not the
operator's. They grant nothing. An image that declares either needs the
operator's word on it: any `--NAME.listen` or `--NAME.write` is that word;
without one the generator refuses and prints the grants, least privilege
first:

```
web: ghcr.io/acme/web:1.4 is sha256:9f86d0…; say --oci web=ghcr.io/acme/web@sha256:9f86d0…
web: the image exposes 8080 and writes /var/cache/web; nothing is granted. Say what you want:
    --web.listen 'tcp/8080 loopback'   for a linked container alone
    --web.listen tcp/8080              public
    --web.write /var/cache/web
```

A port the operator did not grant stays unbindable; a path not granted
stays read-only; the printed service shows both.

### The service an image gets

```
# ghcr.io/acme/web@sha256:9f86d0…, from howl form
root    /oci/web
exec    /app/server
user    _oci-web
listen  tcp/8080
connect tcp/6379
write   /var/cache/web
env     PATH=/usr/local/bin:/usr/bin:/bin HOME=/data
secret  DB_PASSWORD /run/svc/web/db-password
memory  512
```

leash gains `root DIR` and `dir DIR` as oci.md specifies; a `write PATH`
under a root is a `noexec` bind of `/data/svc/NAME/PATH` at PATH, made by
init with the binds oci.md lists, each opened `RESOLVE_BENEATH`. The
service logs its digest on every start. `/etc/hosts` names the services
it is linked to, at `127.0.0.1`, and no other: a name that resolves is a
name it may reach. A link to a form whose service speaks a UNIX socket
(`postgres`, `valkey`) binds `/run/svc/SVC` into the image at the path the
client library expects, so the listener knows its peer and no password is
needed; the generator prints the env the container wants (`PGHOST`). A
link to an image is a `connect` to its `loopback` port.

### `loopback` on a listen

Leash lets a service `bind()` only its `listen` ports (Landlock
`BIND_TCP`), and a `listen` in `net` is a served port fence delivers from
outside ([fence.md](fence.md), rule 300): a listener is public or
impossible. `listen tcp/5432 loopback` grants the bind and is left out of
the served set, the twin of `connect … public`: one word in the net
compiler, leash, fence and posture's `network-ports`. Loopback is delivered
before any rule (rule 10), so a link is two declared lines. The build
asserts the kernel's Landlock ABI is at least 4, and leash refuses to
start a service with network lines on one below, rather than dropping
them. Forms gain the word too: Gitea calling its own API today.

### What does not change

Every existing form, its `net` and its checks; every verb without an
ad-hoc flag; `pack`; fence's rules for every policy that has no `loopback`
line; the release forms and the updater. `root`, `dir`, `write` under a
root, and `loopback` are additive; a service file without them parses as
today. oci.md's boot-time pull stays possible later on the same unpacker.

### Order

Each phase ships alone, with its check, and touches nothing above it.

1. **`loopback`**: net compiler, leash, fence, posture; a check that the
   host cannot reach a `loopback` port the guest serves itself.
2. **`--with`, `--packages`, `form`** with `-o`, `-n`, `--print`, naming by
   directory, provenance, defaults written out, APKINDEX and collision
   checks, the memory sum. Checks: `caddy --with valkey` and `python
   --packages` booted ad-hoc and from their kept forms, byte-identical.
3. **leash `root`/`dir`, `write` under a root, init's binds, fence's
   `/oci` exec rule, the ABI assertion**, tested with a hand-laid
   `rootfs/oci/t/` holding a static ELF and a `/bin/sh` that must not run.
   No puller yet, no network.
4. **The host puller**: `_fetch`, the parent, `_unpack`, cache, limits,
   tag resolution; oci.md's fixtures as unit tests; a stand-in registry in
   `make check`.
5. **One image**: the generated account and service, the checklist
   refusal, `#!` refused with the pointer, `--NAME.exec`, the digest in
   the manifest and the start log, posture's `oci-mount` and `oci-user`.
6. **Several**: `--link` by `loopback` and by socket, hosts for linked
   names, uids written out, collisions across images and forms; the mixed
   check: two linked images and `postgresql`, a whiteout, a volume, a
   `loopback` port the host cannot reach.
7. **Limits for what is shared**: a `disk` line per service enforced on
   `/data/svc/NAME` (ext4 project quotas, set by init; designed in
   data.md first), restart backoff in leash, the disk sum printed with the
   memory sum.
8. **Docs**: README's "Try it", forms.md, cli.md's verb table; oci.md
   marked as the fleet path over this one.

## Drawbacks

- The first build needs the network: the lock and the blobs. Hermetic
  once `form -o` has kept the lock beside the form.
- Stock images get two refusals, entrypoint and volumes, each pointing at
  the form that replaces them or the line that grants them.
- The one-shot's `--web.secret` becomes `--db-password` in the kept form;
  the printed next command is the bridge.
- Baked images make the disk larger and a redeploy a rebuild.
- Three host processes for a pull is more code than one; it is oci.md's
  code, linked for the host.
- Phase 7's quota needs the `project` feature on `/data`; existing data
  disks lack it and keep running without a limit, which posture reports.

## Alternatives Considered

**A compose file.** Most of it means nothing here; the rest is these
flags. `form` could read one later without changing this design.

**Infer a service from a package.** Guessing, which the guest refuses
everywhere else. Packages add.

**Pull at boot (oci.md).** Right for a fleet swapping images under a
signed base; wrong for the first machine. Kept open.

**`ExposedPorts` and `Volumes` as policy.** The first draft did this.
It makes the image author the author of binds and writable paths, and a
printed service is not consent when `run` builds as it prints.

**A hash as the form's name.** The first draft did this. A cache key in
the UI; the directory's name serves, and the user chose it.

**Flags per concern** (`--listen`, `--env`, `--volume`, `--exec`). Six
value grammars for seven leash directives. The line is the grammar.

**Containers reach every sibling.** Compose's default. `--link` is one word.

## Security Considerations

The guest trusts what it trusted before: a form directory, leashed
services, one `net`. The operator is the only author of policy; the image
author's declarations become a checklist with the least-privilege answer
first. What the host resolves once is written down and signed with the
image, never resolved on the machine. Untrusted bytes are fetched and
unpacked by children holding no credentials, with oci.md's limits, so the
deploy laptop is not the new target. `loopback` ports are never served
outside; a UNIX socket is offered where a peer's identity matters; links
are per port; each image is its own uid with `hidepid`; `#!` stays
refused; writable paths are `noexec` and beneath `/data/svc/NAME`; a value
never crosses argv unless it is a setting. Theo's remaining objection is
loopback TCP between images, where the listener cannot name its peer:
Landlock's per-uid `connect` is the kernel saying who may dial, the ABI is
asserted rather than assumed, and the socket path is there for anything
that needs the peer's name.

## Reliability Considerations

Same flags, same form, same lock, same bytes; the blob cache makes a
second build fetch nothing. Every collision and every unanswered image
declaration is refused before apko runs, so a failed build is a line on
the host, never a machine with a parked service; a refused image fails the
build whole. `-n` and `--print` show the effective machine before anything
is built. A kept form carries its provenance and its defaults, so a
changed generator changes no kept machine. Memory and, from phase 7, disk
are summed and printed against the machine. `make check` boots a bundle, a
form with packages, one image, and two linked images beside `postgresql`,
each also from its kept form; CI runs what users type.
