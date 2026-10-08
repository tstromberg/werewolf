# Ad-hoc machines

Proposed, 2026-10-08; revised after review for shape, trust and operation.

## Summary

A werewolf machine from a command line alone: forms to combine, Wolfi
packages to add, OCI images to run, mixed freely. A form is five files
before the first boot ([forms.md](forms.md)): right for a fleet, wrong for
trying something, and people arriving from Docker have a list of images,
not a form. The flags generate a form directory
([forms/README.md](../../forms/README.md)); the existing build builds it
and `form -o` keeps it, so a one-shot machine and a reproducible one are
the same files. The operator alone writes policy; every refusal is a line
to paste.

```sh
howl run python --app ./api --packages py3.13-flask,py3.13-psycopg      # packages
howl run caddy --with valkey,postgresql --domain shop.example.com        # forms
howl run --oci web=ghcr.io/acme/web@sha256:9f86d0… \                     # images
         --oci worker=ghcr.io/acme/worker@sha256:3a7bd3… \
         --web.listen tcp/8080 --link worker:web
howl create shop --on gcp --oci web=ghcr.io/acme/web:1.4 \               # mixed
    --with postgresql,valkey --link web:postgres,valkey --web.listen tcp/8080
howl form caddy --with valkey,postgresql -o forms/shop/                  # keep it
```

## Goals and non-goals

One command boots any input or all three, and `-n` shows the result and
stops. `form -o DIR` keeps it, and the kept form builds byte-identical.
Nothing an image, registry or index says becomes policy. Every refusal is
on the host, before apko, naming both sides and the fix. Several images a
machine. Nothing changes for a machine that uses none of this. Not: a
compose file, a DSL or prompts; a package running by itself; port
remapping, namespaces, cgroups or a runtime; pulling at boot
([oci.md](oci.md)'s path, kept open); shell entrypoints, refused as oci.md
refuses them.

## Detailed design

**The generator.** `build`, `run`, `create` and `form` take the flags
below; `pack` takes the generated directory as any form. FORM is the base,
`prod` when omitted. A form is named after its directory, as an out-of-tree
form is: `create NAME` makes `build/adhoc/NAME`, `-o DIR` the basename,
`run` the directory `run`. The generator writes `form.yaml`, `apko.yaml`
(packages; an account an image, uid written down) and `rootfs/` (a service
an image, its tree at `/oci/NAME`), every behaviour-governing line written
out rather than defaulted and the command as its first comment; prints it;
runs `make FORM=build/adhoc/NAME`.

| Flag | Generates |
| --- | --- |
| `--with FORM,...` | `with:`; refused if two forms serve one port or declare one config name |
| `--packages PKG,...` | packages, each checked against the APKINDEX first |
| `--oci NAME=REF` | account `_oci-NAME`, tree at `rootfs/oci/NAME`, a service |
| `--link A:B,...` | A reaches B: `connect` to B's `loopback` port, or B's UNIX socket bound into A |
| `--NAME.DIRECTIVE 'LINE'` | one line of image NAME's service file, checked by leash's parser in `lib/`: `--web.listen tcp/8080`, `--web.write /var/cache/web`, `--web.env K=V`, `--web.secret 'NAME FILE'`, `--web.exec '/app/server --port 8080'`, `--web.memory 1024` |

The last is the whole grammar for images: the argument is the line as it
stands in the file. A form's flags (`--domain`) work unchanged; a form's
services are not edited from the line. A one-shot `--web.secret` packs the
file and declares `config`, so the kept form's flag is `--db-password FILE`;
the generator prints the command to run next time, with it and every digest.

**Images are baked, by `crane`.** An image goes into the verified root at
build: no tmpfs executed, no policy fixed after boot, no boot cost; a new
image is a new build and a `create`, as `--app` is. `crane export REF@sha256:…
-` pulls by digest, verifies every blob and flattens the layers to one tar
on a pipe; `howl _unpack DIR` reads it with no network, environment or
credentials, sealed on Linux, with oci.md's refusals and limits (`..`,
devices, links out, setuid stripped, 500,000 entries). A tag is resolved
once and printed as the `REF@sha256:…` to use next time; `form -o` refuses
to write one.

**The image's words are a checklist.** `ExposedPorts` and `Volumes` grant
nothing. An image declaring either needs the operator's word, any
`--NAME.listen` or `--NAME.write`; without one the generator refuses and
prints the grants, least privilege first: `--web.listen 'tcp/8080
loopback'` for a linked container alone, `--web.listen tcp/8080` public,
`--web.write /var/cache/web`.

**The service** is oci.md's mapping (`root /oci/web`, `user _oci-web`,
`exec`, `env`, `memory`) plus the operator's lines. leash gains `root` and
`dir` as oci.md specifies; `write PATH` under a root is a `noexec` bind of
`/data/svc/NAME/PATH` at PATH, made by init beside oci.md's binds. A link
to a form speaking a UNIX socket (`postgres`, `valkey`) binds `/run/svc/SVC`
into the image where the client library looks, so the listener knows its
peer and no password exists; a link to an image is `connect` to its
`loopback` port. The service logs its digest at every start.

**`loopback` on a listen.** Leash lets a service `bind()` only its `listen`
ports (Landlock `BIND_TCP`), and a `listen` in `net` is a served port fence
delivers from outside ([fence.md](fence.md), rule 300): a listener is public
or impossible. `listen tcp/5432 loopback` grants the bind and is left out of
the served set, the twin of `connect … public`: one word in the net
compiler, leash, fence and posture. Loopback is delivered before any rule
(rule 10), so a link is two declared lines. Forms gain it too.

**Order**, each phase alone with its check, changing nothing above it:

1. `loopback`.
2. `--with`, `--packages`, `form -o -n`, naming, the APKINDEX, collision
   and memory-sum checks; ad-hoc and kept forms checked identical.
3. leash `root`/`dir`, `write` under a root, init's binds, fence's `/oci`
   exec rule, on a hand-laid tree with a static ELF and a `/bin/sh` that
   must not run.
4. `crane` in `install-deps`; `_unpack` on oci.md's fixtures; a stand-in registry.
5. One image: the checklist, `#!` refused (*docker-entrypoint.sh is a shell
   script; `--with postgresql` runs PostgreSQL without one*), `--NAME.exec`,
   posture's `oci-mount` and `oci-user`.
6. Several: `--link` by port and socket; the mixed check.
7. Docs. Per-service disk limits on `/data` are data.md's proposal.

## Drawbacks

The first build needs the network; hermetic once `form -o` keeps the lock.
Stock images get two refusals, entrypoint and volumes. `--web.secret`
becomes `--db-password` in the kept form; the printed command bridges. A
redeploy is a rebuild. `crane` is one more host dependency, from apko's
toolchain. Loopback TCP cannot name its peer; Landlock's per-uid `connect`
says who may dial, and the socket is there where the peer matters.

## Alternatives Considered

**A compose file**: most of it means nothing here. **A service inferred from
a package**: guessing. **Pull at boot**: oci.md, right for a fleet. **`EXPOSE`
and `VOLUME` as policy** (first draft): the image author authoring binds; a
printed service is not consent when `run` builds as it prints. **A hash as
the name** (first draft): a cache key in the UI. **A flag per concern**: six
grammars for seven leash directives. **Our own host puller**: `crane` and a
pipe replace oci.md's three processes. **Every container reaching every
sibling**: `--link` is one word.

## Security and reliability

The guest trusts what it trusted before: a form directory, leashed services,
one `net`. The operator alone grants, with the closed answer offered first;
what the host resolves once is written down and signed with the image;
untrusted bytes are fetched by a process holding only the registry token and
unpacked by one holding nothing. Same flags, same form, same lock, same
bytes; every collision and unanswered declaration is refused before apko
runs, so a failed build is a line on the host, never a machine with a parked
service. `make check` boots a bundle, a form with packages, one image and two
linked images beside `postgresql`, each also from its kept form.
