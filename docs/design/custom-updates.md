# One updater: apk

Proposed 2026-10-08. Phases 1 to 3 and the format pin are built.

## Summary

An image becomes its `/etc/apk/world` plus compose, one deterministic step
the build and the updater share. Everything else is a package: Wolfi's,
werewolf's programs and forms from a repository CI signs, and the operator's
inputs from one sealed into the image. Every machine updates one way, by apk
into its other slot, so a `howl create shop --with cloudflared,bastion`
machine updates werewolf's programs and forms too. Releases serve installs.

## Background

A form CI releases fetched its signed slot whole; any other `prod` form
reinstalled its world ([updater.md](../updater.md)) and copied werewolf's
programs forward, so a fix to `fence` reached no `howl`-built machine.

## Goals

- A fix to any werewolf program reaches every `prod` machine within the
  [update policy](update-policy.md)'s tiers, with no rebuild or operator.
- One update path, one trust path (apk's keys), one test (`check-updater`).
- A machine builds the slot the host would, and `make check-compose` proves it.

## Non-Goals

- Updating what the operator pinned (OCI digests, `--app`, local recipes,
  bastion users), or putting apko or a compiler on the machine.
- A CI-gated mirror of Wolfi, for now (see Reliability).

## Detailed design

The world file is the spec and apk is the solver: once every input is a
package, a host and a machine resolve the same answer.

**The image is its world.** The machine above has world `local-shop
werewolf-format3`. `local-shop` depends on `prod-form`, `cloudflared-form`,
`bastion-form` and `curl`; each form depends on its base's, its Wolfi packages
and werewolf programs. apk refuses what cannot combine, at build time.

**werewolf's repository** lives in R2 at
`https://dist.werewolf-linux.org/apk/ARCH/` and is signed by the key in
`release/packages.pub`, installed as `/etc/apk/keys/werewolf-packages.rsa.pub`.
It holds `werewolf-PROGRAM`, packed from Zig's cross-compiled output on any
host (lib/package.zig, `make packages`); `NAME-form`, sorting beside the
package it serves, staging its files under `/usr/share/werewolf/forms/NAME/`
as two forms may ship one path; and in-tree melange recipes' packages. Each
version is its commit's time, so a clean tree packs the same bytes. Every
package depends on `werewolf-formatN`. CI never deletes one.

**The image's own repository** is `/usr/share/werewolf/repo`, tagged `@local`.
It holds `local-FORM` for each form outside `forms/`, with its files, OCI
trees, `--app` and local recipes, signed by a key the build makes and then
discards. apk takes a package from a tagged repository only when world names
it `name@local`, so world lists exactly what will not update.

**What howl builds.** A form named is the published one, fetched with the
forms it names and checked against the signed index (lib/apk.zig), so the
machine updates it. A path is the caller's own, never updated; its names are
published. `--build` takes the tree's forms and programs; phase 4 makes them `@local`.

**compose** (lib/compose.zig; lib/README.md) lays the staged forms and writes
what the chain derives. The updater runs it over the accounts apk laid, from
the forms world names as NAME-form as the new root's packages laid them, and
the image's own copies of the rest, and writes only into scratch.

**One path.** The release path goes: `release.zig`, the manifest compare and
`check-updater-release`. `image.pub` stays with howl, to verify fresh-install
downloads, and werewolf's advisories move into the signed tiers feed.

**The format pin**, a package per format, `werewolf-formatN`, that a published
world names, keeps compose and the programs reading the same files. It holds
a file, as apk fetches no empty package. After CI moves to N+1, a machine on
N takes the newest programs for N and logs `held` each check, until reinstalled.

**Phases.**
1. Built: compose replaces the Makefile's `ro` and `meta` shell, byte-identical.
2. Built: images stage their chain and the updater composes from it; CI
   publishes changed programs, and a published machine took eight.
3. Built: `NAME-form` packages, fetched by name; stage0 is a package. Left:
   no checkout (howl still reads keys, locks and test files from one).
4. The image's repository; `buildSlot` copies nothing forward.
5. The release path goes.

## Drawbacks

CI keeps a second key and a package host forever. A compose bug reaches every
machine at once, bounded by one boot try and rollback. No `prod` machine runs
an image CI booted first.

## Alternatives Considered

- **Keep the release path for `prod`**: CI-gated images, but two code paths,
  trust paths and tests for one result. The tiers already hold Medium and
  Low fixes for days, long enough for CI's hourly build to fail first.
- **Publish instead of build** (`howl release` with the operator's key) suits
  a fleet, and can be built on this design later.
- **A signed tarball of programs** misses the forms; **upgrading in place**
  drifts, and verity needs a whole image.

## Security Considerations

`packages.pub` is as powerful as a Wolfi key: a leak lets the holder ship a
malicious `werewolf-init` to every machine, so its private half lives only in
a CI secret and offline. The updater refuses older versions, and a new slot
boots once before it is kept. compose parses signed data as root, from
packages whose binaries root runs anyway. The image's own repository is
trusted through dm-verity, as copied files are today. The host can withhold
or replay, never forge. apk following package-laid links as root remains a
known gap.

## Reliability Considerations

A removed package would strand every machine that needs it, so CI checks
each published one is still served. Hourly checks fetch three indexes, so the
`_update` fetcher asks conditionally. If ungated Wolfi proves too fast, the
werewolf repository can become a CI-tested mirror of the forms' locked
packages, with Wolfi reached only for tagged extras (`curl@wolfi`).
