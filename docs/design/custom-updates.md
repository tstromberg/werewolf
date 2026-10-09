# One updater: apk

Proposed 2026-10-08. Phases 1 and 2a are built; 2b is in progress.

## Summary

An image becomes its `/etc/apk/world` plus compose, one deterministic step
the build and the updater share. Everything else is a package: Wolfi's,
werewolf's programs and forms from a repository CI signs, and the operator's
inputs from one sealed into the image. Every machine updates one way, by apk
into its other slot, so a `howl create shop --with cloudflared,bastion`
machine updates werewolf's programs and forms too. Releases serve installs.

## Background

A form CI publishes fetches its signed slot whole; any other `prod` form
reinstalls its world ([updater.md](../updater.md)) and copies werewolf's
programs forward, so a fix to `fence` or the updater reaches no `howl`-built
machine until someone rebuilds it.

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

The world file is the spec and apk is the solver. Once every input is a
package, a host and a machine resolve the same answer, so a machine can
build its own slot.

**The image is its world.** The machine above has world `local-shop
werewolf-format=3`. `local-shop` depends on `form-prod`, `form-cloudflared`,
`form-bastion` and `curl`; each form depends on its Wolfi packages and
werewolf programs. apk refuses what cannot combine, at build time.

**werewolf's repository** lives in R2 at
`https://dist.werewolf-linux.org/apk/ARCH/` and is signed by the key in
`release/packages.pub`, which images install as
`/etc/apk/keys/werewolf-packages.rsa.pub`. It holds `werewolf-PROGRAM`, one
package per program, packed from Zig's cross-compiled output on any host
without a VM (lib/package.zig, `make packages`); `form-NAME`, one per form,
staging its files under `/usr/share/werewolf/forms/NAME/` because two forms
may ship the same path; and packages from in-tree melange recipes. Each
version is its commit's time, so a clean tree packs the same bytes. Every
package provides `werewolf-format=N`. CI never deletes a published package.

**The image's own repository** is `/usr/share/werewolf/repo`, tagged `@local`.
It holds `local-FORM` for each form outside `forms/`, with its files, OCI
trees, `--app` and local recipes, signed by a key the build makes and then
discards. apk takes a package from a tagged repository only when world names
it `name@local`, so world lists exactly what will not update.

**What howl builds.** howl takes werewolf's programs and forms from the
repository, so any machine it makes updates. `--build` packs the tree's own
as `@local`, pinning only those whose bytes differ from the published ones.

**compose** (lib/compose.zig; lib/README.md) lays the staged forms and writes
what the chain derives. The updater runs it from the running image's staged
chain over the accounts apk laid, and writes only into scratch.

**One path.** The release path goes: `release.zig`, the manifest compare and
`check-updater-release`. `image.pub` stays with howl, to verify fresh-install
downloads, and werewolf's advisories move into the signed tiers feed.

**The format pin** keeps compose and the programs reading the same files.
After CI moves to format N+1, a machine on N takes the newest packages that
provide N, logs `held` each check, and fails posture's `update-format-held`.

**Phases.**
1. Built: compose replaces the Makefile's `ro` and `meta` shell, byte-identical.
2. 2a, built: images stage their chain and the updater composes from it.
   2b, in progress: the packer, the key and R2 exist; next, images install
   `werewolf-*`, then CI signs and uploads.
3. `form-*` packages; the overlay list goes.
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
