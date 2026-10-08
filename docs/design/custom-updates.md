# One updater: apk

Proposed, 2026-10-08.

## Summary

A werewolf image becomes a function of its `/etc/apk/world` and one
deterministic step, `compose`, shared by the build and the updater.
Everything else is a package: Wolfi's, werewolf's programs and forms from a
repository CI signs, and the operator's inputs from one sealed into the
image. Every machine then updates one way, by apk into its other slot;
releases are for fresh installs alone. A machine from `howl create shop
--with cloudflared,bastion --package curl` updates werewolf's programs, its
forms and its packages, where today only the packages move.

## Background

Two paths today ([updater.md](../updater.md)). A form CI publishes fetches
its signed slot whole. Any other form on `prod` reinstalls its world into a
new root each check; what apk installs updates, and the rest is a list of
paths copied forward from the running image (`cmd/slot-update/slot.zig`,
`buildSlot`), frozen until a rebuild: werewolf's programs, the updater among
them; each form's `rootfs/`; what the Makefile derives from the chain
(`meta.stamp`, `ro.stamp`); local melange packages and baked OCI trees. Part
of the image is Makefile logic the machine cannot rerun.

## Goals

- A fix to any werewolf program reaches every machine on `prod` by the
  update policy's tiers, with no rebuild and no operator.
- One update path, one trust path (apk's keys), one test (`check-updater`).
- The machine builds the slot the host would, byte for byte, and CI proves
  it on every change (`make check-compose`).
- The Makefile's `meta` and `ro` shell and awk become one Zig library.

## Non-Goals

What the operator pinned (OCI digests, `--app`, local recipes, bastion
users) changes with a rebuild. No apko or compiler on the machine. A
CI-gated mirror of Wolfi: later (Reliability).

## Detailed design

ChromeOS never composes on the device; Pike wants one builder, not two paths
sharing a shape but not code; de Raadt wants nothing on the machine that
need not be there and every input signed. Ariadne breaks the tie: the world
is the spec and apk the solver; once every input is a package, the same
answer comes out on a host or a machine, so the machine may as well be the
one to ask.

**The image is its world.** The machine above has world `local-shop
werewolf-format=3`. `local-shop` depends on `form-prod`, `form-cloudflared`,
`form-bastion`, `curl` and `werewolf-format=3`; a form on its Wolfi packages
and werewolf programs (`form.yaml`'s `programs` becomes `depends`). apk
refuses what cannot combine at build; apko still builds from a lock.

**werewolf's repository**, published with each release, signed by a new key
(`release/packages.pub`, in every image's `/etc/apk/keys`), on a static host
as the tiers feed is: `werewolf-PROGRAM`, one a program, packed from what
`zig build` makes; `form-NAME`, one a form in `forms/`, its `form.yaml`,
`apko.yaml` and `rootfs/` *staged* under `/usr/share/werewolf/forms/NAME/`,
since two forms in a chain may ship one path (`sshd` and `bastion` both bring
`etc/sv/sshd`) and apk refuses that; and in-tree recipes' packages, built by
CI's melange. Every package carries the release's serial as its version and
`provides: werewolf-format=N`. Nothing is ever deleted.

**The image's repository**, `/usr/share/werewolf/repo`, named by path in
`/etc/apk/repositories`: `local-FORM` for each form outside `forms/`, with
its fragments, `rootfs/`, OCI trees, `--app` and local recipes, its index
signed by a key the build makes and discards. Closed after the build, which
is what pinned means: the one layer that is not a package.

**compose**, `lib/compose.zig`, run by `build/host/form` on the host and
`buildSlot` on the machine. From a root apk filled, it orders the staged
fragments as `lib/form.zig` orders a chain, lays each `rootfs/` on `/` in
that order, later winning, and writes what `meta.stamp` and `ro.stamp` write
today (`net` compiled against the root's accounts, `pledge`, `oci`, `allow`,
`weaknesses`, `modules`, `cmdline`, sshd's `form.conf`, accounts, supervise
links), `prune` last. The updater's `root` step is apk then compose, no list
of paths; `compare` diffs `werewolf-*` versions too, so a release of werewolf
alone is an update.

**One path.** `release.zig`, the manifest `compare`, `meta/releases` and
`check-updater-release` go; `image.pub` leaves the machine, kept for `howl`
to verify a fresh-install download; werewolf's own advisories move into the
tiers feed, already signed. A release is `disk.qcow2` and `initramfs.zst`
from the same apko and compose: a fresh install and a slot a machine builds
from the same lock are one image.

**The format pin** keeps the running updater's compose and the new root's
programs reading the same files. When CI moves to N+1, a machine on N takes
the newest packages still providing N, with Wolfi's current fixes, logs
`held` each check and fails posture's `update-format-held`.

**Phases.** 1: compose replaces `meta.stamp`/`ro.stamp`, byte-identical,
proven by `check-compose`. 2: `werewolf-*` packages, the key, the pin. 3:
`form-*` packages; the overlay list goes. 4: the image's repository;
`buildSlot` copies nothing forward. 5: the release path goes.

## Drawbacks

A second key and a host CI keeps up forever. A compose bug ships to every
machine at once, bounded by one try and rollback. Every machine builds as
root now, `prod` included, trusting signed packages rather than a list of
paths. No `prod` machine runs an image CI booted first.

## Alternatives Considered

**Keep the release path** for `prod`: CI-gated images, one small request a
check. Two code paths, two trust paths and two tests for one result, and the
gating only for the forms CI builds; the tiers already hold Medium and Low
fixes for days, in which CI's hourly `prod` build would have failed.
**Publish instead of build**: `howl release`, the operator's key, the
machine following as `prod` did. A fleet's path, built on this one, later.
**A signed tarball of programs**: not forms or derived files, and a second
verifier. **Upgrade in place**: drift, and verity needs an image built whole.

## Security Considerations

`packages.pub` is as powerful as a Wolfi key: its own key, CI-held; a leak
means a signed malicious `werewolf-init`, with `compare`'s refusal of older
versions and the one-try boot standing. Compose parses signed data as root,
the fragments of packages whose binaries root runs anyway. The image's
repository is trusted as copy-forward is, by dm-verity, now with apk
checking it. The host can withhold or replay, never forge. apk following
package-laid links as root stays the gap it is.

## Reliability Considerations

A deleted package strands every machine resolving through it: CI checks each
published one is still served. Hourly checks fetch three indexes, Wolfi's in
megabytes: the `_update` fetcher asks conditionally and hands apk nothing
unchanged. A held format is loud: `held` each check, a posture weakness.
Should ungated Wolfi prove too fast, the werewolf repository becomes a
CI-tested mirror of the forms' locked packages, Wolfi reached only for
tagged extras (`curl@wolfi`). `check-compose` makes the two builders agree.
