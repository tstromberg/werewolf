# Forms

Proposed, 2026-10-06. Built by 2026-10-08 (forms/, tools/form.zig,
lib/compose.zig), with `sshd` a form taken `with` in place of `SSH=1`.

## Summary

As few forms as do what most people want, as Chainguard offers a handful
of images and a `-dev` variant of each, but each a whole machine harder
to take over than their containers ([docs/forms.md](../forms.md)).

## Background

- **The graph grew by accretion**: fourteen forms, several only to add one
  capability (`dhcp`, `cloud`, `disk`, `crypt`); `bitten` meant both
  "boots from slots" (any machine that updates) and "installed by bite".
- **A chain is linear.** A form has one `base`, so a capability added as a
  link burdens every form above it, and every combination wants a form.
- **People pick a runtime, not a capability**: "a Python machine".

## Goals

- A short list of forms chosen by what they run.
- Any image boots from the initramfs, a native disk or a slot bite
  installed; no form is "the bitten one".
- A capability is a variant or a form taken `with`, never a chain link.

## Non-Goals

- A form for every combination of capabilities.
- An application fetched at boot, or a shell or package manager on board.

## Detailed design

```
minimal ──→ prod ──┬──→ nginx ──→ php
                   ├──→ app ──→ node, python, ruby, jre, examples
                   ├──→ postgresql ──→ demo
                   └──→ service forms: caddy, valkey, gitea, ...
minimal ──→ sshd ──→ qemu-host;   prod with sshd ──→ prod-ssh, lima
```

**`minimal` absorbed `bitten`**: slots, `blkid`, `bite-cleanup` and the
filesystem modules, so any image can go on a native disk or be installed
by bite. xfs, btrfs and FAT load only where stage0 tags the machine
(`@xfs`, `@btrfs`, `@esp` in form.yaml's `modules`), so modload still
runs once. `bite-cleanup` on a machine that was never bitten stops.

**`prod` absorbed** `dhcp`, `cloud`, `autoupdate`, `disk` and `crypt`. It
carries `mke2fs` and `cryptsetup`, so having the tools cannot mean
wanting a disk: the kernel command line says whether there is one
(`werewolf.data`), the config whether it is encrypted (`data.key`), and a
disk slow to appear never quietly becomes RAM ([data.md](../data.md)).

**Variants and bundles.** `DEV=1` adds busybox and the debug shell to any
form, with its own lock and output directory. SSH needed no flag: `sshd`
is a form that `prod-ssh`, `playground` or a form of yours takes `with`.

**Runtime forms** are `prod`, one Wolfi runtime, and a leashed service.
The application is in the image, not on `/data` or in the config: it is
code, so it is verified and rolls back with the rest. An interpreter is
the point of these forms, so each excuses `programs-no-interpreters` in
its `weaknesses`; posture looks for `java` and `php-fpm` too, so what a
form carries, posture reports. A form outside the tree builds the same
way (`make FORM=../myapp`), and `howl --app DIR` needs no form at all.

**Checks follow configurations, not forms.** `prod` boots with `/data` on
a disk, in LUKS2 and in RAM, by static address and DHCP, and on each
cloud's metadata ([testing.md](../testing.md)). A check that boots `prod`
from slots (check-persist, check-dist) gives it no way out, so no slot b
appears mid-check. Every form boots with `DEV=1` and as it ships;
test/posture-known holds what every form of a kind fails.

**Open:** which forms are published. Today `minimal`, `prod` and
`prod-ssh` (lib/compose.zig's `release_forms`); perhaps every runtime form.

## Drawbacks

- `prod` carries `mke2fs` and `cryptsetup`, and every image the slot
  tools, used or not. More is set by the config tar, which pack and the
  guest check value by value.

## Alternatives Considered

**Capability forms in the chain**: every combination becomes a form.
**`SSH=1` beside `DEV=1`**: bundles made `sshd` a form any form can take,
with no second build axis.

## Security Considerations

A runtime form beats a container running the same runtime: a verified
read-only root, no shell or package manager, the application leashed
(Landlock to its own directories and ports, no capabilities), fence
deciding what leaves, posture at every boot. leash clears supplementary
groups, so php-fpm's socket is shared through php's primary group, nginx's.

## Reliability Considerations

Every form boots one way: stage0 opens `root.erofs` through dm-verity.
Coverage follows configurations, so retiring a form lost no check.
