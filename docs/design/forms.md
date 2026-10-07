# Forms

Proposed, 2026-10-06. The graph's first step is done: `minimal` and `prod`
have absorbed what they should, and `dhcp`, `cloud`, `bitten`,
`autoupdate`, `disk` and `crypt` are gone. `sshd` and `prod-ssh` wait for
`SSH=1`; the runtime forms are next.

As few forms as will do what most people want, the way Chainguard offers a
handful of images (nginx, node, python, php, the JRE) and a `-dev` variant
of each, but each one a whole machine that is harder to take over than
their containers.

## Why

- **The graph grew by accretion.** Fourteen forms, several of which exist
  only to add one capability to the chain (`dhcp`, `cloud`, `disk`,
  `crypt`, `bitten`), and one, `bitten`, that came to mean two things:
  "boots from slots", which every self-updating machine needs, and
  "installed by bite", which only some are.
- **A chain is linear.** A form includes one other, so capabilities cannot
  be mixed in. Every capability added as a link forces every form above it
  to carry it, and every combination wants its own form (`prod-ssh`,
  `sshd`, `lima`).
- **People pick a runtime, not a capability.** "An nginx machine", "a
  Python machine", "PostgreSQL" is how a choice starts.

## The graph

```
minimal ──→ prod ──┬──→ nginx ──→ php
                   ├──→ node
                   ├──→ python
                   ├──→ jre
                   └──→ postgresql ──→ demo
qemu-host (on prod, allows kvm)
lima      (on prod, the Lima test vehicle)
```

| Form | Is | Absorbs |
| --- | --- | --- |
| `minimal` | boots anywhere: directly, from a native disk, or from slots bite installed; a static address; listens on nothing | `bitten`: slots, `blkid`, `bite-cleanup`, and the ext4, xfs, btrfs and FAT modules |
| `prod` | the production base: DHCP, the cloud's metadata, updates itself, `/data` on a disk, in LUKS when the config brings `data.key` | `dhcp`, `cloud`, `autoupdate`, `disk`, `crypt` |
| `nginx`, `node`, `python`, `jre`, `php` | `prod` and one runtime, with a leashed service for the application | |
| `postgresql` | `prod` and PostgreSQL 17 on a UNIX socket ([postgresql.md](../postgresql.md)) | |
| `demo` | `postgresql`, nginx and the status page ([demo.md](../demo.md)) | |

The forms that go: `dhcp`, `cloud`, `bitten`, `autoupdate`, `disk`,
`crypt` (gone), and `sshd`, `prod-ssh` (once `SSH=1` is built). Their checks
became checks of what absorbed them.

### Slots in minimal

Every image boots the same way already: stage0, then `root.erofs` from a
slot or from the initramfs. What made `bitten` necessary is only what it
carried: `blkid`, `bite-cleanup`, and filesystem modules. In `minimal`, any
image can go on a native disk (`make disk`) or be installed by bite, and no
form is "the bitten one".

Every boot loads the filesystem modules, ext4, xfs, btrfs and FAT, as
`bitten` did; loop, dm-verity and erofs too, since a direct boot needs
them. Loading only the slots' own filesystem is an open question, below.

`bite-cleanup` on a machine that was never bitten has no distro to remove,
and refuses.

### /data in prod

`prod` carries `mke2fs` and `cryptsetup`, so having the tools can no longer
mean wanting a disk. The kernel command line says whether there is one
(`werewolf.data`), and the config whether it is encrypted (`data.key`);
without `werewolf.data`, `/data` is RAM. A disk is used only where one is
asked for, and one that is slow to appear never quietly becomes RAM
([data.md](../data.md)).

### The build flags

What used to be forms of their own becomes a flag on any form, as
Chainguard's `-dev` is a variant of every image:

| Flag | Adds | Retires |
| --- | --- | --- |
| `SSH=1` | OpenSSH, and busybox for the shell a login needs | `sshd`, `prod-ssh` |
| `DEV=1` | busybox, and the debug shell on the console (`werewolf.debug=1`) | (exists today) |

Each builds the form with its own lock and output directory, as `DEV=1`
does now, so `make FORM=python SSH=1` is the Python machine with ssh, and
a release can publish `prod` and `prod-ssh` from one form.

A release built with `SSH=1` is named for its form and `-ssh`, as
`prod-ssh` is today, and its build record names that published form. So a
machine in the field keeps its release's URL and the updater keeps
following the same manifests.

## The runtime forms

Each is `prod`, one Wolfi runtime package, and a leash service (`app`)
that runs the application as a user of its own:

| Form | Package | The service runs |
| --- | --- | --- |
| `nginx` | `nginx-mainline` | nginx, serving `/data/svc/nginx/www`, configured from the config |
| `php` | nginx's, and `php-8.4-fpm` | nginx, and php-fpm on a UNIX socket |
| `node` | `nodejs-22` | `node` on the application |
| `python` | `python-3.13` | `python3` on the application |
| `jre` | `openjdk-21-jre` | `java -jar` on the application |

Where they are still more secure than a container running the same
runtime: the root is read-only and verified; there is no shell or package
manager; the application is leashed (Landlock to its own directories and
declared ports, no capabilities); fence decides what may leave the
machine; and posture says so at every boot.

**An interpreter is the point of these forms.** posture's
`programs-no-interpreters` fails on them by design, as `kernel-no-hypervisor`
fails on `qemu-host`. They are listed in test/posture-known for those forms,
and the page says the form allows it, as it does for `kvm`.

## Applications

An application is baked into the image, as Chainguard's are built with
apko: a form of the user's own includes a runtime form, lists the Wolfi
packages it needs, and carries the application's files and its leash
`service` file in its folder.

```yaml
# forms/myapp.yaml
include: python.yaml
contents:
  packages: [py3.13-flask]
```

So the application is code in the verified, read-only root, built,
signed, updated and rolled back with the rest. Nothing fetches code at
boot, and nothing writable runs. What changes per machine is config,
small, in `/run/config/NAME`; what the application keeps is data, in
`/data/svc/NAME`. A `wordpress` form on `php` is the worked example:
WordPress and its plugins in the image, uploads on `/data`, its own file
writes off (`DISALLOW_FILE_MODS`), and SQLite rather than a second
database server.

Forms outside this repository build the same way
(`make FORM=../myapp/myapp.yaml`).

## Checks

Every `prod` machine updates itself, and so tries to replace its slot as
soon as it has kept one. A check that boots `prod` more than once gives it
no network (or a restricted one), so no slot b appears mid-check: what is
one check's precaution today becomes every `prod` check's.

Coverage follows configurations, not forms. Once `prod` absorbs `disk`,
`crypt`, `dhcp` and `cloud`, `prod` is booted in each configuration that
used to be a form of its own: `/data` on a plain disk (the first boot
formats it, the second keeps it), in LUKS from `data.key`, with no disk
(`/data` in RAM), a static address and a DHCP lease, and each cloud's
metadata. The Makefile and [testing.md](../testing.md) list that matrix.

Not every form is built with every flag. `DEV=1` goes on every form, since
the shell checks need it; `SSH=1` on `prod`, `lima` and bite's default,
where the ssh login checks run; and every release form also boots as it
ships, with no shell, judged by its console. test/posture-known keys its
lines by form, as now, plus `dev` and `ssh` lines that add their failures,
as the architecture lines do, so `prod` with both flags expects the union.

bite installs `prod` with `SSH=1` by default (`make bite-me` today defaults
to `prod-ssh`).

## Open questions

- **Only the slots' filesystem module.** stage0 reads the slots'
  filesystem's superblock, so it could load just that module (ext4, xfs or
  btrfs), and FAT only with `werewolf.esp`. But the disk drivers must be
  loaded before a superblock can be read, and modload closes the loader in
  the one run it gets. Choosing means opening the loader twice, which gives
  up the run-once design; until a way keeps it, every boot loads all four.

- **`/run/config/NAME`.** leash's design gives each service its part of the
  config; it is not built yet, and the runtime forms need it.
- **Which forms are published.** Today `minimal`, `prod` and `prod-ssh`.
  With the runtime forms, perhaps all of them, each with `SSH=1`.

## Work, and who

| Who | What |
| --- | --- |
| this session | the forms themselves (the yaml, folders and modules moving into `minimal` and `prod`), stage0 loading only the slots' filesystem module (with postdoc-79, whose dm-verity work changes stage0's mount), leash's `/run/config/NAME`, the runtime forms' services, the docs |
| werewolf-21 | the checks: one per remaining form, check-slot and check-persist without `bitten`, test/posture-known, bite's default form, lima |
| postdoc-79 | `SSH=1` beside `DEV=1` in the Makefile, the release forms and their names, the updater following a published form, CI |

Order: the graph first (minimal and prod absorb, the retired forms go, the
checks follow: done), then `SSH=1` and releases, then the runtime forms one at a
time, each with its check.
