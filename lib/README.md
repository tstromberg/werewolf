# lib

Shared Zig code for werewolf's programs, the build tools in `tools/` and
the host CLI, `howl`. Each file is one library, imported by name. A rule
two programs must agree on, such as how a service file is read, lives
here once, so what one program accepts every program accepts. The
confinement rules are in [docs/programs.md](../docs/programs.md).

## sandbox

Drops a program's privileges: closes inherited descriptors, switches user
and chroot, empties the capability bounding set or keeps a few with
securebits locked, sets limits, and applies Landlock and a seccomp
allowlist that kills on anything else. It also reads a child's output
within a byte limit and a deadline. Used by most programs in `cmd/`.

- The kernel clears the parent-death signal on a credential change, so
  `dropTo` and `keepOnly` set it again, and exit if the parent died.
- `dropTo` clears the capability sets after `setresuid`, since under
  NO_SETUID_FIXUP the uid change alone would keep them, then checks that
  uid 0 cannot be regained.
- Landlock rights are masked to the kernel's ABI. An old kernel leaves
  ports (before ABI 4) and scoping (before ABI 6) unrestricted;
  werewolf's kernel has both.

## seal

Maps pledge-style promises (`stdio`, `inet`, `exec`, ...) to the system
calls each allows, on both architectures, and builds the seccomp filters.
init installs the machine seal, which allows the union of every promise
the machine makes and hands other calls to seal-watch; leash installs a
per-service filter that fails other calls with ENOSYS. seal-watch and
`seal` name a refused call by the promise that would allow it. See
[docs/design/pledge.md](../docs/design/pledge.md).

Measured 2026-10-06 on an Apple M4 Max (20 million `getpid` calls), a call
took 125 ns bare and 150 sealed on werewolf's kernel (Alpine's 6.18), and
115 bare and 132 sealed on Ubuntu 26.04's Linux 7.0, where a one-instruction
filter and 200 comparisons cost the same: verdicts are cached, so the cost
is having a filter at all, not its length.

- One table says which calls a promise brings, for both architectures.
- No promise allows bpf, io_uring, userfaultfd, kexec or keyrings. The
  machine seal also refuses by argument paths that exploited CVEs used:
  unnamed socket families (AF_ALG), TCP_ULP, O_NOTIFICATION_PIPE and
  CPU-time clocks, failing as a kernel without the feature would.
- Any 32-bit or x32 call kills the process.
- Without `exec`, a service may only `execveat` a descriptor: that is
  how leash becomes the service.

## broker

Client for cmd/mount-broker. fence's Landlock domain stops root's programs
from mounting, so slot-update, slot-keep, runit-stage and bite-cleanup ask
the broker for `grub`, `esp`, `victim` or `shutdown`. A mount lasts until
`release` or the asker's exit. Mount points are fixed and checked, so a
fake listener at the socket cannot redirect writes.

## dm

Drives the device mapper through its ioctls, in place of `dmsetup create`
and `cryptsetup close`: stage0 opens the root through dm-verity, and
mount-broker removes /data's LUKS mapping at shutdown.

## verity

Builds the dm-verity hash tree for a root image (format version 1, no
superblock, 4 KiB blocks, SHA-256, levels top first after the data) and
the table stage0 loads. Used by the build (`tools/verity.zig`),
slot-update and stage0. The salt is SHA-256 of the image rather than
random, so the build and the updater make the same tree and builds stay
reproducible. See [docs/design/verified-boot.md](../docs/design/verified-boot.md).

## image

The steps of making a slot that howl's build (`cmd/howl/build.zig`) and,
in time, slot-update share, as functions of bytes rather than paths: the
modules a stage0 loads and `werewolf.modules`, from `modules.dep`, in the
Makefile's order; gunzip; the arm64 zboot unwrap and x86_64's `vmlinux`;
the kernel config's rules (`tools/kernel-config-check.zig`); and
mkfs.erofs's options and the version check that refuses one before 1.9,
which writes empty files from a tar. See
[docs/design/howl-build.md](../docs/design/howl-build.md).

## cmdline

Parses the `werewolf.*` words of the kernel command line for stage0,
init, mount-broker, slot-update, leash, posture and others:

| Word | Meaning |
| --- | --- |
| `ip=CIDR gw=ADDR dns=ADDR` | static network, by lib/network's rules |
| `mac=ADDR` | which NIC, when there are several |
| `data=DEV` | /data's disk, by name in /dev |
| `victim=UUID:/DIR`, `slot=a\|b` | the slots' directory, and this boot's slot; both or neither |
| `grubenv=UUID:/PATH` | GRUB's environment block, after bite |
| `esp=XXXX-XXXX` | the EFI system partition, by FAT serial |
| `root=DEV` | direct boot: the disk holding the image; not with `slot` |
| `deadman=SECONDS` | the deadman's wait, 1 to 600 |
| `seal=learn\|enforce`, `debug=1` | DEV=1 builds only |
| `check=1` | posture's attacks, for tests |

Each word may appear once and must be well formed, or the whole line is
refused: a repeated key or an ambiguous value is a mistake, not a choice.
stage0 reads the line first and panics on a refusal, so every later
program sees a line this accepted.

## network

Parses and checks a static IPv4 network, from the command line or a
config tar's `network` file (the same three words). init reads the file
when the command line has none; iface-up applies it; `howl pack` checks
it with the same code, so what the host packs the machine accepts. Rules:
no leading zeros, a usable host that is not its subnet's network or
broadcast (below /31), and a gateway that is not the address. A gateway
outside the subnet is allowed, as on GCP's /32; iface-up adds a host
route to it.

## form

Reads a form (`forms/NAME`: apko.yaml and form.yaml), resolves its chain
of `base` and `with` forms, and merges their apko configs by the rules of
apko's deprecated `include:`. Used by tools/form.zig, howl and slot-update.
It parses a strict YAML subset (block maps and lists, scalars, `[a, b]`,
comments) and refuses anchors, tags, multi-line scalars and inline maps by
line, rather than read them differently from apko. See
[forms/README.md](../forms/README.md).

## compose

Derives everything an image holds beyond its packages from its chain:
allowances, sshd and bastion files, the accounts init seeds, supervise
links, and the records in /usr/share/werewolf (network policy, promises,
modules, kernel arguments) that init, fence, posture, modload and the
updater read. The build (`build/host/form compose`) and slot-update call
the same function, so a slot built on a machine matches the build's.
It writes only into the two directories it is given: on a machine, a
scratch directory the updater copies in with its own checks, never the
new root, where a package's symlink could redirect a write. See
[docs/design/custom-updates.md](../docs/design/custom-updates.md).

Each image stages its chain (form.yaml, apko.yaml, rootfs) and
posture-known in /usr/share/werewolf, and the updater composes from that.
compose adds apko.yaml's accounts the way apko does: on the build's root it
checks that apko's lines end each account file, in order; on a machine's,
which apk filled, it adds them. It refuses a root holding only some of them,
and a home other than /var/empty or /dev/null, which no machine would make.
`make check-compose` recomposes a built image from what it staged and must
match the build.

A service user that apko.yaml does not declare gets a user and group of
its own, with id `defaultId(name)`: an FNV-1a hash of the name in
[65536, 2^31), so the id is the same on every build and machine and the
service keeps its files on /data. The build fails if two services share a
user, if a default id collides with a declared one, or if a service reads
or writes inside another service's directory whose `share` is strict.

## package

Writes apk packages and the index that vouches for them, as apk-tools 2
reads them, so werewolf's own programs update the way Wolfi's packages do
([docs/design/custom-updates.md](../docs/design/custom-updates.md)). A
package is two gzip members: its control, a tar of `.PKGINFO`, then its
data, a tar of its files, each carrying its SHA-1 in a PAX record.
`.PKGINFO`'s `datahash` is the SHA-256 of the data member, and the index
lists each package with `C:`, the SHA-1 of its control member. An index is
a signature member, added by whoever holds the key, then the member holding
DESCRIPTION and APKINDEX, which is what the signature covers. A member that
another follows is a tar without its end, as abuild writes it, so the
members read as one tar. Nothing records when a package was built, so the
same input gives the same bytes. Packages carry no signature of their own,
as Wolfi's carry none: the index's `C:` vouches for them. slot-update
checks all of this before apk reads a byte (cmd/slot-update/apk.zig), and a
test there runs those checks on what this writes.

## allow

Lists the allowances a form may grant (`kvm`, `nested-kvm`, `netadmin`,
`packet`, `ipv6`, `pty`, `jit`) and the capabilities werewolf takes from
root. Allowances in form.yaml's `allow` accumulate along the chain; the
build writes one empty file each to /etc/werewolf/allow and derives
kernel arguments from them. Nothing reads an allowance from the command
line, config or metadata, which root could rewrite. Used by init, fence,
posture and lib/form. See [docs/design/lockdown.md](../docs/design/lockdown.md).

## sshd

Checks form.yaml's `sshd:` and `bastion:` at build time (via lib/form).

- `sshd:` keywords (sshd_config names, lowercased, joined by `-`) go to
  `sshd_config.d/form.conf`, which sorts before werewolf.conf; sshd uses
  a keyword's first value, so the form wins. The list is closed: no
  keyword names a file or program (AuthorizedKeysCommand, ForceCommand)
  or changes the file's shape (Match, Include). Values cannot hold
  quotes, comments, escapes, `=`, `%` or newlines.
- `bastion: users:` gives each user keys and destinations. Each key gets
  `restrict,port-forwarding` and a permitopen per destination, so it
  reaches only its user's. Keys are bare; the build writes the options.
  Only security keys are accepted unless `sshd:` allows key files.

## service

Parses a service file, `/etc/sv/NAME/service`, for leash (which starts the
service), howl pack (its config and setting flags), `seal` (its pledge)
and compose (the machine's promises). Each reads the whole file the same
way. cmd/leash/README.md documents the lines.

## settings

Checks a service's values from the config tar's settings.json against
the `setting` and `render` lines of its service file, and renders them as
env, json or conf. Declarations come from the verified image; a value can
only fill a declared key with a value of its type, and no type may hold
its format's delimiters, so nothing is quoted. leash, service-config and
howl share it. It also holds the config tar's rules (hostnames, entry
names, data.key length) for init, cloud-metadata and howl pack. See
[docs/design/settings.md](../docs/design/settings.md).

## update-policy

Decides when a staged update boots, and says why in one sentence. Urgent
and High fixes boot within a set time of first being seen; Medium and Low
wait, then boot in the maintenance window. A machine's place in that span
comes from SHA-256 of its id and the build, so a fleet spreads out. A form,
then an operator, may change times and window within limits, never
Urgent's. Times are passed in, so tests need no clock. It also owns the two
time formats: RFC 3339 UTC, and a serial without dashes or colons for git
tags. Used by slot-update, howl and tools/cve-tiers.zig. See
[docs/design/update-policy.md](../docs/design/update-policy.md).

## cve

Parses Wolfi's security.json and the kernel CNA's records (which stable
release fixed a CVE on a branch) for both the tiers feed's writer
(tools/cve-tiers.zig) and slot-update, so machines accept what it signs.

## audit

Talks to the kernel's audit subsystem over netlink. init adds one rule
that logs every refused exec (a missing shell, a dropped program, a path
Landlock denies) and locks audit until reboot; posture checks the lock.
With no audit daemon the kernel prints records to its rate-limited log,
and never blocks a process on a full queue.

## hostkey

Makes an ssh host key once with ssh-keygen, for sshd-start, ssh-host-key
and gitea-init. Both halves are written as KEY.new, synced, and renamed
public half first, so an interrupted boot leaves a whole key or none. A
missing public half is rebuilt from the key.
