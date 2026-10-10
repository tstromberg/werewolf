# The updater

`/usr/lib/werewolf/slot-update` keeps a machine booted from a slot current. It
asks werewolf's repository, Wolfi and Alpine for anything newer than the
running image, builds the other slot from it on the machine (werewolf's
programs and forms are packages: [custom-updates.md](design/custom-updates.md)),
boots that slot once, and records what changed and which CVEs that fixes.
Releases are for installs; every machine updates this one way.

It is one Zig program, `cmd/slot-update/slot-update.zig` with
`cmd/slot-update/cve.zig` (the CVE children and the checks of what they say)
and `lib/sandbox.zig`, in `minimal` and so every form.

## Running

```
update check      build and stage the other slot if anything is newer
update outcome    after a reboot, log whether the last update held
```

The `autoupdate` service waits for the running slot to commit, reads its
settings and logs them (`policy`), runs `outcome` once, then `check` at
once and every hour (a form's `updates:` names another interval with
`every: 30m`, 5m to 7d; `updates: off` leaves the service out of the
image). A check stages what it finds; the service boots a staged slot
when it is due, by how urgent its fixes are, and in between sleeps until
the next check or that time, whichever comes first
([design/update-policy.md](design/update-policy.md)). A failed check is
logged and tried again at the next.

The machine must be booted from a slot: the kernel command line names
`werewolf.slot`, `werewolf.victim`, and `werewolf.grubenv` (bite's GRUB)
or `werewolf.esp` (werewolf's own disk). Elsewhere the
service stays down.

## When an update boots

Each fix takes its tier from the signed CVE tiers feed
([releases.md](releases.md#the-tiers-feed)), or from its advisory for
werewolf's own fixes; a CVE the feed does not name is `medium`, and an
update that fixes none is `low`. With no valid feed, every CVE, or else the
update itself, counts as `high`. A staged slot boots at the soonest time
any of its tiers sets, counted from when this machine first saw a fix of
that tier:

| Tier | Boots | Setting: default, limit |
| --- | --- | --- |
| `urgent` | within 15 minutes | none |
| `high` | within `high` | `4h`, `24h` |
| `medium` | in the first window after `medium` | `7d`, `28d` |
| `low` | in the first window after `low` | `28d`, `90d` |

A machine's place in each span is the first 8 bytes of SHA-256 of the
UUID of the filesystem holding its slots and the build, modulo the span,
so a fleet spreads out and a restart keeps the time.

Two files may change the settings, each one JSON object, read when the
service starts: the form's `/etc/werewolf/update-policy.json`, then the
operator's `update-policy.json` in the config tar (howl's
`--update-policy FILE`, checked by the same code, lib/update-policy.zig).

```json
{"window": "sun,wed 23:00-02:00", "high": "1h", "medium": "14d"}
```

- `window`: `daily` or days (`sun` to `sat`, joined by commas), then UTC
  hours at least an hour apart, which may wrap past midnight. Default
  `daily 02:00-05:00`.
- `high`, `medium`, `low`: a whole number of `m`, `h` or `d`, at most the
  limit. `0d` means the next window.
- `limits`, in the form's file only: `{"high": ..., "medium": ..., "low":
  ...}`, each at most werewolf's. A limit below its time lowers the time.

A file is taken whole or refused whole, naming the key: an unknown or
repeated key, a value of the wrong type or above its limit, or more than
32 KiB. A form's file that is refused, or cannot be read, stops the
operator's too, since its lowered limits are lost with it. `policy` logs
each setting, who set it and its limit, and each refusal. Nothing turns
updates off.

## What a check does

| Step | |
| --- | --- |
| `userland` | Fetch, as `_update`, the indexes and packages for the image's `/etc/apk/world`, from its own repositories; then, as root and offline, `apk add --initdb` them into a new root, verified with its own keys ([Separation](#separation)). |
| `kernel` | The same for `linux-virt` from Alpine, verified with `/etc/werewolf/alpine-keys`. |
| `compare` | Diff the new root's installed packages and kernel against the running image's. No difference: log `check` and stop. A package or the kernel at an older version, in apk's order: log `skip` and stop, since an index carries no date, and an older one, signed, would install as readily as a newer. A build that rolled back before: log `skip` and stop. |
| `cves` | Fetch the CVE sources and find what the update fixes (below), in children of their own ([Separation](#separation)). |
| `compose` | Compose what the forms derive (`lib/compose.zig`), as the build composes it: from the chain, each form world names as `NAME-form` as the new root's package laid it in `/usr/share/werewolf/forms`, and each other (a path the image was built from) as this image staged it, over the account files apk laid, into a scratch directory, which the root then takes in: the forms' files, accounts, network policy, promises, modules, kernel arguments. |
| `root` | Add busybox's links, copy werewolf's programs, the operator's `--app` and the build's other records forward, clear setuid and setgid bits, run `mkfs.erofs`. |
| `verity` | Append the root image's dm-verity hash tree, as the build does (lib/verity.zig), keeping the root hash for stage0. |
| `vmlinuz` | Take Alpine's kernel as it is: on arm64 an EFI zboot image, which systemd-boot runs, and a quarter the size of the `Image` inside it. |
| `stage0` | Build stage0, which has no packages, from `/dev`'s five nodes, `init` and the module loader from the new root (`/usr/lib/werewolf/stage0` and `modload`, so a fix to either arrives with its package), the form's modules in the build's order (`modules`, or `modules-bitten` on a distro's disk; lib/image.zig) and `/verity`, the root hash and salt it opens the root with, as a newc cpio compressed with `zstd`. |
| `install` | Clear GRUB's `next_entry`, so nothing boots the slot while it changes; mount the victim's filesystem and GRUB's apart, copy the slot in, the kernel unwrapped to its `Image` for GRUB, which cannot run zboot, `sync`, set GRUB's `next_entry`, then write `attempt`, so an attempt is on record only for a slot that is armed. On werewolf's own disk, the kernel goes to the EFI partition as it is. |
| `stage` | Fetch the CVE tiers feed and tier the fixes by it, with any of werewolf's own advisories the new slot lists (`werewolf-advisories`) and this image lacks; keep in `pending` when this machine first saw each tier, and work out when the slot is due. A build already staged stops here: its fixes are tiered again against the latest feed, and it is logged as `check`, `staged`, with when it is due. |
| `report` | Write the report, with the update's tier and why it boots when it does; log `stage`. |

When the staged slot is due, the service logs `reboot` and reboots cleanly.
On the machine's first check, ever, that is within two minutes; otherwise
at the soonest of each tier's time, and never within an hour of boot.
Any reboot before then boots the staged slot too: its one try is set.

The slot keeps itself or not: `slot-keep` makes it GRUB's default once it is
healthy, and anything else ends on the previous slot ([bite.md](bite.md#slots)).
Healthy includes the updater: once its setup succeeds it writes
`/run/werewolf/updater-ready`, and `slot-keep` keeps no slot without it, so
a slot whose updater cannot run, the one failure no later update could
undo, rolls back.
After the reboot, `outcome` compares the running slot with `attempt` and
logs `commit` or `rollback`. A rolled-back build's hash goes in `bad`.
`attempt` names the boot that armed the slot, too (the kernel's
`boot_id`): until the machine has rebooted, `outcome` judges nothing, so
the service starting again over a staged slot is no rollback. A staged
slot counts only while it is armed, its `attempt` this boot's; the service
reboots for nothing else.

A check runs only once this slot has committed, since until then the other
slot is the one to fall back to; and `check`, `outcome` and the reboot
each hold `lock`, so a check run by hand and the service's never meet.

`build` names what a slot holds, in the log, the reports, `attempt`,
`pending` and `bad`: 16 hex digits, the same for the same slot, the first
16 hex digits of the sha256 of its package list and kernel.

## Trust

apk fetches every package; root checks every signature and hash before
apk reads one, and apk checks them again and compares every version. The
updater decides nothing about trust: the keys do.

The trust anchors are the Wolfi key apko installed in `/etc/apk/keys` and
the two Alpine keys in `/etc/werewolf/alpine-keys`, which matched byte for
byte at alpinelinux.org and in Alpine's git.

The CVE sources are not signed. They are fetched over TLS, checked against
the system's CA bundle, and inform the report and nothing else. A source
that fails is recorded with its error, and the update goes ahead.

## Separation

Root, which builds and installs the slot, has no network at all: the
form's policy (`forms/minimal/form.yaml`) lets only `_update` (uid 69) send,
and only HTTPS and DNS. Everything the updater takes from the network is
fetched by children running as `_update`, as werewolf's programs are
written ([programs.md](programs.md)).

**Packages.** For each root it builds (the userland, the kernel,
stage0), a child runs apk's network half: `apk update`, then `apk cache
download`, into that root's cache, against a scratch root of its own
that holds only the package names and an empty database. It is
`_update`, with no capabilities and no_new_privs, every descriptor of
root's closed, and apk's output on a pipe to root. Landlock lets it read
`/usr`, `/etc` and the resolver's file, execute only apk and its loader,
write only the cache and its scratch root, and connect over TCP only to
443 and 53. A seccomp filter allows the calls apk makes to fetch, as
traced; `ioctl` only for FIONREAD and isatty; sockets only for IP; no
fork or clone at all; and fails `mount`, which apk tries in its root,
with EPERM. Then root takes the cache back: the directory and every file
become root's, and anything that is not a regular file with a name apk
gives its cache (`APKINDEX.*.tar.gz`, `*.apk`, `installed`) is removed
unread. Before its apk reads a byte, root checks the cache itself
(`cmd/slot-update/apk.zig`): each index's signature against the root's
keys (`.SIGN.RSA256` is SHA-256, Alpine's `.SIGN.RSA` SHA-1), each
package's control segment against the SHA-1 its index lists (`C:`), and
the rest against the SHA-256 that control names (`datahash`). A package
no index lists is removed; one that does not match fails the pass, and is
removed for the next to fetch again. Root writes each index's signature
segment anew and drops Alpine's package signatures, which the index
vouches for, so apk installs them as it does Wolfi's, which carry none.
Root's apk then installs with `--no-network`, checking the same again:
the child decides nothing about trust, and a compromised one can
withhold packages, or offer an older index, which `compare` refuses. Its
files are capped at 1 GiB each. Last, root prunes the cache to the
packages the new root took.

**CVE sources.** These are the one input the updater parses itself, 40
MB of JSON from outside, so root does not touch them. Each goes through
two children:

| | Runs as | Can | Cannot |
| --- | --- | --- | --- |
| fetcher | `_update` (uid 69), chrooted to `work/net`, which holds copies of `resolv.conf` and `hosts` and nothing else | resolve names; connect over TCP to ports 443 and 53 (Landlock), as `fence` allows `_update`; write the body to the one file root opened for it, at most 256 MB | read any other file, bind a TCP port, write anywhere else, make any system call TLS and DNS do not need (seccomp, traced) |
| reader | `_update`, chrooted to the empty `/var/empty` | read the fetched file, through the descriptor it was handed; write lines to root; map at most 1 GB | open any file, make a socket, make any call but `pread64`, `write` to its pipe, and memory's (seccomp) |

Both have no capabilities and an empty bounding set, no_new_privs, every
descriptor of root's closed but theirs, and stdin, stdout and stderr on
`/dev/null`; both die with root. The fetcher has 10 minutes and the
reader 5, after which root kills them.

The reader sends back a status line and then one line per CVE: `INDEX
FIXED CVE` for a package (`INDEX` into the origins root asked about), `CVE
FIXED TITLE` for the kernel. Root checks every field again: the CVE id's
form, the origin, the version inside that origin's window in apk's order,
the kernel version on the branch and in its range, a title of printable
UTF-8 under 512 bytes. A single line that fails means the reader is not
believed at all, and the source is recorded with the error `BadLine`. A
compromised reader can therefore leave out CVEs, or name ones the source
does not, but only inside the windows root would accept anyway; it cannot
reach the network, the disk, or root.

Root hashes the file for the report's `sources`, and never parses it.

All of it has run end to end, a whole update from fetch to reboot, on
aarch64 (HVF) and on x86_64 (QEMU's emulator, which enforces the same
seccomp filters); x86_64 alone needed `arch_prctl`, which glibc calls to
set up thread-local storage.

The source's `error` says what happened to a child: its own word
(`not_found`, `TlsInitializationFailed`, ...), or root's: `Timeout`,
`ChildKilled` (by seccomp, or a limit), `ChildFailed`,
`ChildSaidTooMuch`, `ChildSaidNonsense`, `BadLine`.

Root still runs apk, offline, to install, and `mkfs.erofs` and `zstd` to
build, each by its full path, each killed if it runs 30 minutes. They read
only what root made or checked. Root writes into the roots it builds
through `openat2` with `RESOLVE_IN_ROOT`: a link a package laid resolves
as it would on the slot, within the root, never into the running system.

## CVEs

**Packages.** Wolfi's `security.json` lists, per source package, the
version that fixed each CVE. A CVE counts when that version is newer than
the old one and no newer than the new one, in apk's order. That order is
apk-tools 2.14's, ported to Zig so the reader need run nothing, and checked
against `apk version -t` on 3,000 pairs of the file's own versions. Version `0` means never affected, and is skipped. A versioned stream
(`openssl-4.0`) is also looked up under its base name (`openssl`); the
version window keeps the other streams' fixes out.

**Kernel.** The Linux kernel CNA's records come from git.kernel.org as one
33 MB tarball, fetched only when the kernel changes and read as a stream. A
record counts when it has an entry `unaffected`, `semver`, `lessThanOrEqual`
the running branch (`6.18.*`), at a version in the update's range. Records
often appear weeks after a fix ships: the report lists what was known when
it was written. Alpine's own patches on top of upstream are not counted.

## Files

```
/data/svc/autoupdate/
    log                 one JSON line per event, never pruned (hourly
                        checks come to about 2 MB a year)
    reports/TIME-BUILD.json
                        one per update staged, the newest 500 kept
    attempt             "SLOT BUILD BOOT" of the slot armed to boot once,
                        and the boot that armed it
    lock                held while a check, outcome or reboot runs
    pending             the staged slot: its build, and for each tier of
                        its fixes when this machine first saw one
    rebooted            when the updater last rebooted, RFC 3339, for
                        `down`
    cve-tiers.json      the last CVE tiers feed this machine took, and
    cve-tiers.json.sig  its signature, checked again whenever it is read
    cve-tiers.json.serial
                        the newest feed serial taken: none older is, even
                        once the kept feed has expired
    bad                 builds that rolled back, one per line
    checked             exists once a check has finished; until then
                        what a check stages boots within two minutes
    cache/              apk's downloads, one directory per root built
                        (root, kernel, stage0), holding what the last
                        good check installed; root's, lent to _update
                        while it fetches
    work/               the build, deleted when done
        apk-NAME/       apk's scratch root while _update fetches
        net/etc/        the CVE fetcher's root: resolv.conf and hosts
        cves/           the CVE sources as fetched, root's, mode 0600
```

The updater reads `/proc/cmdline`, `/etc/apk/` and the
build record in `/usr/share/werewolf/`: `form`, `release`, `kernel`,
`alpine`, `overlay`, `modules`, `modules-bitten`, `tiers`,
`tiers.pub` and `advisories`.

## Events

Every line has `time` (RFC 3339, UTC), `host`, `seq`, `prev` and `event`.
`seq` counts on from the line before; `prev` is the first 16 hex digits of
that line's SHA-256, so a line edited or removed breaks the chain from
there ([design/update-policy.md](design/update-policy.md#the-audit-log)).

| Event | Fields |
| --- | --- |
| `policy` | `settings` (each one's `value`, `source` and `limit`), `refused` (each file refused, with `key` and `why`) |
| `check` | `slot`, `release`, `result`; when `staged`: `build`, `tier`, `due`, `due_in` |
| `stage` | `slot`, `from`, `build`, `kernel`, `packages` (count), `cves` (count), `tier`, `seen` (per tier), `fixes` (count per tier), `due`, `due_in` (seconds), `why`, `report` |
| `reboot` | `build`, `tier`, `cause` (`due` or `first-boot`), `due`, `late` (seconds), `why` |
| `feed` | `serial`, `expires`, `result` (`ok`, `unchanged`, `kept`: the feed kept from before, as a new one could not be had or did not check; `none`), `reason`, and with `none`, `consequence` |
| `tier` | `build`, `fix`, `cause` (the evidence), `feed` (its serial), `from`, `to`, `was_due`, `due`, `due_in`, `why`: a staged fix's tier rose |
| `commit` | `slot`, `build`, `release`, `waited` (per tier: `seen`, and the seconds from then to the commit), `down` (seconds from the update's reboot to this boot's kernel start, or null) |
| `rollback` | `failed`, `running`, `build`, `release`, `down` |
| `skip` | `build`, `reason` |
| `held` | `format` (the N of the `werewolf-formatN` world names), `offered` (the newest format the repository has), `why`: the machine takes only programs for its format |
| `error` | `step`, `error`, `detail` (what the failed command said) |

## Report

An example, abridged:

```json
{
  "time": "2026-10-06T13:42:36Z",
  "host": "example",
  "build": "0123456789abcdef",
  "from": { "slot": "a", "release": "...", "kernel": "linux-virt-6.18.54-r0" },
  "to": { "slot": "b", "kernel": "linux-virt-6.18.55-r0" },
  "packages": [ { "name": "busybox-full", "from": "1.37.0-r30", "to": "1.38.0-r2" } ],
  "package_cves": [ { "origin": "busybox", "from": "1.37.0-r30", "to": "1.38.0-r2", "cves": ["CVE-2024-58251"] } ],
  "kernel_cves": {
    "branch": "6.18", "from": "linux-virt-6.18.54-r0", "to": "linux-virt-6.18.55-r0",
    "cves": [ { "id": "CVE-2026-52988", "fixed_in": "6.18.55", "title": "netfilter: ..." } ]
  },
  "sources": [
    { "url": "https://packages.wolfi.dev/os/security.json", "fetched": "...", "sha256": "...", "error": null },
    { "url": "https://git.kernel.org/.../vulns-master.tar.gz", "fetched": "...", "sha256": "...", "error": null }
  ]
}
```

In `packages`, `from` is null for an added package and `to` for a removed
one. `kernel_cves` is empty when the kernel did not change. To check a
report, fetch the sources, compare their sha256, and apply the rules above.

## Design

The program is small and does one pass. It favours what cannot go wrong:

- **Memory.** Everything comes from the process arena and is freed at exit,
  so nothing is used after it is freed. The kernel's 17,000 records are each
  parsed, by the reader, in a scratch arena reset between them.
- **Safety checks.** Built ReleaseSafe: an out-of-bounds index or an
  overflow stops the program instead of corrupting it.
- **Other programs** do what they do best: `apk`, `mkfs.erofs`, `zstd`,
  `blkid`, `mount`, `umount`, `sync`, `/usr/lib/werewolf/grub-setenv` (which
  `slot-keep` shares), `/usr/bin/reboot`. Everything else is Zig's standard
  library.
- **Errors** end the run. The `error` event names the step and what the
  failed command said; the work directory is removed, and mounts are undone.

## Building and testing

```sh
make test                        # zig fmt --check, and the unit tests
make FORM=prod slot              # builds the updater for ARCH, and the slot
```

The Makefile builds it with `zig build-exe -O ReleaseSafe -fstrip -target
ARCH-linux-musl`: 1.1 MB on arm64, 1.3 MB on x86_64, static. It refuses any
Zig but 0.17.0, since Zig changes between releases.

The unit tests cover the pure parts: the kernel command line, package
databases and their diffs, stream base names, apk's version order (each
case as apk answered it), kernel versions, the kernel CVE window,
`security.json` parsing, the readers' lines and root's checks of them,
lying readers included, the seccomp filter's jumps, module order, cpio
entries (device nodes included), zboot unwrapping and timestamps.

To exercise a whole update, build a slot whose build record claims an older
kernel, bite a VM with it, and power-cycle it:

```sh
make FORM=lima slot
echo linux-virt-6.18.54-r0 > build/aarch64/lima/meta/usr/share/werewolf/kernel
rm build/aarch64/lima/overlay.tar build/aarch64/lima/slot/root.erofs && make FORM=lima slot
```

The machine will find Alpine's current kernel newer, build and boot slot
`b`, commit it, and log the kernel's fixed CVEs.

## Limits

- werewolf's programs (`init`, `fence`, the updater) are copied forward,
  and its forms are the ones the image stages, so both change only with a
  new image; what the forms derive is composed again at each update
  ([custom-updates.md](design/custom-updates.md)).
- An update needs the network: Wolfi, Alpine and git.kernel.org.
- The kernel CVE list is what the CNA had published at update time.
