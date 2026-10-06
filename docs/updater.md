# The updater

`/usr/lib/werewolf/slot-update` keeps a machine booted from a slot current. On a
form CI publishes (`prod`, `prod-ssh`), it installs the latest signed
release of that form ([Releases](#releases)). On any other, it asks Wolfi
and Alpine for anything newer than the running image and builds the other
slot from it. Either way it boots that slot once, and records what changed
and which CVEs that fixes.

It is one Zig program, `cmd/slot-update/slot-update.zig` with `cmd/slot-update/release.zig` (a
release's manifest and signature), `cmd/slot-update/cve.zig` (the CVE children and
the checks of what they say) and `updater/sandbox.zig`, in the
`autoupdate` form.

## Running

```
update check      build and boot the other slot if anything is newer
update outcome    after a reboot, log whether the last update held
```

The `autoupdate` service waits for the running slot to commit, runs
`outcome` once, then `check` at once and every 20 hours. A failed check is
logged and tried again 20 hours later.

The machine must be booted from a slot: the kernel command line names
`werewolf.slot`, `werewolf.victim` and `werewolf.grubenv`. Elsewhere the
service stays down.

## What a check does

| Step | |
| --- | --- |
| `userland` | Fetch, as `_update`, the indexes and packages for the image's `/etc/apk/world`, from its own repositories; then, as root and offline, `apk add --initdb` them into a new root, verified with its own keys ([Separation](#separation)). |
| `kernel` | The same for `linux-virt` from Alpine, verified with `/etc/werewolf/alpine-keys`. |
| `compare` | Diff the new root's installed packages and kernel against the running image's. No difference: log `check` and stop. A build that rolled back before: log `skip` and stop. |
| `cves` | Fetch the CVE sources and find what the update fixes (below), in children of their own ([Separation](#separation)). |
| `root` | Add busybox's links, copy werewolf's own files forward, clear setuid and setgid bits, run `mkfs.erofs`. |
| `vmlinuz` | Unwrap Alpine's arm64 EFI zboot image to the raw `Image`. |
| `stage0` | Build stage0 from its packages, `init` and the form's modules, as a newc cpio compressed with `zstd`. |
| `install` | Mount the victim's filesystem and GRUB's apart, copy the slot in, `sync`, write `attempt`, set GRUB's `next_entry`. |
| `report` | Write the report; log `update`. |
| `reboot` | Reboot cleanly. |

The slot keeps itself or not: `slot-keep` makes it GRUB's default once it is
healthy, and anything else ends on the previous slot ([bite.md](bite.md#slots)).
After the reboot, `outcome` compares the running slot with `attempt` and
logs `commit` or `rollback`. A rolled-back build's hash goes in `bad`.

The build hash is the first 16 hex digits of the sha256 of the new package
list and kernel. The same inputs give the same hash.

## Releases

A form built as it ships for release (`RELEASE_FORMS` in the Makefile, not
a `DEV=1` build) carries two more files in its build record:
`/usr/share/werewolf/releases`, where its releases are (the latest GitHub
release's downloads), and `/usr/share/werewolf/image.pub`, the public half
of the image key CI signs manifests with ([releases.md](releases.md)). With
them, a check, instead of `userland`, `kernel` and `root`:

| Step | |
| --- | --- |
| `release` | Fetch `FORM-ARCH.json` and its `.sig`, as `_update`. Believe nothing in them until the signature checks against `image.pub`: RSA PKCS#1 v1.5 over SHA-256, checked by Zig's standard library. Then refuse a manifest of another format, form or architecture; one past its `expires` (logged `skip`, "expired"), since CI re-signs daily and a frozen mirror must not hold a machine back in silence; and one signed more than a day in the future. No release of the form yet (404): `skip`. |
| `compare` | This slot is the release if its root image's sha256 and kernel are the manifest's: `check`, `current`. A release no newer, by `serial`, than the last one that committed: `skip`. A `build` that rolled back before: `skip`. |
| `fetch` | Fetch the slot's three files as `_update`, each checked against the manifest's size and sha256, into the slot as a built one would be: `vmlinuz`, `stage0.zst` as `initramfs.zst`, `root.erofs`. |

The CVEs, the install, the report and the reboot are as for a built slot;
the package changes are the manifest's `packages` against the running
image's. When the slot commits, `outcome` keeps the release's `serial` in
`serial`.

A machine that follows releases runs exactly what CI built, tested and
signed: werewolf's own programs update with it, which a built slot cannot
do. Until our kernel and IPE (docs/design/verified-boot.md, phase 4), the
signature guards against a bad mirror, not against root on the machine.

## Trust

apk fetches every package, checks every signature and compares every
version. The updater decides nothing about trust.

The trust anchors are the Wolfi key apko installed in `/etc/apk/keys` and
the two Alpine keys in `/etc/werewolf/alpine-keys`, which matched byte for
byte at alpinelinux.org and in Alpine's git.

The CVE sources are not signed. They are fetched over TLS, checked against
the system's CA bundle, and inform the report and nothing else. A source
that fails is recorded with its error, and the update goes ahead.

## Separation

Root, which builds and installs the slot, has no network at all: the
form's policy (`forms/autoupdate.net`) lets only `_update` (uid 69) send,
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
unread. Root's apk installs from it with `--no-network`, checking every
index signature and package hash against root's keys, as it always
does: the child decides nothing about trust, and a compromised one can
only withhold packages. Last, root prunes the cache to the packages the
new root took.

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
build; those read only what root has checked or made.

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
    log                 one JSON line per event
    reports/TIME-BUILD.json
    serial              the last release that committed, when following
                        releases
    attempt             "SLOT BUILD" of the update awaiting its outcome
    bad                 builds that rolled back, one per line
    cache/              apk's downloads, one directory per root built
                        (root, kernel, stage0), holding what the last
                        check installed and nothing older; root's, lent
                        to _update while it fetches
    work/               the build, deleted when done
        apk-NAME/       apk's scratch root while _update fetches
        net/etc/        the CVE fetcher's root: resolv.conf and hosts
        cves/           the CVE sources as fetched, root's, mode 0600
```

The updater reads `/proc/cmdline`, `/etc/apk/` and the
build record in `/usr/share/werewolf/`: `form`, `release`, `kernel`,
`alpine`, `overlay`, `modules`, `stage0.world`, `stage0.init`.

## Events

Every line has `time` (RFC 3339, UTC), `host` and `event`.

| Event | Fields |
| --- | --- |
| `check` | `slot`, `release`, `result` |
| `update` | `from`, `to`, `build`, `kernel`, `packages` (count), `cves` (count), `report` |
| `commit` | `slot`, `build`, `release` |
| `rollback` | `failed`, `running`, `build`, `release` |
| `skip` | `build`, `reason` |
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
make FORM=autoupdate slot        # builds the updater for ARCH, and the slot
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

- werewolf's own files (`init`, the run scripts, `bite`, the updater) are
  copied forward, so they change only with a new image.
- An update needs the network: Wolfi, Alpine and git.kernel.org.
- The kernel CVE list is what the CNA had published at update time.
