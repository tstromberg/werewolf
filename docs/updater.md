# The updater

`/usr/lib/werewolf/update` keeps a machine booted from a slot current. It
asks Wolfi and Alpine for anything newer than the running image, builds the
other slot from it, boots that slot once, and records what changed and which
CVEs that fixes.

It is one Zig program, `updater/update.zig`, in the `autoupdate` form.

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
| `userland` | `apk add --initdb` the image's `/etc/apk/world` into a new root, from its own repositories and keys. |
| `kernel` | `apk add --initdb linux-virt` from Alpine, verified with `/etc/werewolf/alpine-keys`. |
| `compare` | Diff the new root's installed packages and kernel against the running image's. No difference: log `check` and stop. A build that rolled back before: log `skip` and stop. |
| `cves` | Fetch the CVE sources and find what the update fixes (below). |
| `root` | Add busybox's links, copy werewolf's own files forward, clear setuid and setgid bits, run `mkfs.erofs`. |
| `vmlinuz` | Unwrap Alpine's arm64 EFI zboot image to the raw `Image`. |
| `stage0` | Build stage0 from its packages, `init` and the form's modules, as a newc cpio compressed with `zstd`. |
| `install` | Mount the victim's filesystem and GRUB's apart, copy the slot in, `sync`, write `attempt`, set GRUB's `next_entry`. |
| `report` | Write the report; log `update`. |
| `reboot` | Reboot cleanly. |

The slot keeps itself or not: `commit` makes it GRUB's default once it is
healthy, and anything else ends on the previous slot ([bite.md](bite.md#slots)).
After the reboot, `outcome` compares the running slot with `attempt` and
logs `commit` or `rollback`. A rolled-back build's hash goes in `bad`.

The build hash is the first 16 hex digits of the sha256 of the new package
list and kernel. The same inputs give the same hash.

## Trust

apk fetches every package, checks every signature and compares every
version. The updater decides nothing about trust.

The trust anchors are the Wolfi key apko installed in `/etc/apk/keys` and
the two Alpine keys in `/etc/werewolf/alpine-keys`, which matched byte for
byte at alpinelinux.org and in Alpine's git.

The CVE sources are not signed. They are fetched over TLS, checked against
the system's CA bundle, and inform the report and nothing else. A source
that fails is recorded with its error, and the update goes ahead.

## CVEs

**Packages.** Wolfi's `security.json` lists, per source package, the
version that fixed each CVE. A CVE counts when that version is newer than
the old one and no newer than the new one, as `apk version -t` compares
them. Version `0` means never affected, and is skipped. A versioned stream
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
    attempt             "SLOT BUILD" of the update awaiting its outcome
    bad                 builds that rolled back, one per line
    work/               the build, deleted when done
```

The updater reads `/proc/cmdline`, `/etc/hostname`, `/etc/apk/` and the
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
  parsed in a scratch arena reset between them; only matches are copied out.
- **Safety checks.** Built ReleaseSafe: an out-of-bounds index or an
  overflow stops the program instead of corrupting it.
- **Other programs** do what they do best: `apk`, `mkfs.erofs`, `zstd`,
  `blkid`, `mount`, `umount`, `sync`, `/usr/lib/werewolf/grubenv` (which
  `commit` shares), `/usr/bin/reboot`. Everything else is Zig's standard
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
Zig but 0.16.0, since Zig changes between releases.

The unit tests cover the pure parts: the kernel command line, package
databases and their diffs, stream base names, kernel versions, the kernel
CVE window, `security.json` parsing, module order, cpio entries (device
nodes included), zboot unwrapping and timestamps.

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
