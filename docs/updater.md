# The updater

`/usr/lib/werewolf/slot-update` keeps a machine booted from a slot current.
It asks werewolf's repositories and Wolfi for anything newer than the
running image, builds the other slot from it on the machine (werewolf's
programs and forms are packages: [custom-updates.md](design/custom-updates.md)),
boots that slot once, and records what changed and which CVEs that fixes.
Enrolled IPE images fetch signed prebuilt slots instead
([prebuilt-images.md](design/prebuilt-images.md)); protected published
images take them from a host service that polls the vendor channel
([form-images.md](form-images.md#downloading-images)). The policy
below decides when any staged slot boots. It is one Zig program,
`cmd/slot-update/slot-update.zig`, in `minimal` and so every form.

## Running

```
update check      build and stage the other slot if anything is newer
update outcome    after a reboot, log whether the last update held
```

Both delegate to the supervised `autoupdate` service through a root-only
Unix socket; `try [HASH]` asks it for a rollback the same way. The service
waits for the running slot to commit, logs its settings (`policy`), runs
`outcome` once, then `check` every hour (a form's `updates: {every: 30m}`
names another interval, 5m to 7d; `updates: off` leaves the service out).
It stays down unless the kernel command line names `werewolf.slot`,
`werewolf.slots` and `werewolf.esp`.

## When an update boots

Each fix takes its tier from the signed CVE tiers feed
([cve-feed.md](cve-feed.md)), or from its advisory for werewolf's own
fixes; a CVE the feed does not name is `medium`, an update that fixes none
is `low`, and with no valid feed everything is `high`. A staged slot boots
at the soonest time any of its tiers sets, counted from when this machine
first saw a fix of that tier:

| Tier | Boots | Setting: default, limit |
| --- | --- | --- |
| `urgent` | within 15 minutes | none |
| `high` | within `high` | `4h`, `24h` |
| `medium` | in the first window after `medium` | `7d`, `28d` |
| `low` | in the first window after `low` | `28d`, `90d` |

A machine's place in each span is a hash of its slot filesystem's UUID and
the build, so a fleet spreads out and a restart keeps the time. Two JSON
files may change the settings: the form's `/etc/werewolf/update-policy.json`,
then the operator's `update-policy.json` in the config tar (howl's
`--update-policy FILE`), as `{"window": "sun,wed 23:00-02:00", "high":
"1h"}`: `window` is `daily` or days, then UTC hours at least an hour apart
(default `daily 02:00-05:00`); a tier is a whole number of `m`, `h` or `d`,
at most its limit; `limits`, in the form's file only, lowers the limits. A
file is taken whole or refused whole, naming the key. Nothing turns updates
off (lib/update-policy.zig, [update-policy.md](design/update-policy.md)).

## What a check does

| Step | |
| --- | --- |
| `userland`, `kernel` | Fetch, as `_update`, the indexes and packages for the image's `/etc/apk/world`, and `linux-werewolf` from the repository the image's kernel came from (`kernel-repository`); then, as root and offline, `apk add --initdb` them into new roots: packages verified with the image's keys, the kernel with werewolf's alone (`/etc/werewolf/kernel-keys`). The kernel's config must still hold what the build required of it (lib/ipe.zig, lib/image.zig), or the check stops. |
| `compare` | Diff the new packages and kernel against the running image's. Nothing newer, anything older (an old signed index installs as readily as a new one), or a build that rolled back before: log `check` or `skip` and stop. |
| `cves` | Fetch the CVE sources and find what the update fixes, in children of their own. |
| `compose` | Compose what the forms derive, as the build does (`lib/compose.zig`): files, accounts, network policy, promises, kernel arguments. |
| `root`, `verity` | Add busybox's links, copy werewolf's programs, `--app` and the build's records forward, clear setuid bits, run `mkfs.erofs`; append the dm-verity hash tree (lib/verity.zig). |
| `vmlinuz`, `stage0` | Take the kernel image as it is (`boot/vmlinuz-werewolf`); build stage0 from the new root's `init` and `/verity`. |
| `install` | Disarm the other slot through the mount broker; install root, kernel, stage0 and UKI with digest-checked broker operations; arm one try; write `attempt`. |
| `stage`, `report` | Fetch the tiers feed, tier the fixes, note in `pending` when each tier was first seen, work out when the slot is due, write the report; log `stage`. |

When the slot is due, the service writes wall notices a minute, fifteen
seconds and a second ahead, naming each package, CVE and risk
([current.md](design/current.md)), logs `reboot` and reboots; a second
update reboot waits an hour after the last, and any earlier reboot boots
the slot too. `slot-keep` commits the slot once it is healthy, which includes the
updater writing `/run/werewolf/updater-ready` and posture reporting no failure the
image does not excuse; anything else ends on the previous slot
([native-boot.md](design/native-boot.md)), and `outcome` then logs `commit` or
`rollback`, putting a rolled-back build in `bad`. `build`, everywhere, is the first
16 hex digits of the sha256 of a slot's package list and kernel.

## Trust and separation

apk fetches every package; root checks every signature and hash before apk
reads one, and apk checks them again, against the keys in `/etc/apk/keys`
and, for the kernel, werewolf's packages key alone in
`/etc/werewolf/kernel-keys`. The CVE sources are unsigned, fetched over
TLS, and inform the report alone; one that fails is recorded with its
error, and the update goes ahead.

Root, which builds and installs the slot, has no network: the form's policy
lets only `_update` (uid 69) send, and only HTTPS and DNS. Children running
as `_update` fetch everything, with no capabilities and Landlock and
seccomp cut to the job (`lib/sandbox.zig`, [programs.md](programs.md)).

**Packages.** A child runs `apk update` and `apk cache download` against a
scratch root of package names, reaching only ports 443 and 53. Root takes
the cache back, removes anything that is not a file apk names, checks each
index's signature and each package's hashes itself (`apk.zig`), and only
then installs with `--no-network`. A compromised child can at most withhold
packages or offer an older index, which `compare` refuses.

**CVE sources.** 40 MB of JSON from outside, which root never parses. A
fetcher, chrooted to `work/net`, writes at most 256 MB to the one file
root opened for it; a reader, chrooted to the empty `/var/empty`, reads
that file and writes one line per CVE to root, with no other call but
memory's. Root checks every field of every line, and one bad line
discredits the whole source (`BadLine`): a compromised reader can only
leave out or add CVEs inside windows root would accept anyway. Root writes
into the roots it builds with `RESOLVE_IN_ROOT`, so a package's link never
resolves into the running system.

## CVEs

Wolfi's `security.json` lists, per source package, the version that fixed
each CVE; one counts when that version is newer than the old and no newer
than the new, in apk's order (ported to Zig in `cve.zig`). The Linux CNA's
records, fetched from git.kernel.org when the kernel changes, count when
`unaffected` names a version on the running branch in the update's range;
they often appear weeks after a fix ships.

## Files

`/data/svc/autoupdate/` holds `log` (one JSON line per event, never
pruned: about 2 MB a year), `reports/TIME-BUILD.json` (the newest 500),
`attempt` (`SLOT BUILD BOOT` of the armed slot and the boot that armed it),
`pending` (the staged build, and when each tier was first seen), `bad`
(builds that rolled back), `cve-tiers.json` with its `.sig` and `.serial`
(the last feed taken), `cache/` and `work/`; `slot-update.zig` names the rest.

## Events

Every line has `time` (RFC 3339, UTC), `host`, `seq`, `prev` and `event`;
`prev` is the first 16 hex digits of the previous line's SHA-256, so an
edited line breaks the chain ([audit log](design/update-policy.md#the-audit-log)).

| Event | Fields |
| --- | --- |
| `policy` | `settings` (each one's `value`, `source` and `limit`), `refused` (each file refused, with `key` and `why`) |
| `check` | `slot`, `release`, `result`; when `staged`: `build`, `tier`, `due`, `due_in` |
| `stage` | `slot`, `from`, `build`, `kernel`, `packages`, `cves`, `tier`, `seen` (per tier), `fixes` (per tier), `due`, `due_in`, `why`, `report` |
| `warn` | `build`, `tier`, `lead` (seconds), `console`, `sessions` |
| `reboot` | `build`, `tier`, `cause` (`due` or `first-boot`), `due`, `late`, `why` |
| `feed` | `serial`, `expires`, `result` (`ok`, `unchanged`, `kept`, `none`), `reason`, and with `none`, `consequence` |
| `tier` | `build`, `fix`, `cause`, `feed`, `from`, `to`, `was_due`, `due`, `due_in`, `why`: a staged fix's tier rose |
| `commit` | `slot`, `build`, `release`, `waited` (per tier), `down` (seconds from the update's reboot to this kernel's start) |
| `rollback` | `failed`, `running`, `build`, `release`, `down` |
| `skip` | `build`, `reason` |
| `held` | `format`, `offered`, `why`: the machine takes only programs for its `werewolf-formatN` |
| `error` | `step`, `error`, `detail` (what the failed command said) |

## Report

```json
{ "time": "2026-10-06T13:42:36Z", "host": "example", "build": "0123456789abcdef",
  "from": { "slot": "a", "release": "...", "kernel": "linux-werewolf-7.2.10-r1" }, "to": { "slot": "b", "kernel": "linux-werewolf-7.2.11-r1" },
  "packages": [ { "name": "busybox-full", "from": "1.37.0-r30", "to": "1.38.0-r2" } ],
  "package_cves": [ { "origin": "busybox", "from": "1.37.0-r30", "to": "1.38.0-r2", "cves": ["CVE-2024-58251"] } ],
  "kernel_cves": { "branch": "7.2", "cves": [ { "id": "CVE-2026-52988", "fixed_in": "7.2.11", "title": "netfilter: ..." } ] },
  "sources": [ { "url": "https://packages.wolfi.dev/os/security.json", "sha256": "...", "error": null } ] }
```

`from` is null for an added package and `to` for a removed one. To check a
report, fetch the sources, compare their sha256, and apply the rules above.

## Testing and limits

`make test` runs the unit tests; `make check-updater` runs a whole update
over the network ([testing-live.md](testing-live.md)). By hand, write an
older kernel (`linux-werewolf-7.2.10-r1`) into a built slot's
`meta/usr/share/werewolf/kernel`, remove its `overlay.tar` and
`slot/root.erofs`, `make FORM=lima slot` again and boot it: the machine
finds the newer kernel, builds and boots slot `b`, and commits it.
werewolf's programs and forms change only with a new image; an update
needs Wolfi, werewolf's repositories and git.kernel.org; and the kernel CVE
list is what the CNA had published at update time.
