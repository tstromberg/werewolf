# slot-update

## Summary

slot-update builds or fetches the other slot and boots it once due; an unhealthy slot
rolls back ([updater.md](../../docs/updater.md),
[update-policy.md](../../docs/design/update-policy.md)). Signed `local-NAME` updates are
due at once; `try [HASH]` selects the parked slot; a failed solve fails `update-held`
([manifest.md](../../docs/design/manifest.md)).

## Background

A root is an immutable dm-verity EROFS image. A fix lands in the other slot, `a` or `b`;
the loader falls back unless slot-keep commits it. It is composed locally from
werewolf's repositories and Wolfi. Enrolled IPE machines fetch complete signed
slots instead; unenrolled IPE holds updates
([prebuilt-images.md](../../docs/design/prebuilt-images.md)).

| File | Holds |
| --- | --- |
| `control.zig` | root-only operator requests delegated to the supervised service |
| `slot-update.zig` | daemon, `check`, `outcome`, the plans, the log |
| `stage.zig` | settings, tiers feed, `attempt`, `pending`, lock, reboot |
| `slot.zig` | building and installing the other slot; new roots (`Root`) |
| `images.zig` | authenticated prebuilt delivery and retained slot proof |
| `../../lib/apk.zig` | checking apk's cache before root's apk reads it; RSA keys |
| `cve.zig` | CVE fetcher and reader children; root's checks of their lines |
| `tiers.zig` | the signed CVE tiers feed; tiering an update's fixes |
| `../../lib/update-policy.zig` | due times, settings, `why`, the log's chain |

## Goals

- Exploited CVEs fixed within about 75 minutes, high ones within hours.
- No update can leave a machine unbootable.
- Authenticate network inputs before root uses them.
- A log an auditor can read alone, every line chained to the one before.

## Non-Goals

- Fleet coordination, code compiled into a user's form, live patching.

## Detailed design

The `autoupdate` service writes `/run/werewolf/updater-ready` after setup (slot-keep
waits for it). Once the slot commits it runs `outcome`, then checks after a 10-second
grace and every configured interval (default an hour). Each update writes a report to
`/data/svc/autoupdate/reports` (changes, CVEs, the sha256 of every source) and logs JSON
lines to `log` there and the console. Manual commands send bounded requests through the
service's root-only control socket; nothing mounts without the supervised updater.
Invariants to keep:

- **Staged means armed.** `attempt` holds `SLOT BUILD BOOT_ID`. Only a slot this boot
  armed is rebooted into, and `outcome` does not judge it yet.
- **Arming order.** Disarm, write, sync, arm, then fsync `attempt`. A cut before
  `attempt` costs one boot; reversing the order misjudges an untried build.
- **The ESP and the slots stay detached.** The broker disarms, installs, arms and
  inspects the other slot: it checks the size and SHA-256 of what the updater staged in
  `work/slot` (`vmlinuz`, `stage0.zst`, optional `uki.efi`, the command line) before
  copying, writes the loader entry, and reads the digests back through `esp-inspect`;
  `slot-root`, `slot-decl`, `slot-meta` and `slot-state` check digests the same way on a
  detached mount. Reads use stage0's read-only `/boot`.
- **Nothing goes backwards.** Packages and the kernel never get older (apk's order); the
  feed never older than `cve-tiers.json.serial`. Signatures are verified before parsing.
- **apk reads only what a key vouched for.** Index signatures, package control (index
  SHA-1) and data (datahash) are checked first; the rest of the cache is removed. New
  roots resolve paths within themselves (`Root`).
- **compose writes only scratch** (`work/compose`), from the forms world names NAME-form
  as the new root's packages laid them, the rest as staged here, and `Root`'s accounts;
  it writes exactly `compose.records`, the rest carries over.
- **Fail toward sooner.** With no valid feed, every fix, or else the update itself,
  counts High. A refused form policy blocks the operator's file too.
- **Durability and exclusion.** State and log writes are synced; passes hold `lock`
  and require `/run/werewolf/committed`.

## Drawbacks

- Medium and Low come from unsigned CVE sources; only Urgent and High are signed.

## Alternatives Considered

- Reboot immediately: disrupts busy forms. Tier locally: adds untrusted parsing.

## Security Considerations

- **Network to `_update` children** (apk fetcher, CVE fetcher and reader): uid 69, no
  capabilities, Landlock, seccomp, size and time limits. Root re-checks every line a
  reader sends and rejects a source on one bad line.
- **Signed inputs:** package indexes and the tiers feed use separate keys. A leaked feed
  key changes timing within bounds (serial at most a day ahead, expiry at most a week);
  package keys authorize code.
- **Open:** apk, installing as root, follows links that signed packages lay. Indexes
  name packages by SHA-1 (forging needs a second preimage); SHA-1 signatures fail.

## Reliability Considerations

- A bad update costs a reboot and a rollback; `bad` stops it being retried.
- Update reboots are an hour apart. Boot checks retry for 10 minutes; transient fetch
  failures retry with jittered backoff for up to 2 minutes.
- Tested by `make test`, `make check-updater` (a whole update), `check-updater-staged`
  (a power cut mid-update) and `SEAL_LEARN=1 check-updater` (what the seal refuses).
