# slot-update

## Summary

The autoupdater: it builds or fetches the other slot, stages it, and boots it
once its fixes say it is due; a slot that does not prove healthy rolls back.
[docs/updater.md](../../docs/updater.md) has operations and the log,
[docs/design/update-policy.md](../../docs/design/update-policy.md) the policy.

## Background

A werewolf root is an immutable dm-verity erofs image, so a fix lands only as
a new image. A machine has two slots, `a` and `b`; the bootloader boots a new
slot once and falls back unless `slot-keep` commits it. The other slot comes
from the form's latest signed release (`prod`, `prod-ssh`), or is built on the
machine from Wolfi and Alpine (any other form built on `prod`).

| File | Holds |
| --- | --- |
| `slot-update.zig` | daemon, check, outcome, the plans, the log |
| `stage.zig` | settings, tiers feed, `attempt`, `pending`, lock, reboot |
| `slot.zig` | the other slot built and installed; new roots (`Root`) |
| `apk.zig` | apk's cache checked before root's apk reads it |
| `cve.zig` | CVE fetcher and reader children; root's checks of their lines |
| `release.zig` | release manifest: signature, checks, advisories |
| `tiers.zig` | the signed CVE tiers feed; tiering an update's fixes |
| `../../lib/update-policy.zig` | due times, settings, `why`, the log's chain |

## Goals

- Exploited CVEs fixed within about 75 minutes, high ones within hours.
- No update that can leave a machine unbootable.
- Nothing from the network decides anything as root.
- A log an auditor can read alone, every line chained to the one before.

## Non-Goals

- Fleet coordination, code compiled into a user's form, live patching.

## Detailed design

Invariants to keep when changing this code:

- **Staged means armed.** `attempt` holds `SLOT BUILD BOOT`, BOOT the
  `boot_id` that armed it. The daemon reboots only for a slot this boot armed;
  `outcome` judges nothing in it. Any reboot boots a staged slot.
- **Arming order.** Remove `attempt` and disarm; write the slot; sync; arm;
  write `attempt` (fsync) last. So `attempt` is on record only for a slot
  that is armed: a power cut between the two leaves a slot armed with no
  record, which boots once and is committed or forgotten, where the other
  order would record a try that never happened as a rollback and blacklist
  a build no boot has judged. `pending` survives the install so first-seen
  times are never lost.
- **Nothing goes backwards.** Packages and the kernel never older (apk's
  order), built or released; releases never older than `serial`; the feed
  never older than `cve-tiers.json.serial`. Signed inputs verified first.
- **apk reads only what a key vouched for.** Indexes' signatures, packages'
  control (index SHA-1) and data (datahash) are checked first; the rest of
  the cache is removed. New roots resolve within themselves (`Root`).
- **compose writes only scratch,** never the new root: from the staged chain
  and the accounts `Root` reads, into `work/compose`, which `Root` takes in.
  It makes exactly `compose.records`; every other record is carried forward.
- **Fail toward sooner.** No valid feed: every fix, or the update itself,
  counts High. A refused form policy blocks the operator's file too.
- **Durability.** State files go through `writeReplacing`; log lines and
  reports are fsync'd.
- **One pass at a time.** `check`, `outcome` and the reboot hold `lock`;
  `check` requires `/run/werewolf/committed`.

## Drawbacks

- Medium and Low come from unsigned CVE sources; only Urgent and High signed.

## Alternatives Considered

- **Reboot as soon as built:** nightly reboots on a busy form.
- **Tier on each machine:** more untrusted parsing; CI tiers once and signs.

## Security Considerations

Trust boundaries:

- **Network to `_update` children** (apk fetcher, CVE fetcher and reader):
  uid 69, no capabilities, Landlock, seccomp, size limits. Root re-checks
  every line a reader sends, and refuses a source on one bad line.
- **Signed inputs:** a release manifest (image key) and the tiers feed (its
  own key). A leaked feed key costs timing within bounds (serial at most a
  day ahead, expiry at most a week); a leaked image key costs what runs.

Known gaps, for the next reviewer:

- apk itself, installing as root, follows links that signed packages lay.
- Alpine's index signatures and every package hash are SHA-1 (a second
  preimage, not a collision, to forge).
- A tree-built image of a release form takes a release with its packages
  but older code: only packages and the kernel are compared (use DEV=1).

## Reliability Considerations

- One try, the deadman and `slot-keep` make a bad update cost a reboot and a
  rollback; `bad` stops it being tried again.
- No update reboot within an hour of boot, except a machine's first check.
- `make test`; `make check-updater`, a whole update over the network;
  `make check-updater-staged`, power cut with an update staged, which the
  next boot must take; `make SEAL_LEARN=1 check-updater`, what the seal
  would refuse.
