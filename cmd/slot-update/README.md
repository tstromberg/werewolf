# slot-update

## Summary

slot-update is the autoupdater: it builds or fetches the other slot and boots
it once due; a slot that does not prove healthy rolls back. See
[docs/updater.md](../../docs/updater.md) and [update-policy.md](../../docs/design/update-policy.md).

## Background

A werewolf root is an immutable dm-verity erofs image, so a fix lands only as
a new image in the other of two slots, `a` and `b`; the loader boots it once and
falls back unless slot-keep commits it. It comes from the form's latest signed
release (`prod`, `prod-ssh`), or is built from Wolfi and Alpine (other forms).

| File | Holds |
| --- | --- |
| `slot-update.zig` | daemon, `check`, `outcome`, the plans, the log |
| `stage.zig` | settings, tiers feed, `attempt`, `pending`, lock, reboot |
| `slot.zig` | building and installing the other slot; new roots (`Root`) |
| `../../lib/apk.zig` | checking apk's cache before root's apk reads it; RSA keys |
| `cve.zig` | CVE fetcher and reader children; root's checks of their lines |
| `release.zig` | release manifest: signature, checks, advisories |
| `tiers.zig` | the signed CVE tiers feed; tiering an update's fixes |
| `../../lib/update-policy.zig` | due times, settings, `why`, the log's chain |

## Goals

- Exploited CVEs fixed within about 75 minutes, high ones within hours.
- No update can leave a machine unbootable.
- Nothing from the network decides anything as root.
- A log an auditor can read alone, every line chained to the one before.

## Non-Goals

- Fleet coordination, code compiled into a user's form, live patching.

## Detailed design

The `autoupdate` service writes `/run/werewolf/updater-ready` after setup
(slot-keep waits for it). Once the slot commits it runs `outcome`, then `check`
at once and every `/etc/werewolf/update-every` seconds (default an hour). A
slot built here matches `make slot`: userland from `/etc/apk`, `linux-virt`
checked against `/etc/werewolf/alpine-keys`, the rest from `/usr/share/werewolf`.
Each update writes a report to `/data/svc/autoupdate/reports` (changes, CVEs,
the sha256 of every source) and logs JSON lines to `log` there and the console.
Invariants to keep:

- **Staged means armed.** `attempt` holds `SLOT BUILD BOOT_ID`. Only a slot this
  boot armed is rebooted into, and `outcome` does not judge it yet.
- **Arming order.** Remove `attempt` and disarm; write the slot; sync; arm;
  write `attempt` (fsync) last. A power cut between the last two costs one
  boot; the other order would log a try that never happened as a rollback and
  mark an unjudged build bad. `pending` survives the install (first-seen times).
- **Nothing goes backwards.** Packages and the kernel never get older (apk's
  order); a release must be newer than `serial`; the feed never older than
  `cve-tiers.json.serial`. Signatures are verified before parsing.
- **apk reads only what a key vouched for.** Index signatures, package control
  (index SHA-1) and data (datahash) are checked first; the rest of the cache
  is removed. New roots resolve paths within themselves (`Root`).
- **compose writes only scratch** (`work/compose`), from the forms world names
  NAME-form as the new root's packages laid them, the rest as staged here, and
  `Root`'s accounts; it writes exactly `compose.records`, the rest carries over.
- **Fail toward sooner.** With no valid feed, every fix, or else the update
  itself, counts High. A refused form policy blocks the operator's file too.
- **Durability.** State files go through `writeReplacing`; log lines are fsync'd.
- **One pass at a time.** `check`, `outcome` and the reboot hold `lock`; `check`
  and `outcome` require `/run/werewolf/committed`.

## Drawbacks

- Medium and Low come from unsigned CVE sources; only Urgent and High are signed.

## Alternatives Considered

- **Reboot as soon as built:** nightly reboots on a busy form.
- **Tier on each machine:** more untrusted parsing; CI tiers once and signs.

## Security Considerations

- **Network to `_update` children** (apk fetcher, CVE fetcher and reader):
  uid 69, no capabilities, Landlock, seccomp, size and time limits. Root
  re-checks every line a reader sends and rejects a source on one bad line.
  Speculative Store Bypass is disabled for the daemon and every child.
- **Signed inputs:** release manifests (image key) and the tiers feed (its own
  key). A leaked feed key costs timing within bounds (serial at most a day
  ahead, expiry at most a week); a leaked image key costs what runs.
- **Open:** apk, installing as root, follows links that signed packages lay.
  Alpine's index signatures and every package hash are SHA-1 (forging needs a
  second preimage). A tree-built image of a release form takes a release with
  newer packages but older code: only packages and kernel compare (use DEV=1).

## Reliability Considerations

- A bad update costs a reboot and a rollback; `bad` stops it being retried.
- No update reboot within an hour of boot, except after a first check.
  Transient fetch failures retry with jittered backoff for up to 2 minutes.
- Tested by `make test`, `make check-updater` (a whole update),
  `make check-updater-staged` (power cut with an update staged) and
  `make SEAL_LEARN=1 check-updater` (what the seal would refuse).
