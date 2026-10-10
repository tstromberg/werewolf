# A current machine

Proposed, 2026-10-10. Built (cmd/slot-update/notice.zig, the boot
check's retry, and the hour between update reboots).

## Summary

A VM should not sit on packages it already knows how to replace. Once its
slot has committed it checks, installs anything newer it has not already
failed, and reboots only when that changes its security posture. Like
wall(1), it says so at one minute, fifteen seconds and one second, with
the package, the CVE and the risk, on every login and on the console.

## Background

The updater checks once the running slot commits, then hourly, and writes
a newer slot at once
([updater.md](../updater.md), [update-policy.md](update-policy.md)). A
rolled-back build is in `bad` and is not installed again. The staged
report and the signed tiers feed already name each package, CVE and risk.

`bootIfDue` calls `/usr/bin/reboot` with only a log line. Except on the
machine's first check ever, a due update waits an hour after boot: a VM
that was off keeps its staged fix, and a check that missed DHCP waits too.

## Goals

- Every boot finishes one check once the slot has committed, before the
  hourly schedule. A newer build not in `bad` is installed on that check.
- A posture fix that is already due reboots on that boot, after the three
  notices, even when uptime is under an hour.
- Someone on ssh or `howl console` can read the package, CVE and risk in
  time to stop. `make test` covers the text and wake times; `check-updater`
  shows the three notices on the console.

## Non-Goals

- Draining, live patching, or an ack. A VM with no login must not stay stale.
- A message from `reboot`, power-button, panic, or an operator. slot-update
  writes the notices; the image gains no `wall`.

## Detailed design

**Install at boot. Reboot only for posture.** Each boot, the first pass
after `/run/werewolf/committed` is a check. Until then the other slot is
the fallback.

| Result | What happens |
| --- | --- |
| Nothing newer | Log `check`. Start the hourly schedule. |
| Newer build, not in `bad` | Install it: stage and arm the other slot now. |
| Build in `bad` | Log `skip`. That version is never installed again. A newer one still is. |
| Check failed | Retry every 30s until a check finishes or uptime passes 10 minutes, then hourly. |

Installing does not reboot. The slot boots when its tier is due:

| Tier | Risk | Reboot |
| --- | --- | --- |
| Urgent | In KEV, or CVSS ≥ 9.0 with `AV:N`; a werewolf advisory marked urgent | Within 15 minutes. A posture fix. |
| High | CVSS ≥ 7.0, a werewolf advisory marked high, or no valid tiers feed | Within `high` (default 4h, at most 24h). A posture fix. |
| Medium | CVSS 4.0–6.9, or no score yet | The window after `medium` (default 7 days). Not posture. |
| Low | CVSS < 4.0, or the update fixes no CVE | The window after `low` (default 28 days). Not posture. |

Medium and Low are staged at boot so a later reboot lands on them; they
wait for the window. The hour-after-boot hold drops for a posture fix
already due. Another update reboot still waits an hour after `rebooted`.

**Three notices.** The daemon wakes at due−60s, due−15s and due−1s.

```
Broadcast message from werewolf@host (autoupdate) (Sat Oct 10 12:34:00 2026):

Rebooting in 1 minute to install updates. Security posture: Urgent.

  openssl     3.4.0-r0 -> 3.4.1-r1
    CVE-2026-1111  Urgent
    CVE-2026-2222  High
  linux-virt  6.18.54-r0 -> 6.18.55-r0
    CVE-2026-52988  High

The new slot is already installed. This reboot switches to it.
```

A window reboot names its tier. A package with no CVE is listed only on a
Low reboot; advisories use the same lines as CVEs. The one-second notice
keeps the causing tier, and past 12 lines the longer ones name the report.
Under a minute the lead says the time left; already due, it waits 15
seconds. A first check's reboot is still within two minutes, not before 61.

Each notice goes to `/dev/console` and every `/dev/pts/N` (no utmp), beside
a `warn` line. The body joins the staged report to the feed's tiers. Pending is
reread at each mark: a new build restarts it, a disarmed slot is not
booted, and a failed write does not cancel the reboot.

## Drawbacks

A due Urgent fix on a cold boot reboots about 15 seconds after the check.
A deadline already missed slips by at most that long.

## Alternatives Considered

| Alternative | Why not |
| --- | --- |
| `wall(1)` from util-linux | No util-linux on the image. `reboot` stays message-free. |
| One notice, or print and reboot together | A late reader, or a slow console, never sees the reason. |
| Wait for an ack | A VM with no login stays stale. |
| Keep the hour after every boot | A short-lived VM never takes a staged fix. An hour after `rebooted`, plus `bad`, stops a loop. |
| Reboot at boot for Medium and Low | A package bump most days, on a machine someone may be using. |

## Security Considerations

The notice decides nothing: the reboot already follows from the report
and the signed feed. The body has no free-form strings, so a CVE source
cannot write a terminal escape onto a session.

## Reliability Considerations

`outcome` runs before the boot check, so a rollback is in `bad` first.
The hour hold is after `rebooted` only. Boot retries last 10 minutes.
Warn and reboot hold today's lock across the last notice and the reboot.
