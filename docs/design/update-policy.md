# Update policy

Proposed, 2026-10-07. Built (lib/update-policy.zig, cmd/slot-update,
tools/cve-tiers.zig, release/tiers), except draining.

## Summary

A machine checks for updates hourly, stages a fix in its other slot at
once, and boots it when its most urgent fix is due: within 15 minutes for
an exploited or critical CVE, 4 hours for a high one, and after one or four
weeks, in a maintenance window, for the rest.

## Background

The updater used to check every 20 hours and reboot at once for anything.
Exploited bugs stayed open most of a day, and an hourly check would reboot
machines nightly, since Wolfi changes something most days. Its CVE sources
are unsigned, and say which CVEs an update fixes but not how severe they are.

## Goals

- By default a fix runs within 1 h 15 min of release if Urgent, 5 h if
  High, 7–8 days if Medium, 28–29 days if Low.
- Only signed data can delay an Urgent or High fix; nothing turns updates
  off; the log alone explains every wait ([below](#the-audit-log)).

## Non-Goals

Fleet coordination, live patching, reachability analysis, runtime policy
changes, and code compiled into a user's form.

## Detailed design

A check stages an update at once and records when this machine first saw a
fix of each tier. Newer builds keep those times, so a stream of builds
cannot postpone a reboot ([updater.md](../updater.md#when-an-update-boots)).

| Tier | A fix is in it when | Due | Setting: default, limit |
| --- | --- | --- | --- |
| Urgent | its CVE is in [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), or has CVSS ≥ 9.0 with `AV:N` | within 15 min | none |
| High | CVSS ≥ 7.0 | within `high` | 4h, 24h |
| Medium | CVSS 4.0–6.9, or no score yet | first window after `medium` | 7d, 28d |
| Low | CVSS < 4.0, or the update fixes no CVE | first window after `low` | 28d, 90d |

Medium and Low are minimum waits, so a week's routine fixes share one
reboot in the window (02:00–05:00 UTC daily). Unscored CVEs are Medium, not
High, which would reboot machines for fixes nobody has judged; KEV lifts an
exploited one the day CISA lists it, and each check re-tiers what is staged.

**Settings.** A form, then an operator, may change the window and times
within limits only a form may lower ([keys](../updater.md#when-an-update-boots)).

**The feed.** CI tiers the CVEs of werewolf's packages and kernel hourly,
under a key of its own ([releases.md](../releases.md#the-tiers-feed)).
Urgent and High entries name the fixed version, so signed data alone finds
them. With no valid feed, every fix counts as High.

### werewolf's own fixes

A fix to werewolf's code has no CVE, so it gets a line, with its tier, in
`release/advisories`. Images and release manifests carry the file, and a
machine applies each advisory its release has and its own image lacks.

### The audit log

For any fix, the log alone must say when this machine first saw it, its
tier and evidence, the setting behind its wait and who set it, and when it
was due and ran. Each wait has `due`, `due_in` and a `why` sentence; each
check restates what is staged, so gaps show; and chained lines bind root
once the head is kept off the machine ([events](../updater.md#events)).

## Drawbacks

- Medium and Low wait one and four weeks, and a severe CVE waits as Medium
  until scored. CI tiers for every machine; werewolf tiers its own fixes.

## Alternatives Considered

| Alternative | Why not |
| --- | --- |
| Reboot at once, or deadlines for every tier | nightly reboots; `high 0h`, `medium 0d`, `low 0d` come close |
| CVSS alone | it rates harm, not exploitation; KEV is one more 1 MB file |
| Tiering on each machine | more untrusted parsing, NVD's rate limits, machines that disagree |
| Times from the release | machines back from one outage would all reboot together |
| The image key for the feed | a key used daily should cost timing, not code, if it leaks |
| kexec, or a soft reboot | kexec skips the one try; PID 1's Landlock domain and seal cannot be left |

## Security Considerations

- Unsigned sources cannot hide an Urgent or High fix. A leaked feed key
  delays fixes by at most Low's 90 days; the image key decides what runs.
- Settings are bounded, not tighten-only: operators who cannot reboot
  weekly would otherwise turn updates off. No one can change Urgent.

## Reliability Considerations

- Update reboots are an hour apart, counted from the last one, so no
  source can cause a reboot loop. A cold boot is not that reboot: a due
  posture fix is taken then, after a short notice. An Urgent fix restarts
  a whole fleet within 15 minutes.
- Open: draining (`/etc/werewolf/drain-seconds`) is not built; what hourly
  checks cost Wolfi's mirrors; a CDN for the feed, for large fleets.
