# Update policy

Proposed, 2026-10-07.

**Note for reviewers**:
While reviewing this proposal, focus on answering for yourself:

* Does this proposal fit with our engineering principles?
* Are there unexplored concerns with this design, such as reliability or usability issues?
* Could the proposed implementation be made simpler?
* Are there other alternatives to consider?

## Summary

A werewolf machine checks for updates every hour and stages a fix into its
other slot as soon as it sees one. When it reboots into that slot depends
on how urgent the most urgent fix is:

| Tier | Reboot |
| --- | --- |
| Urgent | within 15 minutes |
| High | within 4 hours |
| Medium, or not yet scored | after 7 days, in the maintenance window |
| Low | after 28 days, in the maintenance window |

The maintenance window is 02:00–05:00 UTC daily by default. An operator
may change the window and the High, Medium and Low times within limits
the image sets; Urgent is fixed. A machine's exposure to an exploited bug
drops from up to 20 hours today to under 2, and routine fixes stop
rebooting machines nightly.

## Background

### The updater today

[updater.md](../updater.md) has the details. In short:

- **Two paths.** A form CI publishes (`prod`, `prod-ssh`) follows its signed
  releases. Any other form built on `prod` rebuilds its other slot on the
  machine from Wolfi and Alpine: the *packages path* (below).
- **When it checks.** `autoupdate` checks once the running slot commits,
  then every 20 hours (`/etc/werewolf/update-every` overrides this; `demo`
  sets 3600 seconds). A failed check is retried at the next interval.
- **What it does with an update.** It builds or fetches the other slot,
  writes it, gives it GRUB's one try (`next_entry`) or systemd-boot's
  (`werewolf-b+1.conf`), and reboots at once, whatever the update fixes.
- **What protects a bad update.** A new slot boots once. `slot-keep` keeps
  it only if every service has stayed up for a minute, and stage0's deadman
  reboots a slot that never gets healthy within ten minutes
  ([bite.md](../bite.md#slots)). A build that rolls back goes in `bad` and
  is never tried again.
- **What it knows about CVEs.** Two sources, which the updater reads for
  which CVEs an update fixes, not how severe they are:
  - Wolfi's `security.json` names the version that fixed each CVE.
  - The Linux kernel CNA's records name the kernel versions that fixed
    each. Many now carry the CNA's own CVSS score too.
  Both are fetched unsigned over TLS and "inform the report and nothing
  else".
- **How fast releases follow fixes.** CI builds a release within about an
  hour of a fix reaching Wolfi or Alpine, re-signs the latest manifests
  daily, and lets each expire after a week ([releases.md](../releases.md)).

So the policy today is "reboot at once for anything", with up to 20 hours
before a machine notices. Checked hourly, the same policy would reboot a
machine most nights, for whatever Wolfi changed that day.

### Forms users build

A form a user builds from this repository, with `prod` in its include
chain, takes the packages path. Each check:

1. fetches the indexes and packages for the image's `/etc/apk/world` and
   the Alpine kernel, as `_update`;
2. installs them offline into a new root, with apk checking every signature
   against the image's own keys;
3. diffs that root against the running image, and stops if nothing changed;
4. copies the form's own files forward, then builds the root with
   `mkfs.erofs`, its dm-verity tree and stage0, installs the slot and
   reboots.

What apk installs gets updated: every package in the form, the kernel, and
runtimes such as .NET or Python. What is copied forward never changes until
the user rebuilds the image:

- werewolf's own programs (init, fence, the updater itself);
- the form's files under `forms/<name>/`;
- applications compiled into the image, such as the Go and Rust tutorial
  servers (`examples/build.mk`). A static binary carries its own copy of its
  language's standard library, so a CVE in Go's `net/http` stays until the
  user builds again.

A form without `prod` in its chain, `minimal` for one, has no updater at all.

### Terms

- **CVSS**: a vulnerability's base severity score, 0–10, in its record at
  NVD (the US National Vulnerability Database). NVD has had a scoring
  backlog of weeks since 2024.
- **KEV**: CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog: CVEs with evidence of exploitation in the wild, as one JSON
  file.
- **Staged**: a slot written, with its one try armed, that the machine has
  not booted yet.
- **Due**: when a staged slot will be booted.

## Goals

Time to running a fix, with the default settings, from when the machine can
first fetch it (a release published, or a package in Wolfi's index):

| Tier | Target |
| --- | --- |
| Urgent | ≤ 1 h 15 min: at most an hour to see it, then at most 15 minutes |
| High | ≤ 5 h |
| Medium | 7 to 8 days |
| Low | 28 to 29 days |

- **Few reboots for routine fixes.** With the defaults, Medium and Low fixes
  cause at most one reboot a week, always in the maintenance window. A
  machine reboots outside the window only for an Urgent or High fix.
- **A new machine** runs the latest release within 15 minutes of its first
  commit, whatever the tier.
- **No more than one update reboot an hour** on any machine. A fleet spreads
  each release's reboots over the tier's time, not the same minute.
- **Only signed data can make a fix Urgent or High wait longer.** Unsigned
  CVE sources can bring a reboot sooner, never later, for those tiers.
- **No setting can switch updates off.** Every tier has a ceiling the
  image sets; Urgent has no setting at all.
- **Release-path checks stay cheap.** A check that finds nothing new costs
  one HTTPS request for a manifest of a few KB and its signature.
- **The log explains every reboot and every wait.** For any fix, an
  auditor can read when the machine first saw it, its tier and the
  evidence for it, the setting and who set it, when the reboot was due and
  how long remained, and when the machine ran it
  ([The audit log](#the-audit-log)). The time from release to commit can
  be charted per tier.

## Non-goals

- **Coordinating a fleet**: rolling updates across machines, or quorum. The
  spread is the whole of fleet awareness here.
- **Patching without a reboot.** The root is an immutable erofs image;
  activating a fix means booting the slot that has it.
- **Reachability analysis**: deciding whether the vulnerable code runs on
  this form. Every package in a werewolf image is there because something
  uses it.
- **Updating code compiled into a user's form.** Its bytes change only when
  the user rebuilds the image ([Limits](#limits)).
- **Scanning on the machine** with grype or similar. `demo` does this, for
  show.
- **Changing the policy at runtime.** A shell-free machine has no channel
  for it, and the config tar is read at boot.

## Detailed design

### Check hourly, stage at once, reboot when due

`update-every` defaults to 3600. A check runs as today until `install`,
which stages the slot. Then, instead of rebooting, it records the staged
build in `/data/svc/autoupdate/pending`:

```json
{"build": "0123456789abcdef", "report": "/data/svc/autoupdate/reports/...json",
 "first_boot": false,
 "high": {"seen": "2026-10-07T14:02:11Z", "subject": "CVE-2026-1234 in curl",
          "evidence": "CVSS 8.1 from NVD"},
 "medium": {"seen": "2026-10-03T09:00:40Z", "subject": "...", "evidence": "..."}}
```

For each tier among the staged fixes, `pending` holds when this machine
first saw a fix of that tier, and that fix, for the log's `why`. The slot is
due at the earliest of each tier's own time, computed from its `seen`
([Tiers](#tiers)), and worked out afresh whenever it is needed, never
stored. The daemon sleeps until the next
check or `due`, whichever comes first. At `due` it reboots into the staged
slot (see [Draining](#draining)), and the next `pending` starts empty.

- **The staged slot stays armed.** Any reboot (a crash, an operator, a
  cloud's host maintenance) boots it, with every fix it holds, whatever
  their tiers. `outcome` reports such a boot as `commit` or `rollback`,
  and judges nothing in the boot that armed the slot, which `attempt`
  names (the kernel's `boot_id`), so the service restarting over a staged
  slot is no rollback. `make check-updater-staged` cuts a machine's power
  with an update staged, and its next boot must take it.
- **Staged means armed.** The updater reboots only for a slot this boot
  armed, `attempt` naming its build: never for one whose try is spent or
  gone, which the next check stages again.
- **One reboot takes everything.** A High fix that reboots a machine
  applies every Medium and Low fix staged with it, and their waits end
  there.
- **A build already staged is not rebuilt.** A check whose plan names the
  staged build just re-evaluates its tiers. Today every check that finds an
  update builds it again, which an hourly check could not afford.
- **A newer build disarms before it writes.** `install` first clears
  `next_entry`, or removes the `+1` entry, then writes the slot and arms it
  again. Today `install` writes the other slot in place and sets
  `next_entry` last, which is safe only because nothing could already be
  armed. Under this design a staged slot can be, and a reboot mid-write
  must land on the running slot, not a half-written one.
- **Times carry forward.** Updates are cumulative, so a newer build holds
  every fix the staged one did. A tier keeps its earliest `seen` across
  builds, so a trickle of new builds can never postpone a reboot, and a
  Medium fix first seen on Monday is still due the next Monday.
- **Times start when this machine first saw a fix,** not at the release
  ([Alternatives](#anchor-times-at-the-release)).

### Tiers

An update takes the most urgent tier of any fix it carries. Each tier's
time counts from its `seen`:

| Tier | A fix is in it when | Due | Setting (default, limit) |
| --- | --- | --- | --- |
| Urgent | its CVE is in KEV, or has CVSS ≥ 9.0 with network attack vector (`AV:N`) | within 15 min | none |
| High | its CVE has CVSS ≥ 7.0 | within the High time | `high` (4h, 0–24h) |
| Medium | its CVE has CVSS 4.0–6.9, **or no score yet** | the first window after the Medium wait | `medium` (7d, 0–28d) |
| Low | its CVE has CVSS < 4.0, or the update fixes no CVE | the first window after the Low wait | `low` (28d, 0–90d) |

- **Urgent and High are deadlines; Medium and Low are minimum waits.** A
  High fix boots within its time, wherever the window is. A Medium fix
  waits at least its time, then boots in the next window. A wait of `0d`
  means the next window.
- **An update that fixes no CVE is Low.** That covers a rebuild, or a newer
  package with no advisory. werewolf's own security fixes, which have no
  CVE, set their tier in the release ([werewolf's own fixes](#werewolfs-own-fixes)).
- **Unscored CVEs count as Medium.** Many new CVEs have no score for days
  or weeks. Counting them High would reboot machines within 4 hours for
  fixes nobody has judged; as Medium they wait for the window. Two things keep that from
  hiding a severe bug for long:
  - **KEV outranks score.** An unscored CVE that is being exploited is
    Urgent the day CISA lists it.
  - **Tiers move when scores arrive.** While a slot is staged, every check
    tiers its fixes again against the latest feed. A Medium fix that NVD
    scores 8.1 becomes High, due within 4 hours of the check that saw the
    new score. A tier only rises this way: a fix already due keeps its
    time.
- **Exploitation evidence outranks score.** A CVSS 7.5 in KEV is Urgent; a
  9.8 with only local access is High.

### Where tiers come from: a signed feed

CI publishes one more file with every release run, and at least daily since
KEV changes daily: `cve-tiers.json` and its `.sig`.

```json
{
  "format": "werewolf-cve-tiers/1",
  "serial": "20261007T140000Z",
  "expires": "2026-10-10T14:00:00Z",
  "kernel": "6.18",
  "urgent": [
    {"cve": "CVE-2023-4863", "origin": "libwebp", "fixed": "1.3.1-r2", "score": 8.8,
     "vector": "CVSS:3.1/AV:N/...", "source": "nvd", "kev": "2023-09-13"},
    {"cve": "CVE-2025-68263", "kernel": "6.18", "fixed": "6.18.1", "score": 9.8,
     "vector": "CVSS:3.1/AV:N/...", "source": "cna"}
  ],
  "high": [{"cve": "CVE-2026-2222", "origin": "curl", "fixed": "8.17.0-r1", "score": 7.5, "...": "..."}],
  "medium": [{"cve": "CVE-1999-0289"}],
  "low": [{"cve": "CVE-2025-0002", "score": 3.1, "...": "..."}]
}
```

Every entry carries its evidence for the log's `why`: `score`, `vector`
and `source` (`nvd`, `cna` or `cisa-adp`) when it is scored, and `kev`, the
date CISA listed it, when it is exploited.

- **CI builds it** from KEV and CVSS scores, covering the CVE IDs in
  Wolfi's `security.json` and the kernel CNA's records for the branch
  Alpine ships. A score is NVD's, or, where NVD has none yet, the one the
  CNA or CISA (its Vulnrichment container) put in the CVE record, which
  often comes sooner. NVD's API is queried with CI's key and cached between
  runs.
- **Urgent and High name their fixes.** Each entry carries the package
  origin, or kernel branch, and the version that fixed it, so the machine
  finds every Urgent and High fix an update carries from signed data alone,
  with apk's version order as `cve.zig` already has it.
- **Medium and Low name only the CVE.** The machine finds those CVEs from
  the unsigned sources, as today, and the feed only tiers them. Unscored
  CVEs, CVSS v2 scores alone included, are listed as Medium.
- **A CVE the feed does not name,** one too new for CI's last run, counts as
  Medium, as an unscored one does.
- **It names every fix to what it covers.** `security.json` has no dates,
  so a horizon would have to guess by CVE year, and would drop an old CVE
  fixed last week.
- **It covers what werewolf installs.** About 120 source packages, every
  form's, stage0's and the boot disk's, and the kernel: about 7,000 CVEs,
  780 KB, nearly all of it the kernel's. A machine running a form built
  elsewhere counts CVEs in its own packages as Medium, as for any CVE the
  feed does not name.
- **CI builds it hourly and commits it to a repository of its own**,
  [werewolf-linux/cve-feed](https://github.com/werewolf-linux/cve-feed),
  only when a tier changed or the feed is a day old
  ([releases.md](../releases.md#where-it-is-published)): the history is the
  feed's, each change a diff. The job runs in that repository, so its token
  writes nowhere else, and the tiers key is kept apart from the image key.
  Every image's build record names where, `/usr/share/werewolf/tiers`, and
  carries the key, `tiers.pub`, so user-built forms read the same feed.
- **Machines fetch the feed** when a check finds an update, and at each
  check while a slot is staged, to tier its fixes again: about 37 KB,
  gzipped in transit. A fetcher child running as `_update` gets it, as for
  the other sources; root checks the signature before it reads a byte, then
  parses it, as it does a release manifest. The machine keeps the last
  feed it accepted, and uses it whenever a new one cannot be had or does
  not check, until it expires. A feed whose serial is older than the one
  it has is refused, so no cache can take a machine backwards.
- **Both paths use the same feed.** A machine several releases behind tiers
  every fix its jump carries, which a field in each release could not.
- **It has its own key**, not the image key. The public half,
  `/usr/share/werewolf/tiers.pub`, is in `prod`, so user-built forms have it
  too. The private half is a CI secret of its own, like the image key
  ([releases.md](../releases.md#the-key)), and rotates on its own schedule.
- **If the feed is missing, expired or fails its signature,** every CVE in
  the update counts as High. That is not the same as unscored: without the
  feed the machine cannot tell an Urgent fix from a Medium one, so it
  leans toward rebooting sooner; so does an update whose unsigned sources
  named no CVE at all, since nothing signed says what it fixes. It is
  logged as a `feed` event, `none`, and the update goes ahead.

### werewolf's own fixes

A fix to werewolf's own code, in fence or init for example, has no CVE, so
by the rules above it would wait 28 days. So werewolf keeps its own
advisories, one line each, in `release/advisories`, added in the commit
that makes the fix:

```
WW-2026-001  2026-10-07  high  fence: what was wrong, in a line
```

- **Every image carries the file**, as `/usr/share/werewolf/advisories`: it
  knows exactly which of werewolf's fixes its own code has.
- **A release's manifest carries it too**, signed with the rest, as
  `"advisories": [{"id", "date", "tier", "title"}]`.
  `release/manifest` refuses a release whose file has a line it cannot
  read, and the updater refuses a manifest with an advisory it cannot
  check, as for any other malformed field.
- **A machine applies each advisory its own image lacks**, at its tier, its
  title the evidence. Nothing compares dates or serials, which a machine
  cannot know of its own image, since a release is signed after it is
  built; and a machine from a release disk that never updated is right the
  first time.

The manifest's parser already ignores fields it does not know, so the
format stays `werewolf-release/1`; an older updater ignores the list. Only
the release path has advisories: a user-built form gets werewolf's code
only when its user rebuilds it.

### The spread

Each machine reboots at an offset within its tier's time. The offset is the
first 8 bytes of SHA-256(machine ID ‖ build), taken modulo the time:

- Urgent: within 15 minutes of its `seen`.
- High: within the High time of its `seen`.
- Medium and Low: within the window they fall in, 3 hours by default.

The offset is deterministic, so a machine that restarts its updater keeps
its time. It differs per build, so the same machine is not always first.
The machine ID is the data volume's UUID, or the hostname where there is no
data volume.

On top of that, **no update reboot within an hour of boot**, except on a
machine's first check: a slot due sooner waits for the hour to pass, and
`why` says so. Counting from boot, by the kernel's clock, needs no state,
and covers a reboot for any reason, so nothing a CVE source says can reboot
a machine more than once an hour.

### First boot

The first check on a machine whose `autoupdate/log` is empty (it has never
checked) treats anything it stages as Urgent, with a spread of at most 2
minutes. A new machine has no users and no state, so rebooting it costs
nothing.

A machine without a persistent `/data` updates nothing: init mounts an
empty, read-only `/data` there, the updater cannot set up, and so it never
stages, let alone reboots.

Services are not held back until that check finishes. That would tie
booting to the network, and a disk from the latest release usually has
nothing to apply. A first check that fails is logged as `error`, and the
next follows an hour later.

### Settings

Two files, read once at the updater's start, each one strict JSON object:

```json
{"window": "sun,wed 03:00-05:00", "high": "1h", "medium": "14d", "low": "28d"}
```

| Key | Means | Default | Limit |
| --- | --- | --- | --- |
| `window` | when Medium and Low boot: `daily` or days such as `sun,wed`, and UTC hours, an hour at least; a range may wrap past midnight (`23:00-02:00`) | `daily 02:00-05:00` | |
| `high` | High's time | `4h` | `24h` |
| `medium` | Medium's wait | `7d` | `28d` |
| `low` | Low's wait | `28d` | `90d` |
| `limits` | a form's only: `{"high": ..., "medium": ..., "low": ...}`, each no higher than werewolf's | | |

- **The form's**, `/etc/werewolf/update-policy.json` in the image, fixed
  when it is built. It sets the form's defaults and may lower any limit: a
  form for a regulated service might hold `medium` to `7d`. A limit below
  its time brings the time down with it.
- **The operator's**, `update-policy.json` at the top of the config tar,
  beside `hostname`, so `/run/config/update-policy.json`, readable by root
  alone. It may set anything within the limits the form leaves. It holds
  nothing secret.
- **All or nothing.** An unknown key, a key given twice, a value of the
  wrong type or above its limit, or a file over 32 KiB refuses the whole
  file, naming the key, and the settings stay as they were. A missing file
  changes nothing. Nothing can switch updates off, and Urgent has no
  setting.
- **A refused form's file stops the operator's.** Its lowered limits are
  lost with it, so the operator's file is not read either, rather than
  checked against werewolf's wider limits; both are logged as refused.
- **One parser,** `lib/update-policy.zig`, so the host's `werewolf pack`
  checks an operator's file before it ever reaches a machine.

### Draining

A form that sits behind a load balancer sets `/etc/werewolf/drain-seconds`
(say, 30). Before an update reboot, the updater:

1. creates `/run/werewolf/draining`;
2. logs `drain`;
3. waits that long, then reboots.

A form's health endpoint reports unhealthy while the file exists, which
gives the load balancer time to move traffic away. Forms that set nothing,
`prod` included, which listens on nothing, reboot at once.

### The audit log

An auditor should be able to answer, from the log alone and without
reading code:

- **For any fix:** when did this machine first see it, what tier did it
  get and on what evidence, which rule and which setting set its wait,
  when was the reboot due, and when did the machine run it?
- **For any reboot:** why then, and not sooner or later?
- **For any moment:** what settings were in force, and what was waiting to
  boot?

The log is `/data/svc/autoupdate/log`, one JSON line per event, written
also to the service's output with an `autoupdate:` prefix, as today. Four
rules make it auditable:

1. **Inputs, not just results.** An event that makes a decision carries
   what it decided from: the score and where it came from, KEV's date, the
   setting and who set it, the feed's serial.
2. **Every wait is stated three ways:** `due`, the time, RFC 3339 in UTC;
   `due_in`, the seconds left when logged; and `why`, one plain sentence
   that walks from evidence to rule to time, with durations an auditor can
   read ("12d 13h 38m").
3. **State is restated every hour.** Each check logs what is staged and how
   long until it boots, so a gap in the log shows as a gap, and "what was
   pending on the 9th?" has an answer from that day.
4. **Lines are chained.** Each has `seq`, counting up from the first line
   the machine wrote, and `prev`, the first 16 hex digits of the SHA-256
   of the line before it. Editing or deleting a line breaks the chain from
   there on. That proves nothing against root on the machine, who can
   rewrite the whole chain, but it does once the head is held elsewhere:
   the console copy, which clouds keep (GCP's serial port output), or the
   log shipped off the machine ([roadmap](../roadmap.md), item 4).

Every line has `time`, `host`, `seq`, `prev` and `event`:

| Event | When | Fields |
| --- | --- | --- |
| `policy` | the updater starts | `settings`: each one's `value`, `source` (`werewolf`, `form` or `operator`) and `limit`; `refused`: each file refused, with its `key` and why |
| `feed` | the tiers feed is fetched | `serial`, `expires`, `result` (`ok`, `unchanged`, `kept`, `none`), `reason` (why not a new one: `BadSignature`, `Expired`, `Older`, a failed fetch), and with `none`, `consequence` ("every fix counts as High") |
| `check` | every check | `result` (`current`, `staged`, `skip`), and while a slot is staged: `build`, `tier`, `due`, `due_in` |
| `stage` | a build is staged | `slot`, `build`, `tier`, `seen` (per tier), `fixes` (count per tier), `due`, `due_in`, `why`, `report` |
| `tier` | a staged fix's tier rises | `build`, `fix`, `cause` (the evidence: the new score and its source, or KEV's listing date), `feed`, `from`, `to`, `was_due`, `due`, `due_in`, `why` |
| `drain` | before an update reboot | `build`, `seconds` |
| `reboot` | the updater reboots | `build`, `tier`, `cause` (`due` or `first-boot`), `due`, `late` (seconds past `due`, normally 0), `why` |
| `commit`, `rollback` | after the reboot | as today, plus `waited`: for each tier, its `seen` and the seconds from it to this commit |
| `error` | a step fails | as today |

`update` becomes `stage`.

A machine's log through one fix, abridged to the fields that matter here:

```json
{"time":"2026-10-07T00:00:05Z","event":"policy","settings":{"window":{"value":"daily 02:00-05:00","source":"werewolf"},"high":{"value":"4h","source":"werewolf","limit":"24h"},"medium":{"value":"14d","source":"operator","limit":"28d"},"low":{"value":"28d","source":"werewolf","limit":"90d"}},"refused":[]}
{"time":"2026-10-07T14:02:11Z","event":"stage","build":"0123456789abcdef","tier":"medium","fixes":{"medium":1,"low":3},"due":"2026-10-22T03:41:07Z","due_in":1258736,"why":"Medium: CVE-2026-1111 in busybox, no score yet, first seen 2026-10-07T14:02:11Z. The operator's medium wait is 14d, then the window, daily 02:00-05:00 UTC, where this machine's place is 1h 41m 7s in. Due 2026-10-22T03:41:07Z, in 14d 13h 38m."}
{"time":"2026-10-07T15:02:13Z","event":"check","result":"staged","build":"0123456789abcdef","tier":"medium","due":"2026-10-22T03:41:07Z","due_in":1255134}
{"time":"2026-10-09T08:02:10Z","event":"tier","cve":"CVE-2026-1111","from":"medium","to":"high","cause":"NVD scored it 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)","feed":"20261009T080000Z","was_due":"2026-10-22T03:41:07Z","due":"2026-10-09T10:47:52Z","due_in":9942,"why":"High: CVE-2026-1111 in busybox, CVSS 8.1 from NVD, first seen 2026-10-09T08:02:10Z. werewolf's default high time is 4h, where this machine's place is 2h 45m 42s in. Due 2026-10-09T10:47:52Z, in 2h 45m 42s."}
{"time":"2026-10-09T10:47:52Z","event":"reboot","build":"0123456789abcdef","tier":"high","cause":"due","due":"2026-10-09T10:47:52Z","late":0,"why":"High fix CVE-2026-1111 due 2026-10-09T10:47:52Z; also boots 3 Low fixes waiting since 2026-10-07T14:02:11Z."}
{"time":"2026-10-09T10:49:30Z","event":"commit","slot":"b","build":"0123456789abcdef","waited":{"high":{"seen":"2026-10-09T08:02:10Z","seconds":10040},"medium":{"seen":"2026-10-07T14:02:11Z","seconds":161239},"low":{"seen":"2026-10-07T14:02:11Z","seconds":161239}}}
```

**The report** (`reports/TIME-BUILD.json`) is the per-fix record and is
not rewritten. For each CVE it adds the tier and its evidence: `tier`,
`score`, `vector`, `score_source` (`nvd`, `cna` or `cisa-adp`), `kev` (the
date CISA listed it, or null), the feed's `serial`, `seen` and `due`. A
later change of tier is the `tier` event's to record.

**Size.** An hourly `check` line is about 250 bytes, about 2 MB a year;
`stage` and `tier` lines are rarer. The log is kept whole: an auditor's
year fits in a few MB of `/data`.

`status-page` reads `stage` where it read `update`, and shows what is
staged, its tier, and its `due` and `why`.

### What changes

- **`cmd/slot-update/slot-update.zig`:**
  - the daemon's sleep becomes "next check or due";
  - `check` ends at `stage`, and a new pass reboots when due;
  - the `pending` file, with each tier's `seen`;
  - skipping an already-staged build;
  - disarming the try before `install` writes;
  - the window, the spread, the rate limit, and the settings files;
  - the audit log: the new events, `why` sentences, and `seq` and `prev`.
- **`cmd/slot-update/cve.zig`:** the feed's fetch, signature check and
  reader, and finding Urgent and High fixes from it.
- **`cmd/slot-update/release.zig`:** the manifest's `advisories`.
- **CI:**
  - a new Zig program, `tools/cve-tiers.zig`, builds the feed from KEV,
    NVD, `security.json` and the kernel records;
  - `release.yml` signs it with the tiers key and publishes it with the
    manifests, re-signs it daily, and writes `advisories` from a file in
    the repository.
- **`forms/prod`:** `tiers.pub`.
- **Tests:**
  - unit tests for the tier rules, `seen` carried forward, windows
    (wrapping midnight included), the spread, the rate limit, the settings
    parser and its limits, and the feed's checks, expired and forged feeds
    included;
  - unit tests for the log: each event's fields, `why` for every tier and
    setting source, durations as text, and the chain, a deleted line
    included;
  - `make check-updater` grows a case that stages without rebooting, then
    reboots when due, against a feed CI's test key signs.
- **`cmd/status-page/status-page.zig`:** `stage` for `update`, and what is
  staged and when.
- **Docs:** `docs/updater.md`, with a section for auditors that maps their
  usual questions to events; and the settings in `docs/cloud.md`'s config
  tar.

## Drawbacks

- **More state and more cases.** A staged slot that has not booted, times
  that survive restarts, a window, and settings to parse. Today's updater
  has none of these.
- **Medium and Low fixes wait much longer:** a week and four weeks, where
  today every fix waits at most 20 hours. That is the price of not
  rebooting nightly, and an operator who wants shorter waits can set them.
- **CI becomes the tiering authority for every machine,** user-built forms
  included. Its outage, or a stale feed, makes every update High: more
  reboots, never fewer fixes.
- **Unplanned reboots take staged fixes.** An operator rebooting a sick
  machine also changes its software, which can confuse an investigation.
  The `commit` and `rollback` events say which build booted.
- **A severe bug that is not yet scored waits like a Medium one,** until it
  is scored or CISA lists it as exploited: up to a week at the defaults,
  if neither happens first. Most kernel CVEs fall here at first.
- **CVSS is coarse.** A miscored CVE gets the wrong tier. A CVSS 6.5 that
  matters on a given form waits a week.
- **Advisories are a new duty.** Someone must decide the tier of each of
  werewolf's own security fixes, and write it down, when it lands.
- **Hourly checks cost the mirrors.** On the packages path each check
  fetches Wolfi's index; that cost must be measured
  ([Open questions](#open-questions)).

## Alternatives Considered

### Reboot at once for every update, hourly

The simplest design: today's behaviour, checked more often. But Wolfi
changes some package almost every day, so a machine would reboot most
nights, mostly for fixes that could wait. Setting `high 0h`, `medium 0d`
and `low 0d` comes close to it for an operator who wants it.

### Deadlines for every tier

Medium within a week and Low within a month, at most, rather than at least.
Each fix would then reboot at the first window after it arrived, since
there is no reason to wait for the deadline. With Wolfi's pace that is
nearly nightly. A minimum wait batches a week's routine fixes into one
reboot.

### Settings that may only tighten

Safer against a stolen cloud credential, which could otherwise set the
ceilings. But operators running services that cannot reboot weekly need to
lengthen the waits, and a policy they cannot fit to their service is one
they will switch off another way. The limits keep the worst case bounded:
Urgent untouched, High at most a day, Medium at most four weeks.

### CVSS alone

CVSS rates how bad a bug would be if exploited, not whether anyone is
exploiting it. KEV is the strongest public signal of the latter. Using both
costs one more input, KEV, a file of about 1 MB.

### Tiering on each machine

Each machine could fetch KEV and NVD, or run a scanner such as grype. Every
machine would then parse more untrusted data, NVD rate-limits clients
without a key, and a fleet's machines could disagree about the same
release. A feed signed in CI keeps the machine's parsing to one file whose
signature is checked first.

### The tier in the release manifest alone

Simpler for the release path. But it covers only release forms, and only
the step from the previous release, while a machine several releases behind
needs the union. The feed covers both paths; the manifest carries only
what has no CVE.

### Anchor times at the release

Counting from the release's `serial`, not from `seen`, measures exposure
from when the fix existed. That is better on paper. In practice a machine
that was offline for three days comes back past every deadline and reboots
at once, as does every other machine that went offline in the same outage,
together. Counting from when the machine first saw a fix keeps reboots
spread, and an Urgent fix still lands within 15 minutes of the machine
seeing it.

### Signing the feed with the image key

One key fewer to keep, rotate and publish. But the image key decides what a
machine runs, and the feed only when it reboots: a leak of a key that signs
every day should cost timing, not code. A separate key keeps them apart,
and lets the feed's key rotate without touching releases.

### kexec, or restarting services

kexec would skip the firmware, but it would also skip the bootloader's
one-try-then-fall-back, which is what makes an update safe to apply
unattended. Restarting services cannot change an immutable root.

### Switching userspace without a reboot

A "soft reboot", as systemd calls it: stop every service, open the staged
slot's root through dm-verity, `pivot_root` into it and exec its `/init`,
keeping the running kernel. That would skip firmware, bootloader and
kernel, for any update that leaves the kernel, its arguments and modules
alone. werewolf's hardening rules it out, on purpose: nothing that runs
after boot can become something else.

- **PID 1 is sandboxed for good.** init execs `fence`, which execs runit
  under a Landlock domain that allows exec only beneath the old root's
  `/usr` and refuses `mount`, `umount` and `pivot_root`. A Landlock domain
  cannot be left, so PID 1 can never exec the new root's init.
- **The seal is one-way.** PID 1 carries init's seccomp filter, with its
  listener, and a bounding set without `CAP_SYS_MODULE` and the rest. A new
  init could not install its own seal, which is fatal by design, and would
  run under the old image's filter: an update needing a call the old
  pledges refused would break.
- **Boot state is not idempotent.** fence adds its routing rules one by one
  and fails on any that exist; stage0 names its dm device `root`; init
  mounts `/run` afresh over the old one.

The one design that works keeps stage0 as PID 1 for the machine's life: an
unsandboxed supervisor that starts init as its child, and on a switch opens
the new root and starts the new init. That moves runit off PID 1, makes
fence and the mounts idempotent, and leaves a fully privileged process
running forever, where today nothing privileged outlives boot but the
mount broker and the ten-minute deadman. Its gain is the firmware and
kernel's share of a reboot, which on a cloud VM is seconds to tens of
seconds. Not worth it now; worth measuring a reboot on each cloud first,
and asking again with verified boot, when a signed root hash would let a
supervisor check what it switches to.

### A runtime hold

A way to freeze updates during an incident needs a channel into a machine
that has no shell and reads its config only at boot. It would also be one
more way to switch updates off. Not now.

## Security Considerations

- **Urgent and High rest on signed data.** The feed names their fixes, so
  the unsigned sources can only add CVEs, which brings a reboot sooner. A
  hostile or broken `security.json` can at worst make a Medium fix look
  Low, three more weeks at the defaults, or invent CVEs, which costs at
  most one reboot an hour.
- **The feed is signed, expires, and has its own key.** If that key leaks,
  the attacker controls only timing: an Urgent fix can be made to wait as
  long as Low's limit allows, 90 days at most. If the image key leaks, the
  attacker controls what runs. The two are kept apart, and the feed key can
  rotate on its own schedule. A feed that stops updating expires within
  days, and then every fix counts as High.
- **Settings are bounded, not tighten-only.** Whoever sets the instance's
  user data can lengthen the High, Medium and Low times up to their limits,
  never past them, and cannot touch Urgent. That person can already replace
  `authorized_keys`; a form that must not allow even that lowers the limits
  in its image.
- **Arming a staged slot gives an attacker nothing.** An attacker who can
  force a reboot only moves the machine to newer bits, which the slot's
  checks have already verified.
- **The exposure window on first boot** runs from boot to the first check:
  about a minute for the slot to commit, plus the check. A disk from an old
  release serves on its old bits for those minutes. Holding network-facing
  services until the first check would close that window, at the cost of
  booting only with the network.
- **What Theo would ask:** "Why wait at all?" Because an hourly check would
  otherwise reboot machines nightly, and operators who face that turn
  updates off. The tiers wait only for what is neither exploited nor
  known to be severe, the waits have ceilings, a fix moves up as soon as
  it is scored, and without a valid feed every fix counts as High.
- **Blind spot: code compiled into a user's form.** The machine cannot see a
  CVE in a static binary, so the policy cannot cover it. This is
  documented, not solved.

## Reliability Considerations

- **Reboots are cheap and safe here.** Slots, one try each, `slot-keep` and
  the deadman make a bad update cost one more reboot and a rollback. The
  rate limit keeps a source that misbehaves from causing a reboot loop.
- **Routine reboots are predictable.** Medium and Low reboot only in the
  window, at most weekly with the defaults; Urgent and High are the only
  reboots outside it.
- **Fleets.** The spread keeps a release from rebooting every machine in
  the same minute. An Urgent fix still restarts a whole fleet within 15
  minutes; an SRE would rather roll that out in waves, but this design does
  not coordinate machines, and draining is what it offers. Fleets that need
  waves can stagger their windows.
- **One default window for everyone.** 02:00–05:00 UTC is night in Europe
  and Africa, evening in the Americas and morning in Asia. Every machine
  that keeps the default spreads its Medium and Low reboots over those 3
  hours; a fleet whose quiet hours differ sets its own window.
- **Failures lean toward security.** A missing feed makes updates High:
  more reboots, not fewer fixes. A network outage stalls updates exactly as
  it does today.
- **Clocks.** Times are stored in UTC. The daemon sleeps on the monotonic
  clock and compares against `due` each time it wakes, so a clock that
  jumps forward can bring a reboot early, at most once an hour.
- **Observability.** `waited` on `commit` gives the time from first seen
  to running per tier; `late` flags a missed `due`; the hourly `check`
  shows what is pending and for how long; `policy` shows what a form or
  operator set; and a gap in `seq`, or an hour with no `check`, shows the
  updater was not running.

## Limits

- An application compiled into a user's form changes only when the user
  rebuilds the image. Following their own signed releases, as CI's forms do,
  would need a release pipeline of their own.
- Tiers are only as good as KEV and NVD. Neither covers Alpine's kernel
  patches that have no CVE.

## Open questions

- **Where to publish for a large fleet:** GitHub's raw file server is fine
  for now; a fleet of thousands checking hourly may want the same two
  files on a CDN, such as Cloudflare R2, which machines would fetch the
  same way.

- **Cost of an hourly check on the packages path:** measure what an
  unchanged check fetches from Wolfi, and whether apk revalidates its index
  or downloads it again.
- **The drain signal:** should `draining` be a file a form's health check
  reads, or something `status-page` and service forms expose for it?
