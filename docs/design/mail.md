# Mail

Proposed, 2026-10-09. Mastodon sends by relay ([mastodon.md](mastodon.md)).

## Summary

A `mox` form: one machine that receives a domain's mail, keeps its
mailboxes, serves IMAP, submission and webmail, and sends signed mail.
It is one Go program on one leash, using a relay where :25 is blocked.

## Background

A mail server is an MX on :25, mailboxes read by IMAP, submission
(:465, :587), delivery to other MXs on :25, SPF, DKIM, DMARC, TLS
(MTA-STS, DANE) and a spam filter: usually Postfix, Dovecot, rspamd and
Roundcube. Clouds block outbound :25 (GCP always, AWS and Azure until
asked), and a new address has no reputation, so Mastodon's guide, like
most, says to send through a provider. Receiving has neither problem.

Wolfi ships postfix, exim, rspamd and clamav. It has no dovecot, no
unbound, and no all-in-one server.
[Mox](https://github.com/mjl-/mox) (MIT, Go, v0.0.17, 2026-08) is one
binary with all of it: SMTP in and out, IMAP, webmail, SPF, DKIM and
DMARC with reports, MTA-STS, DANE, a per-account Bayesian junk filter,
ACME, and an admin page that prints and checks the DNS records.

## Goals

- `howl create mail --with mox`, plus the DNS records it prints, means
  mail to `@DOMAIN` arrives and can be read in Thunderbird or webmail.
  Mail it sends passes SPF, DKIM and DMARC at Gmail.
- No root, no exec, writes only `/data/svc/mox`, egress only to public
  addresses, no password on the console or in a log.
- Mastodon's `--smtp-server` can point at it.
- `make check-mox`: mail delivered on :25 is read back over IMAP, a
  submission is DKIM-signed, open relaying is refused, posture clean.

## Non-Goals

- Making a cloud address reputable; the relay is the answer there.
- Calendars, contacts, JMAP and search, which Stalwart has; virus
  scanning, since clamav parses strangers' files (later, narrowed).
- Mailing lists, off-machine backup, and a second machine.

## Detailed design

| User | Listens | Reaches |
| --- | --- | --- |
| `mox` | tcp/25 465 587 993 443, 80 to redirect | tcp/25 465 587 443 public; DNS |

**Package.** A melange recipe, pinned by sha256 as Mastodon's is. Mox
starts as root, binds its ports and re-execs as `mox`; running it
unprivileged is [#194](https://github.com/mjl-/mox/issues/194), open,
with the author's agreement. Until it lands, a four-line patch: started
unprivileged without `MOX_SOCKETS`, mox binds its own listeners
(`mox.FilesImmediate`). leash grants the low ports, as it does Caddy's.

**Config.** Mox splits its config, and the form keeps the split.

- `mox.conf`, static, is written at each start from settings by
  `mox-setup`, a small Zig program on a `before` line: host name,
  listeners (no plain IMAP), ACME contact, postmaster, relay, admin web
  on or off, `CheckUpdates` off (slots update mox).
- `domains.conf`, dynamic, is the admin web's to edit. On first start
  `mox quickstart` makes it, the DKIM keys and the first account, with
  its output (generated passwords) in a 0600 file.
- The admin password, from a file, is written each start as the bcrypt
  hash `AdminPasswordFile` names; the first account's is set in the admin web.
- Each start prints the DNS records (`mox config dnsrecords`), public
  data, to the console for `howl console mail`.

| Flag | |
| --- | --- |
| `--domain NAME` | required. The mail domain |
| `--mail-host NAME` | the MX and certificate name; `mail.DOMAIN` by default |
| `--postmaster NAME`, `--admin-password FILE` | required. The first account; the admin web's password |
| `--relay-server`, `--relay-port`, `--relay-login`, `--relay-password FILE` | send through a provider, as GCP needs; without them mox sends on :25, which needs it open and a PTR record |
| `--admin-web false` | close `/admin/` once the accounts exist |

**DANE.** Mox trusts DNSSEC only from a validating resolver. None ships,
so outbound DANE is off, and MTA-STS still applies, until a later design.

**Prototype first:** the patch, quickstart before the name resolves,
the pledge (`make seal-learn`), and a localhost certificate.

## Drawbacks

- One process holds every mailbox, where Postfix splits its work.
- A carried patch until #194 lands; mox is pre-1.0, with one main author.
- The admin web faces the internet behind a password until closed.
- Blocklists, abuse reports and DNS stay the operator's job.

## Alternatives Considered

- **Stalwart** (Rust, AGPL-3.0) adds JMAP, CalDAV, CardDAV and search.
  It is heavier, keeps its config in its database where no setting can
  declare it, and sells some features. Choose it if calendars matter.
- **Maddy** (Go, GPL-3.0): SMTP and beta IMAP, no webmail or junk filter.
- **Postfix, Dovecot and rspamd**: no Dovecot in Wolfi; Postfix's
  master runs as root over chrooted daemons and setgid helpers, which
  leash cannot hold; three configs.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A bug in SMTP, IMAP or MIME parsing | Go, built without cgo; own user, Landlock, no exec, pledge |
| Open relay | submission requires TLS and authentication |
| Password guessing | passwords from files; mox rate-limits failed logins per IP |
| A stolen account sends spam | mox's daily limits per account (1000 messages, 200 new recipients) |
| SSRF through MTA-STS or ACME | fence's `public` |

## Reliability Considerations

- Queue and mailboxes are on `/data`, and senders retry for days, so a
  reboot loses no mail.
- Mox migrates its stores in place; the check boots the old slot after
  the new one, since older releases may not open them.
- A lapsed certificate stops IMAP clients and, under an enforcing
  MTA-STS policy, senders; mox renews over :443 and logs failures.
