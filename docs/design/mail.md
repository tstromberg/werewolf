# Mail

Built, 2026-10-09 ([forms/mox](../../forms/mox/README.md)); proposed that
day. Mastodon sends by relay ([mastodon.md](mastodon.md)).

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

Wolfi ships postfix, exim, rspamd, and unbound, which brings bash; it
has no dovecot and no all-in-one server.
[Mox](https://github.com/mjl-/mox) (MIT, Go, v0.0.17, 2026-08) is one
binary with all of it: SMTP in and out, IMAP, webmail, SPF, DKIM and
DMARC with reports, MTA-STS, DANE, a per-account Bayesian junk filter,
ACME, and an admin page that prints and checks the DNS records.

## Goals

- `howl create mail --with mox`, plus the DNS records it prints, means
  mail to `@DOMAIN` arrives and can be read in Thunderbird or webmail.
  Mail it sends passes SPF, DKIM and DMARC at Gmail.
- No root, no exec, writes only `/data/svc/mox`, egress only to DNS and
  public addresses, no password on the console or in a log.
- `make check-mox`: mail on :25 is kept, a submission DKIM-signed and
  queued for the relay, open relaying refused, posture clean.

## Non-Goals

- Making a cloud address reputable; the relay is the answer there.
- Calendars, contacts, JMAP and search, which Stalwart has; virus
  scanning, since clamav parses strangers' files (later, narrowed).
- Mailing lists, off-machine backup, and a second machine.

## Detailed design

| User | Listens | Reaches |
| --- | --- | --- |
| `mox` | tcp/25 465 587 993 443 | tcp/25 465 587 443 public; DNS |

**Package.** A melange recipe, pinned by sha256 as Mastodon's is. Mox
never runs as root here. Upstream, a root parent binds the ports and
execs `mox serve` as `mox` with them from fd 3 (`MOX_SOCKETS`); started
unprivileged without them, mox refuses
([#194](https://github.com/mjl-/mox/issues/194), open, agreed by its
author). A patch has it bind its own ports instead (`mox.FilesImmediate`),
the low ones by leash's grant, as Caddy's, and put its control socket
where `MOX_CTL` says, in `/run`: fence lets sockets be made nowhere else.

**Config.** Mox splits its config, and the form keeps the split.

- `mox.conf`, static, is written at each start from settings by
  `mox-setup`, a small Zig program on a `before` line: host name,
  listeners (no plain IMAP), ACME contact, postmaster, relay, admin web
  on or off, `CheckUpdates` off (slots update mox).
- `domains.conf`, dynamic, is the admin web's to edit. On first start
  `mox quickstart` makes it, the DKIM keys and the first account; its
  output, which names the passwords it makes, is dropped.
- The admin password, from a file, is written each start as the bcrypt
  hash `AdminPasswordFile` names; the first account's is set in the admin web.
- Each start prints the DNS records (`mox config dnsrecords`), public
  data, to the console for `howl console mail`.

| Flag | |
| --- | --- |
| `--domain NAME` | required. The mail domain |
| `--mail-host NAME` | the MX and certificate name; `mail.DOMAIN` by default |
| `--postmaster NAME`, `--admin-password FILE` | required. The first account; the admin web's password (`--admin-web false` closes it once the accounts exist) |
| `--relay-server`, `--relay-port`, `--relay-login`, `--relay-password FILE` | send through a provider, as GCP needs: all mail, the domain's own too, as Mox delivers that by SMTP; without them mox sends on :25, which needs it open and a PTR record |
| `--tls-cert FILE`, `--tls-key FILE` | a certificate in Let's Encrypt's place (the check's) |

**Learned building it.** Nothing listens on :80: ACME's challenge is on
:443. The first start needs DNS, for quickstart. No resolver here checks
DNSSEC, which Mox trusts only from one, so outbound DANE is off; MTA-STS holds.

## Drawbacks

- One process holds every mailbox, where Postfix splits its work.
- A carried patch until upstream takes it; mox is pre-1.0, one author.
- The admin web faces the internet behind a password until closed.
- Blocklists, abuse reports and DNS stay the operator's job.

## Alternatives Considered

- **Stalwart** (Rust, AGPL-3.0) adds JMAP, CalDAV, CardDAV and search.
  It is heavier, keeps its config in its database where no setting can
  declare it, and sells some features. Choose it if calendars matter.
- **Maddy** (Go, GPL-3.0): SMTP and beta IMAP, no webmail or junk filter.
- **Postfix, Dovecot and rspamd**: no Dovecot in Wolfi; Postfix's master
  runs as root over chrooted daemons and setgid helpers; three configs.
- **leash as mox's parent**, passing it bound ports in `MOX_SOCKETS`: no
  patch, but new root code in leash, shaped to mox, and key files too.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A bug in SMTP, IMAP or MIME parsing | Go, built without cgo; own user, Landlock, no exec, pledge |
| Open relay | submission requires TLS and authentication |
| Password guessing | passwords from files; mox rate-limits failed logins per IP |
| A stolen account sends spam | mox's daily limits per account (1000 messages, 200 new recipients) |
| SSRF through MTA-STS or ACME | fence's `public` |

## Reliability Considerations

- Queue and mailboxes are on `/data`; senders retry, so reboots lose none.
- Open: Mox migrates its stores in place, and an older release may not
  read them, so a slot rolled back after an update may not start.
- A lapsed certificate stops IMAP clients and, under an enforcing
  MTA-STS policy, senders; mox renews over :443 and logs failures.
