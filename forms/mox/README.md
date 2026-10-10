# Mox

The `mox` form is a mail server for your domain: [Mox](https://github.com/mjl-/mox)
0.0.17, taking mail on port 25 and sending it signed, with IMAP, submission,
webmail and certificates from Let's Encrypt, on one leash
([design/mail.md](../../docs/design/mail.md)).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
printf '%s' 'the SMTP password' >relay-password
howl create mox --with mox --domain example.com --postmaster alice \
	--admin-password admin-password --relay-server smtp.example.com \
	--relay-login postmaster --relay-password relay-password
```

Point `mail.example.com` at the address howl prints, and publish the DNS records Mox prints on the console. Sign in at `https://mail.example.com/admin/` and set `alice`'s password. Clouds block mail leaving on port 25, so the relay sends it.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
printf '%s' 'the SMTP password' >relay-password
howl create mox --with mox --on gcp --allow-from me --domain example.com \
	--postmaster alice --admin-password admin-password \
	--relay-server smtp.example.com --relay-login postmaster \
	--relay-password relay-password
```

`--allow-from me` admits your address to the mail ports. A wider allowance, and the DNS records, are below.

### Migrating data in

Mail starts empty. Point delivery at the address howl prints. This form does not import a mailbox.

### Network Exposure

tcp/25 tcp/443 tcp/465 tcp/587 tcp/993


## Run your own

You need a domain whose DNS you can edit, and a cloud account howl can
use ([docs/cloud.md](../../docs/cloud.md)). Clouds block mail leaving on
port 25, GCP always, so give it an e-mail provider's relay to send
through, as most do ([below](#mail-out)).

```sh
openssl rand -base64 24 >admin-password      # the admin web's; keep it
printf '%s' 'the SMTP password' >relay-password
howl create mail --with mox --on gcp --allow-from 0.0.0.0/0 \
	--domain example.com --postmaster alice --admin-password admin-password \
	--relay-server smtp.postmarkapp.com --relay-login 'the SMTP user' \
	--relay-password relay-password
```

howl prints the machine's address. Then:

1. Point `mail.example.com` at it with an `A` record, and make the
   records Mox prints on the console at each start, under "DNS records
   for example.com" (`howl console mail --on gcp`): MX, SPF, DKIM,
   DMARC, MTA-STS, TLS reports and autoconfig. Add the relay's SPF
   `include:`, which the provider names, to the domain's SPF record.
2. Sign in to `https://mail.example.com/admin/` with the admin password,
   and set `alice`'s password under Accounts. The admin web checks the
   DNS records too.
3. Read and send as `alice@example.com` in any mail program, which finds
   IMAP on 993 and submission on 465 and 587 by autoconfig, or at
   `https://mail.example.com/webmail/`.

| Flag | |
| --- | --- |
| `--domain NAME` | required. The mail domain |
| `--postmaster NAME` | required. The first account, which also gets the postmaster's mail and the DMARC and TLS reports |
| `--admin-password FILE` | required. The admin web's password, 12 to 72 bytes |
| `--mail-host NAME` | the MX's name and its certificate's; `mail.DOMAIN` by default |
| `--relay-server`, `--relay-port`, `--relay-login`, `--relay-password FILE` | send through a provider: port 587 with STARTTLS by default, or 465 |
| `--admin-web false` | close `/admin/` |
| `--tls-cert FILE`, `--tls-key FILE` | a certificate of your own, in Let's Encrypt's place |

The first start runs `mox quickstart`: the domain, its DKIM keys and the
account, as Mox makes them. From then on `domains.conf` is Mox's: make
accounts, aliases and more domains in the admin web, and they are kept on
`/data`. `mox.conf` is written at each start from the flags: to change
them, run the create line again.

## Mail out

With a relay, every message leaves through it, over TLS Mox requires and
checks, even mail between the domain's own accounts, which goes out and
comes back in. Without one, Mox delivers on port 25 itself, which needs
the port open (AWS and Azure on request, or an address of your own) and a
PTR record naming the mail host. The relay's route is the only global
route the form makes or removes; routes made in the admin web are kept.

## How it is held

- **Never root.** Upstream, Mox starts as root, binds its ports and drops
  to its user. melange builds it with a patch so that, started as `mox`
  with leash's grant of ports below 1024, it binds them itself
  ([mjl-/mox#194](https://github.com/mjl-/mox/issues/194)), and makes its
  control socket in `/run/svc/mox`, where fence allows sockets.
- **Its own ports and paths.** It may bind 25, 443, 465, 587 and 993 and
  nothing else, reach DNS and public addresses on 25, 443, 465 and 587,
  write `/data/svc/mox` and `/run/svc/mox` alone, and run nothing.
- **Set up first.** `mox-setup` ([cmd/mox-setup](cmd/mox-setup/mox-setup.zig))
  runs before it, on its leash: quickstart once; `mox.conf` from the
  flags, 0600; the admin password as a bcrypt hash; leash's copies of the
  passwords removed; `mox config test` before Mox starts.
- **No password on the console.** Quickstart's output, which names the
  passwords it makes, is dropped, and the account's is unknown until the
  admin sets it.

## Drawbacks

- One process holds every mailbox.
- No resolver here checks DNSSEC: outbound DANE is off, MTA-STS holds.
- The admin web faces the internet behind its password until
  `--admin-web false` closes it.
- Blocklists, abuse reports and the address's reputation are yours; there
  is no backup off the machine.

## Checked

`make check-mox` boots it with its test config ([test/config](test/config)):
domain `example.com`, a certificate made there in Let's Encrypt's place,
and a relay that never answers. Mox answers SMTP on its ports and nothing
on :80; it keeps mail from a stranger and relays none for one; webmail and
the MTA-STS policy answer over TLS; mox-setup's files are Mox's alone and
the passwords' copies gone; and a message sent by Mox's web API is
DKIM-signed and queued for the relay. `make check-shellfree-mox` boots it
as it ships, with no config: no posture failure, and Mox parked, saying it
has no admin password, before anything is made.
