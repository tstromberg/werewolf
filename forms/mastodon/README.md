# Mastodon

The `mastodon` form is a Mastodon 4.7 server: HTTPS for your domain from
Let's Encrypt, its owner made from your settings, each part on a leash of
its own ([design/mastodon.md](../../docs/design/mastodon.md)).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- ruby and node run Mastodon, which is what this form is for
- PostgreSQL compiles costly queries to machine code with LLVM (allow jit, from postgresql)

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >owner-password
howl create mastodon --with mastodon \
	--domain social.home.arpa --owner alice --owner-email alice@example.com \
	--owner-password owner-password
```

Point the name at the address howl prints and sign in at `https://social.home.arpa` as `alice@example.com`. The first start makes the database and the owner. Sign-ups stay closed.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >owner-password
howl create mastodon --with mastodon --on gcp --allow-from me \
	--domain social.example.com --owner alice --owner-email alice@example.com \
	--owner-password owner-password
```

`--allow-from me` admits your address to ports 80 and 443. The default machine has the 4 GB Mastodon needs. Mail, and a wider allowance, are below.

### Migrating data in

PostgreSQL has no TCP port. `--import` attaches a directory of SQL. It is applied once, in the `postgres` database, while the cluster is first made. See [postgresql](../postgresql/README.md). `CREATE DATABASE` is not available there. The same directory may hold `dump.rdb` for Valkey. A cloud cannot attach the disk.

```sh
openssl rand -base64 24 >owner-password
howl create mastodon --with mastodon \
	--domain social.home.arpa --owner alice --owner-email alice@example.com \
	--owner-password owner-password --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the service after it is up.

### Network Exposure

tcp/80 tcp/443


## Run your own

You need a domain name you can point at the machine, and a cloud account
howl can use ([docs/cloud.md](../../docs/cloud.md)).

```sh
openssl rand -base64 24 >owner-password     # you sign in with it; keep it
howl create social --with mastodon --on gcp --allow-from 0.0.0.0/0 \
	--domain social.example.com --owner alice --owner-email alice@example.com \
	--owner-password owner-password
```

howl prints the machine's address. Point the domain at it, an `A`
record for `social.example.com`, and sign in at
`https://social.example.com` with `alice@example.com` and the password.
The first start makes the database and the owner, which takes about a
minute; Caddy gets the certificate once the domain resolves to the
machine, and retries until it does. `--on aws` and `--on azure` work the
same; the default machine has the 4 GB Mastodon needs.

| Flag | |
| --- | --- |
| `--domain NAME` | required. The server's name, `@alice@NAME`, for good: a later start with another is refused |
| `--owner NAME` | required. The owner's username, made confirmed, approved and Owner on the first start |
| `--owner-email ADDRESS` | required. The owner's sign-in address |
| `--owner-password FILE` | required. The owner's password, never printed or logged |
| `--single-user true` | One person's server: the front page is the owner's profile |
| `--smtp-server`, `--smtp-port`, `--smtp-login`, `--smtp-from`, `--smtp-password FILE` | Mail, by an e-mail provider's relay ([below](#mail)) |

`howl pack --with mastodon -h` lists them, with werewolf's own
(`--hostname`, `--data-key` and the rest). To change a running machine's
flags, run its `howl create` line again: howl replaces its config and
restarts it. Sign-ups are closed, as Mastodon ships; once mail works, the
owner may open them, by approval, under Administration.

## Mail

Mastodon sends mail, confirmations, password resets and notifications,
and receives none. Do what most Mastodon servers do, and Mastodon's own
guide advises: send through an e-mail provider's SMTP relay, such as
Mailgun, Postmark, SendGrid, SparkPost or Amazon SES. A mail server of
your own on a cloud address starts with no reputation, and GCP, and AWS
and Azure until you ask, block the port it would send from. At the
provider, add your domain, set the SPF, DKIM and DMARC records it gives
you, and make an SMTP credential that may only send. Then give the
create line its relay:

```sh
printf '%s' 'the SMTP password' >smtp-password
howl create social --with mastodon --on gcp --allow-from 0.0.0.0/0 \
	--domain social.example.com --owner alice --owner-email alice@example.com \
	--owner-password owner-password \
	--smtp-server smtp.postmarkapp.com --smtp-port 587 --smtp-login 'the SMTP user' \
	--smtp-from notifications@social.example.com --smtp-password smtp-password
```

Mail leaves on port 587 with STARTTLS required and the relay's
certificate checked; only the jobs, which send it, hold the password.
Without these flags no mail leaves.

## Before it serves

The web's `before` lines run as `mastodon`, under its leash, at each
start. `secrets.rb` makes the secrets once, `SECRET_KEY_BASE`, the
encryption keys and a VAPID pair, into `/data/svc/mastodon/env`, 0640,
with the domain; Mastodon reads it as `.env.production`, a link in the
image. `rails db:prepare` makes the schema or migrates it. `owner.rb`
grants the streaming server's role its reads and, if the owner is
missing, makes it. No one meets a setup page.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Puma and streaming on loopback; the media, to read |
| web, Puma | `mastodon` | its database and Valkey; public addresses |
| streaming, Node, no JIT | `mastodon-stream` | its database, read-only, and Valkey |
| jobs, Sidekiq | `mastodon-jobs` | its database and Valkey; public addresses, mail |
| cleanup, supercronic and tootctl | `mastodon-cron` | its database and Valkey |

- **One user each**, so a bug in one part holds only that part's files.
  The web's directories are `share group` (02771, with a default ACL):
  the jobs' and cron's users have its group and write the media and read
  the secrets there; Caddy reads the media by name.
- **The database by role**, each by peer authentication as its user:
  `mastodon` owns it, the jobs' and cron's roles are its members,
  `mastodon-stream` may only read. Valkey's socket is its group's, which
  the four join (`group valkey`).
- **Media parsed narrowed.** Paperclip runs `file`, `ffprobe` and
  `ffmpeg` through `/bin/sh`, which is `sh-shim`; each is the service's
  narrow link ([design/narrow.md](../../docs/design/narrow.md)): no
  network, its own pledge, the upload's directory alone.
- **Public addresses only.** fence keeps federation, previews and remote
  media off private, loopback, link-local and metadata addresses.
- PostgreSQL's `allow: [jit]` turns MDWE off for the whole machine, a
  weakness this form names.

## Drawbacks

- In a DEV build `/bin/sh` is busybox's, which no leash lets run, so
  uploads and media processing fail there (cmd/sh-shim).
- No search and no object storage (design/mastodon.md's Non-Goals).

## Checked

`make check-mastodon` boots it with its test config
([test/config](test/config)), domain `localhost`, for which Caddy's own
CA signs: Mastodon answers `/health` over HTTPS, the instance is the
config's, the owner exists, streaming answers, plain HTTP is sent to
HTTPS, the assets are served, fence lets the jobs out, the jobs hold the
relay's settings and password, and the secrets are 0640 in a 02771
directory. `make check-shellfree-mastodon` boots it
as it ships, with no config: no posture failure but those named, the
streaming server listening, and the web parked, saying it has no owner,
before it makes or serves anything.
