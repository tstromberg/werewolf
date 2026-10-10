# Jellyfin

The `jellyfin` form serves your media: [Jellyfin](https://jellyfin.org)
12.2 behind Caddy, which serves it over HTTPS for your domain with a
certificate from Let's Encrypt, the media copied in over ssh onto `/data`,
each part on a leash of its own
([design/forms-catalog.md](../../docs/design/forms-catalog.md)).

## Run your own

You need a domain name you can point at the machine, and a security key
for ssh, as `prod-ssh` takes ([docs/forms.md](../../docs/forms.md)).

```sh
openssl rand -base64 24 >jellyfin-password    # its administrator's; keep it
howl create media --with jellyfin --on gcp --allow-from 0.0.0.0/0 \
	--domain media.example.com --jellyfin-admin alice \
	--jellyfin-password jellyfin-password \
	--users.alice.keys "$(cat ~/.ssh/id_ed25519_sk.pub)" --users.alice.admin
```

Point `media.example.com` at the address howl prints, then copy the media
in as root, whose keys are an admin's:

```sh
scp -r Movies root@media.example.com:/data/svc/jellyfin/media/
```

and sign in at `https://media.example.com` as `alice`. The library `Media`
is that directory; Jellyfin scans it on its schedule, or at once from its
dashboard.

| Flag | |
| --- | --- |
| `--domain NAME` | required. Caddy's site, with a certificate from Let's Encrypt |
| `--jellyfin-admin NAME` | required. The administrator the first-run wizard makes |
| `--jellyfin-password FILE` | required. Its password, 12 bytes at least, never printed or logged |
| `--users.NAME.keys LINE`, `--users.NAME.admin` | who may log in over ssh, with a security key, to copy media in |

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Jellyfin on loopback; the ACME CA |
| Jellyfin, .NET | `jellyfin` | nothing: it listens on loopback alone |
| ffmpeg, ffprobe | Jellyfin's, narrowed | nothing; its directory alone |
| sshd | `root`, by security key | :22 |

- **No wizard left open.** Jellyfin's first-run wizard makes its first
  administrator for whoever reaches it first. `jellyfin-setup wizard`
  ([cmd/jellyfin-setup](cmd/jellyfin-setup/jellyfin-setup.zig)) runs
  before Caddy, on loopback: it completes the wizard with the
  administrator from the config and adds the library. Only then does
  Caddy start, and anyone reach Jellyfin.
- **Loopback, and nothing out.** `jellyfin-setup network` tells Jellyfin
  once to listen on loopback alone, to trust Caddy as its proxy, and not
  to discover or map ports. fence lets Jellyfin connect nowhere: no
  metadata from the internet, no plugin catalog, no telemetry.
- **Strangers' files parsed narrowed.** Jellyfin runs ffmpeg and ffprobe
  on every file, by their narrow links
  ([design/narrow.md](../../docs/design/narrow.md)): their own pledge, no
  network, Jellyfin's directory alone, and ffmpeg 1 GiB.
- **.NET's JIT.** `allow: [jit]` turns MDWE off for the whole machine, a
  weakness this form names; .NET's write-xor-execute double mapping is
  off too, as it would need memfds the seal refuses.

## Drawbacks

- No metadata or artwork from the internet: titles come from file names
  and what the files carry.
- One administrator account to start; more are made in the dashboard.
- Transcoding is the CPU's: no GPU on these machines.

## Checked

`make check-jellyfin` boots it with its test config ([test/config](test/config)),
domain `localhost`, for which Caddy's own CA signs: the wizard is
complete before Caddy serves, the administrator signs in, the wizard
refuses a stranger through Caddy, the library is the media directory,
and fence has no line for Jellyfin to connect anywhere. `make
check-shellfree-jellyfin` boots it as it ships, with no config: Jellyfin
starts on loopback, and Caddy parks, saying it has no administrator's
password, before the wizard is touched or a port opened.
