# Galène

The `galene` form is a videoconference server for lectures and seminars:
[Galène](https://galene.org) 1.2, from IRIF at Université Paris Cité,
with Caddy in front serving HTTPS at your URL with a certificate from
Let's Encrypt, each part on a leash of its own
([design/forms-catalog.md](../../docs/design/forms-catalog.md)).

## Run your own

You need a domain name you can point at the machine, and UDP port 10000
open to it beside 80 and 443.

```sh
openssl rand -base64 18 >operator-password   # the lecturer's; keep it
openssl rand -base64 9 >password             # the students'; hand it out
howl create lectures --with galene --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://meet.example.edu --groups cs101 --groups seminar \
	--operator ada --operator-password operator-password --password password
```

Point `meet.example.edu` at the address howl prints, and send students to
`https://meet.example.edu/group/cs101/`.

| Flag | |
| --- | --- |
| `--base-url URL` | required, `https://`. Caddy's site, and the links Galène makes |
| `--groups NAME` | required, once a room: each at `/group/NAME/`; letters, digits, `.`, `-`, `_` |
| `--operator NAME` | required. The lecturer: presents, mutes, removes, locks, records, invites |
| `--operator-password FILE` | required, 12 to 72 bytes. Never printed or logged |
| `--password FILE` | 8 to 72 bytes: everyone else joins with it, under any name, and may present. Without it the operator is alone, and invites others by link |
| `--recording true` | lets the operator record, to `/data/svc/galene/recordings` |
| `--ice-servers FILE` | Galène's `ice-servers.json`: a TURN server elsewhere, for students whose network refuses UDP |

To change a running machine's groups or passwords, run its create line
again: galene-setup writes every group anew at each start, and removes
those no longer named.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Galène on loopback; the ACME CA |
| Galène | `galene` | :8443 on loopback; udp/10000 for media; a TURN server on 3478 |

- **No room open to strangers.** Every group needs a password: the
  operator's by name, the others' under any name. No group is listed on
  the front page, none admits the anonymous, and none records unless
  `--recording true` says so.
- **Hashed before it serves.** galene-setup turns both passwords into
  bcrypt hashes in the group files and removes leash's plain copies; the
  form starts Galène only after it succeeds.
- **One media port.** Galène demultiplexes every call over udp/10000;
  fence delivers what arrives there and lets only Galène's user send from
  it.
- **No TURN of its own.** Galène's built-in TURN server relays to any
  address a client asks, from ports fence cannot declare, so it is off. A
  student behind a firewall that refuses UDP needs an external TURN
  server, named with `--ice-servers` (coturn with `use-auth-secret`);
  Galène reaches it on 3478 alone, and its relay test, patched, runs only
  when there is one, with mDNS off.
- **Behind Caddy.** Galène serves plain HTTP on loopback alone; Caddy
  carries its pages and WebSocket over TLS, which browsers need before
  they share a camera.
- **Built here.** Wolfi does not ship Galène: melange builds it from the
  release's commit with Wolfi's Go ([melange/galene.yaml](melange/galene.yaml)).

## Drawbacks

- Galène learns no public address: behind a cloud's 1:1 NAT, media flows
  once a client's checks reach udp/10000 (peer-reflexive candidates), as
  Galène's own documents describe. A client whose network blocks that
  needs the external TURN server.
- One password for all the others: a student who passes it on lets
  someone in. The operator can lock a room, or hand out invitation links
  instead of `--password`.
- IPv4 only, as werewolf's network is.

## Checked

`make check-galene` boots it with its test config ([test/config](test/config)),
base URL `https://localhost`, for which Caddy's own CA signs: the front
page and a named group answer through Caddy over HTTPS, plain HTTP is
sent to HTTPS, an unnamed group is not found, no group is listed, the
passwords are kept as hashes alone, the operator joins over Galène's
WebSocket protocol, a stranger guessing a password is refused, and
fence's line holds udp/10000 for Galène alone.
`make check-shellfree-galene` boots it as it ships, with no config: no
posture failure, Caddy up, and Galène parked, saying it has no operator's
password, before a group is written or anything is served.
