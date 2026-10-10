# Overleaf

The `overleaf` form is collaborative LaTeX: [Overleaf Community
Edition](https://github.com/overleaf/overleaf) 6.3, from Overleaf's own
image, with MongoDB 8.0 from its own, Valkey and Caddy beside it, serving
HTTPS at your URL with a certificate from Let's Encrypt. Each part is on a
leash of its own, and the compiler, which runs what its users write, is
apart from the rest ([design/academic.md](../../docs/design/academic.md)).

Overleaf publishes its image for x86_64 alone, so the form is
`archs: [x86_64]`: no Arm machine, Graviton or Ampere, runs it.

## Run your own

You need a domain name you can point at the machine, and 8 GB of memory.

```sh
mkdir -p config/overleaf
openssl rand -base64 24 >config/overleaf/admin-password   # you sign in with it
howl create latex --with overleaf --on gcp --allow-from 0.0.0.0/0 \
	--config config --base-url https://latex.example.com \
	--admin-email you@example.com
```

Point `latex.example.com` at the address howl prints and sign in with
your email. Make accounts for others under Admin, Manage users; Overleaf
mails each a link to set a password when `--email-from`, `--smtp-host`,
`--smtp-port` and `--smtp-user` (and `config/overleaf/smtp-password`) name
a mail server, and shows you the link when they do not.

The administrator is made once, when the database is new, before
Overleaf serves anything; a later start keeps it as it is.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; web, real-time and clsi's nginx on loopback; the ACME CA |
| Overleaf's services | `_oci-overleaf`, in the image | each other, MongoDB, Valkey, clsi on loopback; a mail server |
| clsi and its nginx | `_oci-clsi`, in a copy of the image | Overleaf's file stores on loopback |
| MongoDB | `_oci-mongo`, in its image | itself |
| Valkey | `valkey` | nothing |

- **No unclaimed first boot.** `/launchpad` makes the first administrator
  in Overleaf's own setup; here the config's is made before web starts,
  so the page sends a stranger to sign in. Overleaf takes no sign-ups.
- **Compiles apart.** TeX runs what a document says, so clsi runs as a
  user of its own, in its own copy of the image and its own `/data`:
  it holds none of the secrets the services share (the session key among
  them), and cannot reach MongoDB or Valkey. TeX may read only its project
  and TeX Live (`openin_any=p`), write only beneath it, and run only TeX
  Live's restricted helpers (`shell_escape=p`): `\write18` runs nothing a
  document names. Of the image, clsi may run nginx, TeX Live, and what
  latexmk and TeX start (perl, sh, qpdf, pdftocairo), and nothing else.
- **No runit, bash or setuser.** `overleaf-start`
  ([rootfs/oci/overleaf/werewolf](rootfs/oci/overleaf/werewolf)) does what
  the image's init scripts did: makes the services' secrets once, in
  `/data`; makes MongoDB a replica set; runs the migrations; makes the
  administrator; starts the ten services, and stops them all if one
  exits, so runsv starts them again; and flushes histories as its cron
  did. `clsi-start` starts clsi and its nginx.
- **Caddy in front** routes as the image's nginx did; Overleaf's metrics
  and health checks are not served.
- **Nothing fetched for a user**: linked files from URLs stay off, as
  upstream ships them.
- MongoDB and Valkey are on loopback TCP, as the services in their image's
  root cannot see a socket; only Overleaf's services may reach them.
- Node's V8 needs `allow: [jit]`, which turns MDWE off machine-wide, a
  weakness this form names.

## Drawbacks

- The image is 3 GB, twice over (clsi's copy), with MongoDB's 0.9 GB:
  a large root, built slowly.
- TeX Live is the image's: `scheme-basic`, with no `tlmgr` (the root is
  read-only). A document needing more packages fails to compile.
- Compiles share one user, as upstream's do: a project's TeX could read
  another's compile directory by a path it may not name (`openin_any`
  stops `\input` of one), so give accounts to people you would trust with
  each other's drafts. Overleaf's sandboxed compiles are Server Pro's.
- Projects deleted by their owners are kept: upstream's cron deletion is
  off by default, and stays so.
- The doc-version recovery scripts the image runs after an upgrade from
  5.0 are not run: start on 6.x.

## Checked

`make ARCH=x86_64 check-overleaf` boots it with its test config
([test/config](test/config)), base URL `https://localhost`, for which
Caddy's own CA signs: Overleaf answers through Caddy over HTTPS, the
administrator signs in and reaches the admin pages, `/launchpad` and
`/register` make no account, clsi runs as another user without the
services' secrets, and a project whose `main.tex` runs `touch` by
`\write18` and tests for `/etc/hostname` compiles to a PDF, served by
clsi's nginx, with TeX refusing both and no file made.
`make ARCH=x86_64 check-shellfree-overleaf` boots it as it ships, with no
config: no posture failure but those named, the rest up, and Overleaf
parked, saying it has no administrator's password, before it migrates or
serves anything.
