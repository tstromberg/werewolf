# zot

The `zot` form is `prod` with [zot](https://zotregistry.dev) 2.1, an
OCI image registry for your own images, behind Caddy, which serves it
over HTTPS for your domain. Every request names its user; each user
pulls, and only those you name push.

| | |
| --- | --- |
| Listens | tcp/80 and tcp/443, Caddy's; zot on loopback alone |
| Sends | nothing but Caddy's ACME requests |
| Runs as | `zot` and `caddy`, each leashed |
| Keeps | the images in `/data/svc/zot`, one copy of each blob |
| Config | `zot/htpasswd`, htpasswd lines, bcrypt (`htpasswd -nB NAME`); settings `pushers` (required), `domain` (required) |

## Run your own

You need a domain name you can point at the machine.

```sh
htpasswd -nB ci >htpasswd          # one line a user; -B is bcrypt
htpasswd -nB deploy >>htpasswd
howl create registry --with zot --on gcp --allow-from 0.0.0.0/0 \
	--domain registry.example.com --htpasswd htpasswd --pushers ci
```

Point `registry.example.com` at the address howl prints. Then:

```sh
docker login registry.example.com -u ci
docker push registry.example.com/app/web:1.0
```

`ci` pushes; `deploy`, on the machines that run the image, only pulls.
To add a user, add a line and run the create line again: howl replaces
the config and restarts the service; the images on `/data` stay.

## Defaults

- **No anonymous access.** No users built in: with no `htpasswd` file zot
  parks before it binds, saying so. A wrong password costs five seconds.
- **Pull for all, push for few.** Each user reads every repository; the
  `pushers` push, overwrite tags and delete. A pull credential stolen
  from a deploy machine cannot replace an image.
- **The registry alone.** melange builds upstream's `zot-minimal`: no
  search, sync (mirroring), UI or metrics extension is in the program,
  so no config line turns one on, and it fetches nothing.
- **Only `/v2/` is served.** Caddy answers anything else with 404, so
  zot's health and metrics endpoints stay on loopback.
- **Docker's manifests are taken** as well as OCI's (`compat:
  docker2s2`), so `docker push` works as it does elsewhere.
- **Storage**: deduplicated by hard link; blobs no manifest holds are
  collected daily, an hour after their last use; each write is synced
  before zot answers, so a power cut loses no pushed layer.
- **Built here.** Wolfi does not ship zot: melange builds it from the
  release's commit with Wolfi's Go ([melange/zot.yaml](melange/zot.yaml)).

## Drawbacks

- No web UI and no search: `crane ls`, `crane catalog` or `skopeo` list
  what is there. The UI is a separate download (zui) the build leaves
  out.
- Users are htpasswd lines: no LDAP, OIDC or API keys, which need the
  extensions left out.
- A pusher may push to every repository; per-repository policies are a
  list of objects, which no setting holds yet.
- Until Wolfi takes the recipe, every release is werewolf's to rebuild.

## Checked

`make check-zot` boots it with its test config ([test/config](test/config)),
domain `localhost`, for which Caddy's own CA signs: zot runs as its own
user without capabilities; a stranger and a wrong password get 401;
Caddy serves `/v2/` alone; alice pushes an image with crane, trusting
Caddy's CA, and bob pulls it back by digest; fence has no line for zot.
The attacks: a stranger can neither pull nor push, and bob, who only
pulls, can neither replace alice's tag nor delete her image.
`make check-shellfree-zot` boots it as it ships, with no config: zot and
Caddy park, each saying why.
