# restic-server

The `restic-server` form is `prod` with restic's REST server 0.14, the
backup target for your other machines, behind Caddy, which serves it
over HTTPS for your domain. It is append-only: a client adds snapshots,
but cannot delete or rewrite one, so a machine broken into cannot take
its backups with it.

| | |
| --- | --- |
| Listens | tcp/80 and tcp/443, Caddy's; rest-server on loopback alone |
| Sends | nothing but Caddy's ACME requests |
| Runs as | `_oci-restic-server` in restic's own image, and `caddy`, each leashed |
| Keeps | one repository a user in `/data/svc/restic-server/USER` |
| Config | `restic-server/restic-users`, htpasswd lines, bcrypt (`htpasswd -nB NAME`); setting `domain` (required) |

## Run your own

You need a domain name you can point at the machine.

```sh
htpasswd -nB laptop >restic-users     # one line a machine; -B is bcrypt
howl create backup --with restic-server --on gcp --allow-from 0.0.0.0/0 \
	--domain backup.example.com --restic-users restic-users
```

Point `backup.example.com` at the address howl prints. Then, on the
machine backed up:

```sh
export RESTIC_REPOSITORY=rest:https://laptop:PASSWORD@backup.example.com/laptop/
restic init && restic backup ~
```

A user reaches only the repository of its own name. To add one, add a
line and run the create line again: howl replaces the config and
restarts the service; the repositories on `/data` stay.

## Defaults

- **Append-only, always.** rest-server refuses every delete and every
  overwrite, so `restic forget` and `prune` fail from a client. A thief
  holding a client's password reads that client's backups (they hold the
  data anyway) but cannot destroy them.
- **Private repositories.** Each user's requests stay under `/USER/`.
- **No users built in**, and no `--no-auth`: with no `restic-users` file
  rest-server parks before it binds, saying so.
- **Uploads are verified.** rest-server checks each blob's hash as it
  arrives.
- **No metrics**, no outbound network: fence has no line for its user.
- **restic's own image**, pinned by digest, run in a tree of its own
  ([oci.md](../../docs/design/oci.md)): its entrypoint is a shell
  script, so leash runs `/usr/bin/rest-server` itself, and nothing else in
  the image can run.

## Pruning

Append-only means nothing on the network can remove a snapshot, this
form included: repositories grow until you prune them. Prune from a
machine you trust with the disk's files (restic's own advice), with the
repository's password: `restic -r /mnt/USER forget --keep-daily 7
--keep-weekly 5 --prune`. A prune service on this machine, with
credentials of its own that no client holds, is open (below).

## Drawbacks

- The repository password is the client's alone: the server holds
  encrypted packs, and cannot check or prune them by itself.
- Only bcrypt and `{SHA}` lines are accepted by rest-server; use bcrypt.
  `{SHA}` is unsalted SHA-1, quick to crack from a stolen file.
- Open: pruning on the machine. It needs a second rest-server, without
  `--append-only`, sharing the repositories, which image services cannot
  do yet.

## Checked

`make check-restic-server` boots it with its test config
([test/config](test/config)), domain `localhost`, for which Caddy's own
CA signs: a stranger and a wrong password get 401; alice makes her
repository and backs up to it with restic; bob cannot reach hers; fence
has no line for rest-server; and alice's credentials cannot delete her
snapshot, which is still there. `make check-shellfree-restic-server`
boots it as it ships, with no config: rest-server and Caddy park, each
saying why.
