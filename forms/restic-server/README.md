# restic-server

A place restic sends backups: [rest-server](https://github.com/restic/rest-server), append-only, from restic's own image, behind Caddy. Each user can see only the repository of their own name, and cannot delete a snapshot. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >laptop-password
htpasswd -nbB laptop "$(cat laptop-password)" >restic-users
howl create restic-server --with restic-server \
	--domain backup.home.arpa --restic-users restic-users
```

There is no web page. On the machine you are backing up, with the password from `laptop-password`:

```text
export RESTIC_REPOSITORY=rest:https://laptop:PASSWORD@backup.home.arpa/laptop/
restic init && restic backup ~
```

Snapshots, forget and prune are in [restic's documentation](https://restic.readthedocs.io/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >laptop-password
openssl rand -base64 18 >nas-password
htpasswd -nbB laptop "$(cat laptop-password)" >restic-users
htpasswd -nbB nas "$(cat nas-password)" >>restic-users
howl create restic-server --with restic-server --on gcp --allow-from me \
	--domain backup.example.com --restic-users restic-users
```

Point the name at the machine. Add a line and run create again to add a user. Repositories already on `/data` stay. Forget and prune are done by a restic that is allowed to, which this server is not.

### Migrating data in

This machine starts empty. Point restic at the address howl prints. There is no repository to copy in.

### Known Quirks

- The repository name in the URL is the username. `laptop` cannot open `nas`.
- Append-only means a backup can be added and read, not deleted, from this server.
- There is no web page. restic is the client.
- The image is pinned by digest at each build.

### Network Exposure

- tcp/80 and tcp/443, Caddy. rest-server is on loopback.
