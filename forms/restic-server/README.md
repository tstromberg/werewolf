# restic-server

A place restic sends backups: [rest-server](https://github.com/restic/rest-server), append-only, from restic's own image, behind Caddy. Each user can see only the repository of their own name, and cannot delete a snapshot.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
htpasswd -nB laptop >restic-users
howl create backup --with restic-server --on lima \
	--domain backup.home.arpa --restic-users restic-users
```

`htpasswd -nB` is bcrypt and asks for the password. On the machine you are backing up:

```sh
export RESTIC_REPOSITORY=rest:https://laptop:PASSWORD@backup.home.arpa/laptop/
restic init && restic backup ~
```

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
htpasswd -nB laptop >restic-users
htpasswd -nB nas >>restic-users
howl create backup --with restic-server --on gcp --allow-from 0.0.0.0/0 \
	--domain backup.example.com --restic-users restic-users
```

Point the name at the machine. Add a line and run create again to add a user. Repositories already on `/data` stay. Forget and prune are done by a restic that is allowed to, which this server is not: a stolen client password cannot erase history.

### Known Quirks

- The repository name in the URL is the username. `laptop` cannot open `nas`.
- Append-only means a backup can be added and read, not deleted, from this server.
- There is no web page. restic is the client.
- The image is pinned by digest at each build.

### Network Exposure

- tcp/80 and tcp/443, Caddy. rest-server is on loopback.
