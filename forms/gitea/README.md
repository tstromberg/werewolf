# Gitea - Hardened VM

Git hosting: [Gitea](https://gitea.com) 1.26, with git as the one program it may run. The form's manifest is [form.yaml](form.yaml).

## Security Posture

Gitea runs as its own user. There is no shell. Landlock and seccomp hold it to its ports and to `/data/svc/gitea`. The root is read-only.

- Nothing runs a repository's code. Hooks a repository admin would write, Actions, the package registry and mirrors are off.
- Gitea's hooks are links to `gitea-hook`, which becomes `gitea hook`. Git does not run a shell.
- SSH is keys only, Ed25519, with a post-quantum key exchange. A session is told there is no shell.
- There is no installer and no registration. The administrator invites people.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/gitea
printf '%s' 'a long administrator password' >config/gitea/admin-password
howl create gitea --with gitea --config config \
	--url https://git.home.arpa/ --domain git.home.arpa --admin-email me@example.com
```

Open `https://git.home.arpa` once something serves TLS in front of port 3000. Sign in as `admin`. Git over SSH is port 22. Repositories are in [Gitea's documentation](https://docs.gitea.com/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/gitea
printf '%s' 'a long administrator password' >config/gitea/admin-password
howl create gitea --with gitea --on gcp --allow-from me --config config \
	--url https://git.example.com/ --domain git.example.com --admin-email me@example.com
```

Point the name at the address howl prints, and put TLS in front of port 3000. `--allow-from me` admits your address to ports 3000 and 22.

### Migrating data in

Repositories and the SQLite database are in `/data/svc/gitea`, and the host cannot write that directory. After this machine is up, push each repository over HTTPS or SSH, or use the site's migrate-from-URL.

### Known Quirks

- The password is at least 12 characters. Cookies are secure, so TLS is in front.
- Repositories are private until the administrator says otherwise.
- Mirrors and webhooks leave the machine only when a form of your own allows them out.

### Network Exposure

tcp/3000 tcp/22
