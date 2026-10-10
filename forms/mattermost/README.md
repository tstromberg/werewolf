# Mattermost

Team chat: [Mattermost](https://mattermost.com) Team Edition 11.7, the extended-support release, with PostgreSQL and Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create chat --with mattermost --on lima \
	--base-url https://chat.home.arpa --admin alice \
	--admin-email alice@example.com --admin-password admin-password
```

Sign in as `alice` and make a team. The first start migrates the database, so give it a few minutes.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create chat --with mattermost --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://chat.example.com --admin alice \
	--admin-email alice@example.com --admin-password admin-password
```

Point the name at the machine with an A record. Invite people with the team's link. Mail is off until you set SMTP in System Console. `--admin` is 3 to 22 characters of lowercase letters, digits, `.`, `-` and `_`. The password is 12 to 72 bytes.

### Known Quirks

- Open sign-up is off. A stranger needs an invitation.
- Plugin uploads are off. A plugin is code.
- The admin is created before Caddy opens the port. A later start does not reset the password.
- Wolfi's Mattermost package lags upstream. This form runs the image's 11.7 line.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Mattermost and PostgreSQL are on loopback. Mattermost may call public addresses on 443.

### Security Weaknesses

- PostgreSQL may compile a query. Named in `form.yaml`.
