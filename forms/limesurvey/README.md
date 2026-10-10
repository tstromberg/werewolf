# LimeSurvey

Surveys and research data: [LimeSurvey](https://www.limesurvey.org) 7.5, its tables in MariaDB. The 6.x line is no longer supported. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- PHP runs LimeSurvey. That is named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
htpasswd -nbB x "$(cat admin-password)" | cut -d: -f2 >admin-password-hash
howl create limesurvey --with limesurvey \
	--url https://surveys.home.arpa --title 'Department surveys' \
	--admin-email it@example.edu --admin-password-hash admin-password-hash
```

Open the address howl prints, port 80, and sign in with the password in `admin-password`. The form stores the hash, never the password. Put TLS in front; it serves plain HTTP and trusts `X-Forwarded-Proto`. Surveys are in [LimeSurvey's manual](https://www.limesurvey.org/manual/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
htpasswd -nbB x "$(cat admin-password)" | cut -d: -f2 >admin-password-hash
howl create limesurvey --with limesurvey --on gcp --allow-from me \
	--url https://surveys.example.edu --title 'Department surveys' \
	--admin-email it@example.edu --admin-password-hash admin-password-hash
```

Open `https://surveys.example.edu` once the name and TLS are in front of port 80. Mail and a directory are optional: `--smtp HOST:PORT`, `--smtp-user`, `--smtp-password`, `--mail-from`.

### Migrating data in

The database has no TCP port. `--import` attaches a directory of SQL. MariaDB applies it once, while it makes the data directory. See [mariadb-local](../mariadb-local/README.md). A cloud cannot attach the disk.

```sh
howl create limesurvey --with limesurvey --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the service after it is up.

### Known Quirks

- It installs itself before it serves, and refuses tables newer than the image, so a rolled-back slot cannot open them.
- Plugin upload is off. Plugins load only from the image.
- Theme uploads stay on, for a department's branding. LimeSurvey unpacks no PHP from them.
- A forged Host header is refused.

### Network Exposure

- tcp/80, nginx. Mail may leave on port 587, and a directory on port 636, when you name them.
