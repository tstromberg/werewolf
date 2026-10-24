# LimeSurvey - Hardened VM

Surveys and research data: [LimeSurvey](https://www.limesurvey.org) 7.5, its tables in
MariaDB. The 6.x line is no longer supported. The form's manifest is
[form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/limesurvey/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names. The
  root is read-only. `/data` is what survives.

### Weaknesses

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

Open the address howl prints, port 80, and sign in with the password in
`admin-password`. The form stores the hash, never the password. Put TLS in front; it
serves plain HTTP and trusts `X-Forwarded-Proto`. Surveys are in [LimeSurvey's
manual](https://www.limesurvey.org/manual/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
htpasswd -nbB x "$(cat admin-password)" | cut -d: -f2 >admin-password-hash
howl create limesurvey --with limesurvey --on gcp --allow-from me \
	--url https://surveys.example.edu --title 'Department surveys' \
	--admin-email it@example.edu --admin-password-hash admin-password-hash
```

Open `https://surveys.example.edu` once the name and TLS are in front of port 80. Mail
is optional: `--smtp HOST:PORT`, `--smtp-user`, `--smtp-password`,
`--mail-from`.

### Importing data

The database has no TCP port. `--import` attaches a directory of SQL. MariaDB applies it
once, while it makes the data directory. See
[mariadb-local](../mariadb-local/README.md). A cloud cannot attach the disk.

```sh
howl create limesurvey --with limesurvey --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the
service after it is up.

### Known Quirks

- It installs itself before it serves, and refuses tables newer than the image, so a
  rolled-back slot cannot open them.
- Plugin upload is off. Plugins load only from the image.
- Theme uploads stay on, for a department's branding. LimeSurvey unpacks no PHP from
  them.
- A forged Host header is refused.
- LDAP is omitted. A custom form can add `php-8.5-ldap` and its directory connection.
- Yii's URL-rule and database-schema caches require object deserialization;
  `php:deserialize` is granted only to LimeSurvey's PHP service.

### Network Exposure

- listen: tcp/80 *
- connect: tcp/587 global
