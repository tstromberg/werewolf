# mox - Hardened VM

[mox](https://github.com/mjl-/mox) is the mail server: SMTP, submission, and IMAP, plus a web admin. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/mox/index.html).

## Security Posture

- mox runs as its own user. The root is read-only. Mail lives on `/data`.
- The admin password and the relay password are files, not flags.
- There is no shell, and no mailbox import.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
printf '%s' 'the SMTP password' >relay-password
howl create mox --with mox --domain example.com --postmaster alice \
	--admin-password admin-password --relay-server smtp.example.com \
	--relay-login postmaster --relay-password relay-password
```

Open `https://example.com` and sign in as the postmaster. Mailboxes and DNS are in [mox's documentation](https://github.com/mjl-/mox).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
printf '%s' 'the SMTP password' >relay-password
howl create mox --with mox --on gcp --allow-from me --domain example.com \
	--postmaster alice --admin-password admin-password \
	--relay-server smtp.example.com --relay-login postmaster \
	--relay-password relay-password
```

`--allow-from me` admits your address to the mail ports and to 443. Point the domain's MX at the machine.

### Importing data

Mail starts empty. There is no mailbox import. Accounts are in the create command.

### Known Quirks

- The relay password file has no newline.
- The domain is the machine's mail name. It is not a flag you can change later.

### Network Exposure

- listen: tcp/25 *
- listen: tcp/443 *
- listen: tcp/465 *
- listen: tcp/587 *
- listen: tcp/993 *
