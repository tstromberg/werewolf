# Samba - Hardened VM

File shares over SMB: [Samba](https://www.samba.org), one directory per user. The form's manifest is [form.yaml](form.yaml).

## Security Posture

- Share logins must name real, non-root UNIX accounts. smbd runs as its own user; share files belong to that service user. The root is read-only. Files live on `/data`.
- SMB3 only. Encryption and signing are required. NetBIOS is off.
- There is no guest and no anonymous login. A share names its one user.
- Printers are off. A share does not follow a symlink out of itself.
- smbd sets its umask to 0 and applies the share's create mask itself. A new file is mode 0600.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
mkdir -p config/samba
printf '%s\n' alice >config/users
printf '%s\n' "alice:$(openssl rand -base64 18)" >config/samba/users
howl create samba --with samba --config config
```

`config/users` declares real UNIX accounts without SSH keys. A manifest can instead declare `users: {alice: {}}`, or cloud metadata can supply accounts. Each line of `config/samba/users` is `name:password`, and the account must already exist. The share has that name. A client is in [Samba's documentation](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html).

```text
smbclient //ADDRESS/alice -m SMB3 --client-protection=encrypt -U alice
```

On QEMU, howl reports `127.0.0.1:PORT`: use `//127.0.0.1/alice` and add `-p PORT` to the client command. On Lima or a cloud VM, use the server's IP address.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
mkdir -p config/samba
printf '%s\n' alice >config/users
printf '%s\n' "alice:$(openssl rand -base64 18)" >config/samba/users
howl create samba --with samba --on gcp --allow-from me --config config
```

`--allow-from me` admits your address to port 445.

### Adding or changing users

Add the UNIX account and its SMB password to the same config, then run the original `howl create` command again, with the same machine name and deployment options:

```sh
printf '%s\n' bob >>config/users
printf '%s\n' "bob:$(openssl rand -base64 18)" >>config/samba/users
howl create samba --with samba --config config
```

The machine restarts with the complete user list. Bob can then connect to `//ADDRESS/bob`. Edit a user's password to rotate it, or remove their line to revoke access. Existing files on `/data` are kept, including files belonging to removed users. No image rebuild or reinstall is needed; the account IDs stay stable across config changes. Cloud UNIX account changes are applied every minute, but changed Samba credentials and shares take effect at the next boot, or after updating the local config and restarting the service. Keep the `config/samba/users` file private; it contains plaintext passwords.

### Importing data

There is no database to import. After the share answers, copy files in with an SMB client. Each user's files are that user's directory.

### Known Quirks

- A password is ASCII, 8 to 128 characters, with no colon. A trailing newline on the file is the end of the last line.
- Changing `config/samba/users` and creating again replaces the passwords. A directory already on `/data` is kept.
- The address is the server. There is no NetBIOS name.

### Network Exposure

- listen: tcp/445 *
