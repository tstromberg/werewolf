# SFTPGo - Hardened VM

SFTP and nothing else: [SFTPGo](https://github.com/drakkan/sftpgo) 2.7. No shell, no commands, no FTP, WebDAV or web admin. The form's manifest is [form.yaml](form.yaml).

## Security Posture

SFTPGo runs as its own user. There is no shell. Landlock and seccomp hold it to port 22 and to `/data/svc/sftpgo`. The root is read-only.

- Keys only, Ed25519 and its FIDO form. No passwords.
- The key exchange is post-quantum (`mlkem768x25519-sha256`). OpenSSH from 9.9 and PuTTY from 0.83 connect. Older clients are turned away.
- `ssh user@host` is refused. Only SFTP is served. Idle sessions end after 15 minutes.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
mkdir -p config/sftpgo
printf '%s\n' '{"users":[]}' >config/sftpgo/users.json
howl create sftpgo --with sftpgo --config config
```

Replace `users.json` with SFTPGo's own backup format: each user, a public key, and the permissions in that user's directory. Files land in `/data/svc/sftpgo/users/NAME`. The host key's fingerprint is on the console at every boot. Users are in [SFTPGo's documentation](https://docs.sftpgo.com/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
mkdir -p config/sftpgo
printf '%s\n' '{"users":[]}' >config/sftpgo/users.json
howl create sftpgo --with sftpgo --on gcp --allow-from me --config config
```

`--allow-from me` admits your address to port 22. The same users file.

### Migrating data in

This machine starts empty. Clients upload to the address howl prints. The host cannot write `/data`.

### Known Quirks

- The file is loaded before each start, adding and updating users. A user removed from it stays until a form of your own loads with `--loaddata-mode 2`.
- Ciphers are `chacha20-poly1305` and `aes256-gcm`. The MAC is `hmac-sha2-256-etm`.

### Network Exposure

tcp/22
