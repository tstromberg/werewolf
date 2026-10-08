# SFTPGo

The `sftpgo` form is `prod` with SFTPGo 2.7, serving SFTP and nothing
else: no shell, no commands, no FTP, WebDAV or web admin.

| | |
| --- | --- |
| Listens | tcp/22, SFTP |
| Sends | nothing |
| Runs as | `sftpgo` (uid 212), leashed |
| Keeps | each user's files in `/data/svc/sftpgo/users/NAME`, its database beside them, and its host key, made on the first boot (`id_ed25519`), whose fingerprint is on the console at every boot |
| Config | `sftpgo/users.json`: the users, each with a key and the permissions it has in its own directory |

```json
{"users": [{"username": "alice", "status": 1, "home_dir": "/data/svc/sftpgo/users/alice",
  "public_keys": ["ssh-ed25519 AAAA... alice"],
  "permissions": {"/": ["list", "download", "upload", "overwrite", "delete", "rename", "create_dirs"]}}]}
```

The file is SFTPGo's own backup format, loaded before each start, adding
and updating users; a user removed from it stays until a load with
`--loaddata-mode 2` in a form of your own, or until `sftpgo` is told.

## Defaults

- **Keys only**, Ed25519 and its FIDO form; no passwords, no
  keyboard-interactive. Three tries, then the defender bans the address.
- **Post-quantum key exchange only** (`mlkem768x25519-sha256`), as the
  bastion requires: OpenSSH from 9.9 and PuTTY from 0.83 connect; older
  clients are turned away.
- `chacha20-poly1305@openssh.com` and `aes256-gcm@openssh.com`;
  `hmac-sha2-256-etm@openssh.com`; the host key Ed25519.
- No SSH commands, no shell: `ssh user@host` is refused, only `sftp` is
  served; idle sessions end after 15 minutes.
- Nothing listens but SFTP: the web admin, REST API, telemetry, FTP and
  WebDAV are off.

## Checked

`make check-sftpgo` makes a key for the run and a user for it
([test/config-sftpgo](../test/config-sftpgo)); from the host, test/boot
puts a file, lists, and gets it back as it went, and sees a shell, a
remote forward, a password and a non-post-quantum exchange refused. On
the machine, [test/checks-sftpgo](../test/checks-sftpgo) finds the host
key and database `sftpgo`'s, nothing else listening, and the file where
the user's directory is.
