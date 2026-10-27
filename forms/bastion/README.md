# Bastion - Hardened VM

A forwarding-only SSH server. Users open TCP forwards with a security key, to
destinations named in the form, and nothing else: no shell, no command, no file copy.
The destination authenticates them again. The form's manifest is
[form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/bastion/index.html).

## Security Posture

- sshd runs as its own user. There is no shell. The root is read-only.
- Security keys only, touched at each login. No passwords, and no root login.
- No session: no shell, SFTP, remote forward, or agent forward.
- Each key reaches only that user's destinations.
- The host key is made once on `/data`. With no disk, sshd stays down.

### Weaknesses

- sshd is how users get in. It opens no session.
- Port forwarding is what a bastion is for.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create bastion --with bastion
```

This form has no users. A form of your own names them. A key is one line of a `.pub`
file. A destination is a literal address and port. Everyone logs in as `bastion`.

```yaml
base: bastion

bastion:
  users:
    alice:
      keys:
        - sk-ssh-ed25519@openssh.com AAAA... alice@laptop
      destinations: [10.20.0.10:22]
```

Create that form and jump through it. The host-key fingerprint is on the console at
every boot. Connecting is in [OpenSSH's manual](https://man.openbsd.org/ssh).

```text
ssh -J bastion@ADDRESS you@10.20.0.10
```

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create bastion --with bastion --on gcp --allow-from me
```

`--allow-from me` opens port 22 to your address. Deploy the form that names your
users, with the same `--on` and `--allow-from`.

### Importing data

Who may reach what is in the form. There is no database to import, and no session to
copy a file through.

### Known Quirks

- A key file is refused until `sshd.pubkey-accepted-algorithms` includes it. That
  fails posture until the form says why.
- A destination on a port other than 22 needs `connect bastion tcp/PORT` in the
  form's network.
- At most 256 users, with 32 keys and 32 destinations each. Hostnames are refused.
- Edit the form and create again to change a user.

### Network Exposure

- listen: tcp/22 *
- connect: tcp/22 global
