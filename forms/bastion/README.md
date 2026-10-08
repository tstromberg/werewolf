# SSH bastion

A forwarding-only SSH server. Your users log in to it with a security key
and forward TCP connections to the destinations they are allowed, and
nothing else: no shell, no commands, no file copies, no remote forwards.
The destination authenticates them again, with its own users and keys.

Who may reach what is part of the image. You list the users, their keys
and their destinations in a form, and the build bakes them into the
verified, read-only root. To change a user, change the form and create
the machine again. The `bastion` form itself has no users and lets no one
in: build your own on it, as below.

## 1. A security key for each user

Each user makes a key on their own security key (a YubiKey, a SoloKey,
any FIDO2 key), touching it when it blinks:

```sh
ssh-keygen -t ed25519-sk -f ~/.ssh/id_bastion
```

The `.pub` file it writes is what the bastion takes. An older key may only
do `ecdsa-sk`: `ssh-keygen -t ecdsa-sk -f ~/.ssh/id_bastion`. A key file
(`ssh-keygen -t ed25519`) is refused unless you
[turn that off](#key-files-and-other-sshd-settings).

## 2. Your users

Start a form of your own in your checkout, `forms/edge/`, from the
bastion:

```sh
howl form --with bastion -o forms/edge
```

It writes `forms/edge/apko.yaml` and a `form.yaml` built on the bastion,
with what posture finds on any bastion, and why, copied in: a form states
its own (forms/README.md). Add your users to `forms/edge/form.yaml`, each
key pasted from a user's `.pub`:

```yaml
base: bastion

bastion:
  users:
    alice:
      keys:
        - sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t... alice@laptop
      destinations: [10.20.0.10:22, 10.20.0.11:22]
    bob:
      keys:
        - sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t... bob@yubikey
        - sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZA... bob@spare
      destinations: [10.20.0.12:22]

weaknesses:
  network-no-login: sshd, by security key, which forwards to the destinations form.yaml names and opens no session
  network-ssh-config: sshd forwards ports, which is what a bastion is for
```

Then make the machine:

```sh
howl create edge --with edge --on gcp --allow-from me
```

`--on` is any target howl knows: `lima`, `qemu`, `firecracker` and `bhyve`
on this machine, or `gcp`, `aws`, `azure` and `proxmox`. On a cloud,
`--allow-from me` opens port 22 to your address alone.

The rules, which the build checks and explains when one is broken:

- **A key** is one line of a `.pub` file, as `ssh-keygen` writes it: its
  type, its key, and a comment, which is dropped. Options (`command=`,
  `permitopen=`) are refused: the build writes those itself. A key
  belongs to one user.
- **A destination** is a literal address and port: `10.20.0.10:22`, or
  `[fd00::10]:22` for IPv6. Hostnames and wildcards are refused. A user
  reaches their own destinations and no one else's.
- **A port other than 22** needs the bastion to be allowed to connect to
  it: add it to the form's network policy, or give `--net` to `howl`.

  ```yaml
  net:
    - connect bastion tcp/5432
  ```
  ```sh
  howl create edge --with edge --on gcp --net 'connect bastion tcp/5432'
  ```
- **Names** are a-z, 0-9 and `-`, for telling users apart in the form.
  Everyone logs in as the account `bastion`; the key says who it is.
- At most 256 users, with up to 32 keys and 32 destinations each.

## 3. Connecting

Check the bastion's host key the first time. It is made on the machine's
first boot, kept on its `/data` disk, and printed on its console at every
boot:

```sh
howl console edge --on gcp | grep ssh-host-key   # "fingerprint":"SHA256:..."
```

Then jump through it to a destination, which asks for its own login:

```sh
ssh -i ~/.ssh/id_bastion -J bastion@BASTION_ADDRESS you@10.20.0.10
```

Or keep it in `~/.ssh/config`, then `ssh you@10.20.0.10`:

```
Host edge
  HostName BASTION_ADDRESS
  User bastion
  IdentityFile ~/.ssh/id_bastion

Host 10.20.0.*
  ProxyJump edge
```

To forward a port instead, for a database or a web console:

```sh
ssh -N -L 127.0.0.1:5432:10.20.0.12:5432 edge
```

`ssh edge` on its own is refused: the bastion opens no sessions.

## Key files and other sshd settings

The bastion takes security keys alone, and wants each one touched for
each login. To take key files too, for a job that has no security key to
touch, say which algorithms sshd takes, in form.yaml:

```yaml
sshd:
  pubkey-accepted-algorithms: ssh-ed25519,sk-ssh-ed25519@openssh.com
```

or on howl's command line:

```sh
howl create edge --with edge --on gcp --allow-from me \
  --sshd.pubkey-accepted-algorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
```

A user's key file in `bastion: users:` is refused at build until sshd
takes key files. `pubkey-auth-options: none`
(`--sshd.pubkey-auth-options none`) keeps security keys but no longer asks
for a touch.

Either change weakens the machine, and its posture check says so at every
boot: `network-ssh-security-keys` fails. Nothing excuses it for you. A
form that means it says why, beside the bastion's two:

```yaml
weaknesses:
  network-ssh-security-keys: the deploy job's key is a file on the CI runner
```

`sshd:` and `--sshd.` take other sshd_config settings the same way, each
named in lowercase with dashes: `client-alive-interval`, `max-auth-tries`,
`login-grace-time`, `log-level`, `ciphers`, `kex-algorithms` and the rest
of the list in [lib/sshd.zig](../../lib/sshd.zig). Settings that would run
a program or read another file are not on it.

## Changing users

Edit the form and run the same `howl create` again: the build makes a new
image and the machine boots it. Keep the form in git, and the machine's
users are what it says.

## What the bastion does not allow

- **No login but a key**, and that key a security key's, touched, unless
  the form says otherwise. No passwords, no keyboard-interactive, no
  host-based trust, no root.
- **No sessions**: no shell, no command, no SFTP, no terminal. No remote
  forwarding, agent forwarding, UNIX-socket forwarding or tunnels.
- **Only the destinations named**: each key is held to its user's
  destinations (`permitopen`), and sshd to all users' (`PermitOpen`).
  The network policy limits the ports it may connect to, whatever the
  address.
- **Post-quantum key exchange only** (`mlkem768x25519-sha256`,
  `sntrup761x25519-sha512`), so a recording of a session cannot be read
  later. A jump through it is a second connection, to the destination,
  which negotiates its own; see
  [OpenSSH's explanation](https://www.openssh.org/pq.html).
- **sshd runs as `bastion`** (uid 205), not root, held by Landlock and
  seccomp to what forwarding needs.
- **A verified, read-only root**: users change only with the image.
  Without a `/data` disk the bastion stays down rather than make a new
  host key at every boot.
