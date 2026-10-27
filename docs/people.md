# People and SSH accounts

## People

A form that runs sshd takes root's keys from the boot config (`--root-keys`). A
manifest can also name accounts, with security keys, and make some admins, whose keys
log in as root too:

```yaml
users:
  tom:
    keys: [sk-ssh-ed25519@openssh.com AAAAGnNr... tom@yubikey]
    admin: true
```

`users: {alice: {}}` is an account without keys; an admin must have keys. prod-ssh
and playground include `ssh-su` for root reauthentication using a forwarded agent. It
installs the SSH client and keeps the existing listener. Production requires FIDO
presence and verification. See [su](../forms/ssh-su/README.md) for client setup and
the explicit software-key policy for local VMs. People are never in the image: howl
packs them into the boot config, init makes each an account (uid mapped from its name
into `[65536, 2^30)`, NoCloud's kept in 500-60000; home on `/data`) and writes its
keys where sshd looks; `net` grants them all as `:people`. Names and IDs stay
reserved in `/data/.werewolf/identities` after removal; cloud metadata locks absent
people and reapplies active keys as they change. Services have distinct users;
components of one application may share one with `shared-user: true` on each, which
shares files, processes and network policy while Landlock, seccomp and limits stay
per service.

When `users` is absent, `howl run` and `howl create` default to adding the current
local user with the public keys in `~/.ssh` accepted by the form's SSH policy.
`--add-current-user=auto|yes|no` controls this: `auto` respects any explicit
`users`, including an empty map or config file; `yes` adds the current user
alongside other accounts, preserving an existing declaration for that name;
`no` disables the addition. This does not grant `admin`. Lima keeps its NoCloud
user, and developer SSH remains root-only. `howl pack --on TARGET` applies the
same default; without a target, pack requires `--add-current-user=yes`.
