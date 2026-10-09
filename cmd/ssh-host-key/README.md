# ssh-host-key

## Summary

ssh-host-key makes a leashed sshd's host key on the machine's first boot,
keeps it in `/data`, and logs its fingerprint on every start. The machine
keeps one ssh identity for life, and an operator can pin it.

## Background

werewolf's root is read-only and the same on every machine, so a host key
cannot live in `/etc/ssh` as on other distros. The bastion form runs sshd
under leash, as an unprivileged user, with its key in `/data/svc/sshd`
(the service's `before` line). The key is made on the machine, never on a
laptop, so the private half never leaves it.

## Goals

- One key per machine, made once, kept across reboots and updates.
- Never a new key each boot. That would change the machine's identity and
  teach operators to ignore ssh's warning.
- The fingerprint on the console at every start, never the private half.

## Non-Goals

- Key rotation, or key types other than Ed25519.
- Machines without a disk for `/data`: their sshd stays down.

## Detailed design

- **Run by leash** as a `before`, as the service's user, inside its
  Landlock rules: `ssh-host-key /data/svc/sshd/host-key`. KEY must be an
  absolute path.
- **Kept**: if the key exists, it is used. If its public half is missing,
  `ssh-keygen -y` makes it again from the key; it is written beside its
  place, synced, and renamed in.
- **Made**: only if the key's directory exists and is not on RAM (tmpfs).
  Leftovers of an interrupted run (`KEY.new`, `KEY.new.pub`) are removed,
  since ssh-keygen would prompt before overwriting them. `ssh-keygen -t
  ed25519` writes `KEY.new`; both halves are synced; the public half is
  renamed into place, then the key, then the directory is synced. If the
  key exists, the pair is whole.
- **Logs**: `ssh-host-key: {"event":"host-key","key":"…","from":"kept in
  /data","fingerprint":"SHA256:…","public":"ssh-ed25519 …"}`. `from` is
  `new, kept in /data` on the boot that made the key. The fingerprint is
  the SHA-256 of the key's decoded blob in unpadded base64, as
  `ssh-keygen -l` prints it.
- **Shared** with sshd-start through `lib/hostkey.zig`: the atomic make,
  the public-half repair, the fingerprint and the RAM check. Only
  ssh-keygen generates key material.
- **Fails** with the reason, which keeps sshd down: no `/data`, `/data` on
  RAM, an unreadable key, `ssh-keygen` failing.

## Drawbacks

- sshd's user owns the key, so a compromised sshd process can read it.
  That is the price of not running sshd as root.
- A machine without `/data` has no ssh.

## Alternatives Considered

### A key in the config tar
The private half would be made on a laptop and travel with every copy of
the tar.

### A new key each boot
Every boot would look like a machine-in-the-middle attack, and operators
would learn to accept the warning.

### ssh-keygen writing in place
This was the first design. An interrupted boot could leave a key without
its public half, or a truncated key, and every later boot kept it, so sshd
stayed down for good.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| The private half leaks | Made on the machine, mode 0600, never logged. |
| Identity changes each boot | Refused: no key is made on RAM. |
| A half-made key is kept forever | Made beside its place, renamed in, public half first. |
| ssh-host-key's privilege | The service's user, in its Landlock rules; it runs only ssh-keygen. |

## Reliability Considerations

- **Whole or absent**: an interrupted first boot leaves no key, so the next
  boot makes one.
- **Repairs**: a lost public half is made again from the key.
- **Tested**: the second boot of `check-sshd` and `check-prod-ssh`
  (test/check-form) must offer the fingerprint the first boot logged.
