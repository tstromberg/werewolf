# ssh-host-key

## Summary

Makes a leashed sshd's host key on the machine's first boot, keeps it in
`/data`, and says its fingerprint on every start, so the machine has one
ssh identity for life and an operator can pin it.

## Background

werewolf's root is read-only and the same on every machine, so a host key
cannot live in `/etc/ssh` as a distro's does. The bastion form runs sshd
leashed, as its own unprivileged user, with its key in `/data/svc/sshd`
(the service's `before` line). The key is made on the machine, never on a
laptop, so its private half never leaves.

## Goals

- One key per machine, made once, kept across reboots and updates.
- Never a key made each boot: that would change the machine's identity, and
  teach operators to ignore ssh's warning.
- The fingerprint on the console every start, never the private half.

## Non-Goals

- Rotating keys, or more than one type: Ed25519 alone.
- Machines without a disk for `/data`: their sshd stays down.

## Detailed design

- **Run by leash** as a `before`, as the service's user, inside its
  Landlock rules: `ssh-host-key /data/svc/sshd/host-key`.
- **Kept**: if the key is there, it stands. If its public half is missing,
  it is made again from the key (`ssh-keygen -y`), written beside it,
  synced, and renamed into place.
- **Made**: only if the key's directory exists and is not on RAM (tmpfs).
  Leftovers of a cut-short make (`KEY.new`, `KEY.new.pub`) are removed;
  `ssh-keygen -t ed25519` writes `KEY.new`; both halves are synced; the
  public half is renamed into place, then the key, then the directory
  synced. The key's presence says the pair is whole.
- **Says**: `ssh-host-key: {"event":"host-key","from":"kept in
  /data","fingerprint":"SHA256:…","public":"ssh-ed25519 …"}`. The
  fingerprint is SHA-256 of the key's decoded blob in base64, as
  `ssh-keygen -l` gives it.
- **Shared** with sshd-start through `lib/hostkey.zig`: the whole-or-absent
  make, the rebuilt public half, the fingerprint and the RAM check.
  ssh-keygen makes every key.
- **Refuses** with the reason, and so keeps sshd down: no `/data`, `/data`
  on RAM, a key that cannot be read, `ssh-keygen` failing.

## Drawbacks

- The key belongs to sshd's user, so a taken-over sshd process can read it;
  that is the price of not running sshd as root.
- A machine without `/data` has no ssh.

## Alternatives Considered

### A key in the config tar
The private half would be made on a laptop and travel with every copy of
the tar.

### A new key each boot
Every boot would look like a machine-in-the-middle, and operators would
learn to accept that.

### ssh-keygen writing in place, as it first did
A boot cut short could leave a key without its public half, or a key cut
off, and every later boot kept it: sshd down for good.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| The private half leaking | Made on the machine, mode 0600, never logged. |
| Identity changing each boot | Refused: no key is made on RAM. |
| A half-made key kept forever | Made beside its place and renamed in, public half first. |
| Its own privilege | The service's user, in its Landlock rules; it runs only ssh-keygen. |

## Reliability Considerations

- **Whole or absent**: a cut-short first boot leaves no key, so the next
  makes one.
- **Heals**: a lost public half is made again from the key.
- **Tested**: `check-bastion`'s second boot must offer the fingerprint the
  first logged.
