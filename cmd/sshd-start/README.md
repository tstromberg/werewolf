# sshd-start

## Summary

The sshd service for forms that install OpenSSH (sshd, lima, prod-ssh): it
makes sure of the host key and becomes sshd. In forms without OpenSSH it
parks itself, so a form adds ssh with a package and no files of its own.

## Background

A distro makes `/etc/ssh`'s host keys on its first boot. werewolf's root is
read-only and the same on every machine, so the key is made on the
machine, kept in `/data`, and copied where sshd reads it. Here sshd runs as
root, with OpenSSH's own privilege separation; the bastion form runs sshd
leashed instead, through ssh-host-key.

## Goals

- One host key per machine, made on its first boot and kept for good.
- An operator can still log in on a machine without a disk for `/data`,
  with a key for that boot alone, said as such.
- The fingerprint on the console every start, never the private half.

## Non-Goals

- Configuring sshd: the form's `sshd_config` does.
- Keys other than Ed25519.

## Detailed design

1. **No sshd** (`/usr/bin/sshd` not executable): `sv down`, and nothing
   more.
2. **Speculative Store Bypass** disabled for itself, `ssh-keygen`, sshd
   and every session (`PR_SET_SPECULATION_CTRL`), which werewolf leaves to
   each program rather than paying for it everywhere.
3. **The key**, through `lib/hostkey.zig`: with `/data` usable, kept at
   `/data/sshd/ssh_host_ed25519_key` (0700 directory, root's), made once by
   `ssh-keygen` beside its place and renamed in, so a boot cut short leaves
   a whole key or none; a lost public half is made again from the key.
   Both halves are copied to `/run/sshd`, each a new 0600 file. Without
   `/data` (`/run/werewolf/nodata`), or with it on RAM, the key is made in
   `/run/sshd` for this boot alone.
4. **Says** `sshd-start: {"event":"host-key","from":"kept in /data",
   "fingerprint":"SHA256:…","public":"…"}`; `from` says when it is new or
   for this boot alone.
5. **Becomes** `sshd -D -e`. If anything fails, it says why, waits ten
   seconds, and exits; runsv starts it again.

## Drawbacks

- Without `/data`, each boot has a new key, and a client sees a warning:
  the price of letting an operator in at all.
- sshd runs as root here, as OpenSSH is built to; a form wanting less uses
  the bastion's leashed sshd.

## Alternatives Considered

### A key in the config tar
The private half would be made on a laptop and travel with the tar.

### No ssh without `/data`
A machine whose disk failed would lock its operator out as well.

### Exit at once on failure
runsv restarts in a second, so a lasting fault, no ssh-keygen say, wrote
a console line a second for the life of the machine.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| The private half leaking | Made on the machine, 0600, in a 0700 root directory; never logged. |
| A half-made key kept forever | Made beside its place and renamed in, public half first. |
| Identity changing unseen | A key for this boot alone says so on the console. |
| Spectre v4 against sshd | Speculative Store Bypass disabled for sshd and its sessions. |

## Reliability Considerations

- **Whole or absent**: a cut-short first boot makes the key again.
- **No flood**: a failure waits ten seconds before runsv tries again.
- **Tested**: `check-sshd` and `check-prod-ssh`: the second boot must offer
  the fingerprint the first logged as kept in `/data`.
