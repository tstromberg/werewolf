# sshd-start

## Summary

sshd-start is the sshd form's service, used by every form that includes it
(prod-ssh, lima). It makes sure the host key exists, then becomes sshd. A
form adds ssh with `with: [sshd]`; minimal has none of it.

## Background

Other distros make the host keys in `/etc/ssh` on first boot. werewolf's
root is read-only and the same on every machine, so the key is made on the
machine, kept in `/data`, and copied to where sshd reads it. Here sshd runs
as root, with OpenSSH's privilege separation. The bastion form runs sshd
under leash instead, with ssh-host-key.

runsv runs sshd-start as `/etc/sv/sshd/run`, with no arguments and no shell.

## Goals

- One host key per machine, made on first boot and kept for good.
- An operator can still log in to a machine with no disk for `/data`,
  using a key for that boot only, and the log says so.
- The fingerprint on the console at every start, never the private half.

## Non-Goals

- Configuring sshd. The form's `sshd_config.d/werewolf.conf` does that: key
  logins only, and only with a touched security key.
- Key types other than Ed25519.

## Detailed design

1. **Speculative Store Bypass** is disabled (`PR_SET_SPECULATION_CTRL`) for
   sshd-start, `ssh-keygen`, sshd and every session. werewolf leaves this
   to each program rather than paying for it machine-wide.
2. **The key** goes through `lib/hostkey.zig`. With `/data` usable, it is
   kept at `/data/svc/sshd/host-key` (a 0700 root directory; a leashed sshd
   uses the same path through ssh-host-key). `ssh-keygen` makes it once,
   beside its place, and it is renamed in, so an interrupted boot leaves a
   whole key or none. A lost public half is made again from the key. Both
   halves are copied to `/run/sshd`, each as a new 0600 file. Without
   `/data` (`/run/werewolf/nodata` exists), or with `/data` on RAM, the key
   is made in `/run/sshd` for this boot only.
3. **Logs** `sshd-start: {"event":"host-key","key":"…","from":"kept in
   /data","fingerprint":"SHA256:…","public":"…"}`. `from` says when the key
   is new or for this boot only.
4. **Becomes** `sshd -D -e`. If making the key fails, it logs why, waits
   ten seconds, and exits; runsv starts it again. If exec fails, it logs
   why and exits.

## Drawbacks

- Without `/data`, each boot has a new key and clients see a warning. That
  is the price of letting an operator in at all.
- sshd runs as root here, as OpenSSH is designed to. A form that wants less
  uses the bastion's leashed sshd.

## Alternatives Considered

### A key in the config tar
The private half would be made on a laptop and travel with the tar.

### No ssh without `/data`
A machine whose disk failed would also lock out its operator.

### Exit at once on failure
runsv restarts within a second, so a lasting fault, such as a missing
ssh-keygen, would log a line a second for the life of the machine.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| The private half leaks | Made on the machine, 0600, in a 0700 root directory; never logged. |
| A half-made key is kept forever | Made beside its place, renamed in, public half first. |
| Identity changes unnoticed | A key for this boot only says so on the console. |
| Spectre v4 against sshd | Speculative Store Bypass disabled for sshd and its sessions. |

## Reliability Considerations

- **Whole or absent**: after an interrupted first boot, the next boot makes
  the key again.
- **No flood**: a failure waits ten seconds before runsv tries again.
- **Tested**: `check-sshd` and `check-prod-ssh`: the second boot must offer
  the fingerprint the first boot logged as kept in `/data`.
