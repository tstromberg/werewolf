# debug-shell

## Summary

A root shell on the serial console, without a password, for debugging a
DEV=1 build booted with `werewolf.debug=1`. On any other image it parks
itself and gives nothing.

## Background

werewolf ships with no shell and no ssh, which makes a boot that goes wrong
hard to see into. A DEV=1 build adds busybox and this console shell, so a
developer, and `make check`'s tests, can look inside. The production image
is a different image, so the shell never ships. runit starts it as
`/etc/sv/debug-shell/run` once the machine is up.

## Goals

- A console shell on a DEV=1 build, with no setup.
- None on any released image, whatever its command line says.
- A shell opened never goes unseen.
- Stage 3 shutdown never waits on it.

## Non-Goals

- Remote access: that is sshd's, on the forms that carry it.
- Authentication: the console of a DEV=1 machine is trusted by design.

## Detailed design

- **Three gates, all required:** the exact word `werewolf.debug=1` on the
  kernel command line; `/usr/share/werewolf/dev`, which only a DEV=1
  build's verified, read-only root carries; and busybox's `getty` and `ash`.
  Otherwise it says why (unless the word is simply absent) and runs
  `sv down .`, so runsv does not restart it.
- **The shell:** it execs `getty -n -l /bin/ash -L 115200 TTY vt100`. TTY is
  the last `console=` on the command line, cut to its leading letters and
  digits (`ttyS0,115200` is `ttyS0`), or `console`. Before the exec it says
  on the console that a passwordless root shell is open, and where.
- **Stopping:** runsv also runs it as `control/t` in place of sending TERM,
  which an interactive ash ignores. As `t`, it reads runsv's `supervise/pid`
  and sends that process HUP, which ash honours.

## Drawbacks

- On a DEV=1 machine, anyone at the console is root.
- `make run` of a non-DEV form gives no console shell: use DEV=1, or ssh.

## Alternatives Considered

### Gate on the command line alone
Root can set `werewolf.debug=1` through GRUB's environment, and anyone at a
bitten machine's console can edit GRUB's menu. A switch an attacker can flip
is no gate (docs/design/lockdown.md); the image must decide.

### A login prompt with a password
werewolf has no passwords, only keys, and a debug build needs a way in when
the network is what broke.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A passwordless root shell in production | Only a DEV=1 build gives one: its marker is on the verified root, which no command line, config or metadata can add. `make dist` refuses a DEV=1 build. |
| `werewolf.debug=1` flipped on a released image | Refused, and said: "werewolf.debug=1 ignored". |
| A shell opened unseen | Each one is announced on the console, so in the cloud's serial log. |
| A device name from the command line | Only leading letters and digits reach getty: no `/` or `..`. |
| `t` signals the wrong process | runsv runs it only to stop a running service, with its own pid file; pid 1 and below are refused. |

## Reliability Considerations

- **No restart loop:** parking runs `sv down`, so it stays down.
- **Shutdown does not stall:** HUP ends the shell where TERM would not, and
  if the kill fails, runsv sends TERM itself.
- **Tested:** `check-slot` drives it on DEV=1; a non-DEV boot refused it.
