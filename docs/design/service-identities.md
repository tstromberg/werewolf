# Service identities and privileged monitors

## Summary

Drop root where setup has finished. Separate input processing from privileged
operations where a daemon must continue changing the machine.

## Background

Application services already run as their own users, except SSH login monitors.
Several system programs retain root after opening their resources. A different
UID is useful only when its file permissions, capabilities and channels also
limit what it can do.

## Goals

- No root identity or capabilities in the power-button reader or metadata parser.
- No UID-changing capabilities in the metadata account publisher.
- Slot health decisions and DHCP lease application use distinct non-root users.
- Preserve clean shutdown, account rotation, boot commit and rollback checks.
- Keep privileged protocols specific to the program that implements them.

## Non-Goals

- Replacing OpenSSH's privilege separation or runit's lifecycle management.
- A general privileged RPC service, setuid executable or capability-bearing file.
- Removing privileges whose replacement would weaken inspection or recovery.

## Detailed design

### Services

| Program | Identity and authority |
| --- | --- |
| power-button | Root opens input devices and runit's flags, then forks `_power` (71), without capabilities, in an empty chroot. The parent keeps no capabilities. Its filter permits only receiving a one-byte decision, setting the fixed poweroff/stop flags, waking PID 1, and parking its own service. |
| slot-keep | `_slotkeep` (72), no capabilities, read-only Landlock paths and its inherited keeper channel. The mount broker publishes the root-owned committed marker after keeping the EFI entry. Its own control pipe is opened before dropping root. |
| DHCP | `_dhcp` (67) parses packets; `_netcfg` (73) applies validated leases with NET_ADMIN alone. Only the network-state directory changes owner. Neither side gains another channel or process. |
| cloud-metadata | `_cloud` (68) fetches; `_usrmgr` (74) checks and rewrites bounded metadata in its scratch directory. A root publisher receives only bounded users/key records, derives accounts through `people.apply`, and keeps CHOWN alone. All three are forked before confinement; neither worker retains UID-changing capabilities. |
| autoupdate | Root coordinator, unprivileged fetchers/readers and fixed mount-broker operations. Offline apk is confined to a state-directory chroot with immutable tools, a read-only cache, Landlock and seccomp ([installer boundary](updater-installer.md)). The coordinator still needs a separate construction boundary before giving up its ownership and worker-setup capabilities. |
| posture | Keep privileged inspection once per boot. Dropping root must not silently skip protected process, account or attack checks. |
| sshd / sshd-dev | Keep upstream's privileged monitor and unprivileged connection handling. The forwarding-only bastion already runs without root. |
| debug-shell | Keep the explicit development-only root console; production images cannot enable it. |

### Other root processes

The mount broker keeps SYS_ADMIN and its existing three role channels. PID 1 and
the shutdown stages retain lifecycle authority. Stage0's deadman stays independent
of the running slot, with its existing reboot and commit-inspection authority.
seal-watch already drops to `_seal` when enforcing; its development-only learning
mode retains the access needed to identify callers. leash gives root up before
executing applications. Boot mount/interface helpers and leash-reap remain small,
short-lived privileged operations.

### Identity and files

`sandbox.dropKeeping` changes real, effective and saved UID/GID, clears groups,
locks securebits, empties inheritable/ambient capabilities and limits permitted,
effective and bounding sets to the named mask. SETUID is forbidden. It resets
dumpability after the credential change and verifies root cannot be recovered.

Account files and SSH-key directories remain under their existing ownership.
Changing shadow's owner is permissible in principle, but would not eliminate the
publisher's responsibility for user-owned homes and OpenSSH's key-path checks.
No daemon receives ownership of all `/run/werewolf` as a shortcut.
Application and narrowed leashes reject the reserved system UID/GID range.

## Drawbacks

Metadata polling keeps two workers. One executable creates and confines them;
there is no separately configured daemon or discoverable control socket.

## Alternatives Considered

- Give a renamed daemon SETUID and prohibit UID 0 in seccomp: needs complete UID
  syscall coverage and careful credential handling. Forking workers before the
  drop removes the continuing need for SETUID.
- Give power-button KILL or SYS_BOOT: broader than requesting clean poweroff.
- Delegate shadow ownership alone: does not solve atomic account publication,
  key ownership or home creation.
- Share a privileged administration broker: combines unrelated authorities.

## Security Considerations

Workers cannot pass arbitrary paths, UIDs, commands or descriptors to monitors.
Malformed publication lengths end the publisher. Channels have bounded reads;
publication failures do not advance the parser's last-applied generation.
Account publication still authorizes access, including explicitly declared root
keys: it remains a trusted operation despite separation from transport parsing.

## Reliability Considerations

Workers watch a pipe whose write end only the publisher holds, also during
network waits; its close ends both workers without relying on signal authority.
DHCP's engine watches its existing parent channel during packet and lease waits.
Failed transport, framing or confinement restarts the supervised program.
Unchanged or refused metadata sends a heartbeat;
each successful account generation is acknowledged before advancing scratch state.
The keeper marks commit only after the broker completes the EFI operation.
Guest tests cover shutdown, DHCP, metadata polling and native EFI commit.
