# Operating a VM without SSH

Current enrolled QEMU images support a host-private control channel through the existing
updater. It works across forms, retaining their normal shell and login policies. Both
the image and the host `howl` must support it.

```sh
howl owner status
howl owner my-machine check
howl owner my-machine try
```

Omitting the name selects `werewolf-run`. Output is bounded JSON; a refusal returns
nonzero. `try [DECLARATION-HASH]` uses the usual authenticated inactive-slot checks,
so it can select a retained release but cannot authorize a retired or failed image.

| Operation | Effect |
| --- | --- |
| `status` | Boot ID, signed command line, readiness, commitment, posture results and inactive-slot command line |
| `check` | Check the authenticated update channel and stage an available update |
| `try [HASH]` | Boot the authenticated inactive slot once, optionally matching its declaration |
| `outcome` | Record whether the previous trial committed or rolled back |
| `pause` | Hold autonomous checks and automatic reboots; explicit operations remain available |
| `resume` | Resume autonomous updates |

A guest reboot clears `pause`. This is operator control, not a deployment policy;
use [update policy](updater.md#when-an-update-boots) for persistent scheduling.
A paused updater remains running and can still satisfy its readiness obligation.

The `werewolf.owner` virtio serial device connects to `owner.sock` inside the private
host machine directory. It opens no TCP port and grants no guest shell. The mount
broker finds exactly one kernel-named port, restricts it to root, and sends its open
descriptor only over the updater's existing private socketpair. Fence continues to
deny other programs access to that device. The updater retains uid 77, no
capabilities, Landlock, seccomp and its existing authenticated broker operations.

Requests contain a correlation ID and one fixed operation, with a hash allowed only for
`try`. Oversized frames are discarded; requests select no executable or path. Status is
guest diagnostics, not independent attestation.

The QEMU lifecycle test uses this production interface on unmodified signed images.
Its unhealthy trial receives real disk write errors after startup, must remain
uncommitted, and must recover the retained release through the production 600-second
deadman. The test neither edits the image nor installs a guest test agent.
