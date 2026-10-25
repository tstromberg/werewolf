# Unprivileged update coordination

## Summary

Run update decisions as `_updater` (77), without capabilities. Keep construction
and worker setup behind an inherited channel inside an updater-only chroot.

## Background

Offline apk already has a chroot, Landlock and seccomp. The coordinator still
keeps ownership and identity-changing capabilities to construct slots and start
fetchers and readers. Renaming that process would not remove its authority.

## Goals

- No root credentials or capabilities in the long-lived coordinator.
- No mount-broker channel, host devices or writable host paths in construction.
- Preserve package verification, update ordering, notices and clean shutdown.
- Check the running credentials and exercise installation and rollback.

## Non-Goals

- Replace the fixed mount-broker operations or upstream SSH privilege separation.
- Provide arbitrary commands, mounts, paths or privileged descriptor requests.

## Detailed design

Before dropping privileges, the updater prepares its persistent state, opens its
operator listener and console, and provisions the immutable runtime. It forks a private
launcher, then changes real, effective and saved credentials to 77 and empties all
capability sets. I/O stays single-threaded across the drop. `_update` (69) remains a
separate worker identity. The coordinator alone retains the updater's mount-broker
channel.

The launcher closes host descriptors and chroots into updater state. It loses
SYS_CHROOT and SYS_ADMIN before receiving requests; it cannot escape by making
another chroot. A nonrecursive, read-only bind of the immutable running root at
`/host` supplies construction sources without its data, devices or runtime mounts.
The existing read-only `/usr` bind supplies executable tools. `/data` stays noexec.

Jobs are reset scratch, install root packages, install the kernel, construct a
slot, fetch a bounded body, or parse CVE records. Requests and responses use
bounded anonymous pipes passed over the inherited socketpair. The launcher forks
before decoding job arguments. Each job has an output bound and deadline; its
children retain their existing Landlock and seccomp restrictions. No request
accepts an executable path or returns a privileged descriptor.

Construction reads the running image through `/host` and writes only updater work, cache
and its audit log; temporary files stay in root-only `work/tmp`. Metadata capabilities
stay confined to state. Candidate ownership is preserved until mkfs normalizes the
immutable image. The coordinator owns reports and policy state. Scratch cleanup and old
ownership migration run before unprivileged use.

The mount broker accepts an argumentless updater-only request for clean reboot.
It sets only the preopened runit flags and wakes PID 1. It also publishes the
fixed root-owned ready marker after coordinator setup. The coordinator cannot
signal arbitrary root processes. Console warnings use a preopened write-only
descriptor; membership in `tty` permits ordinary session broadcasts.

Boot artifacts stay root-owned, with group 77 read/traverse access and no group write
permission. Staged images are also private to this group. The broker publishes this
through its detached mount; `/boot` stays read-only. Only the operator policy receives
group read access under `/run/config`; other files keep their existing permissions. IPE
inspection uses preopened read-only descriptors.

No service, the coordinator included, gets the TPM device. Before overwriting the
inactive slot the coordinator asks the mount broker's `floor` operation, which takes
no argument, to raise the channel's counter to the running release's index; no
worker sees the host device tree.

## Drawbacks

One private launcher remains root inside the state chroot. It retains capabilities
needed to create worker identities and preserve package metadata, but has no
writable host paths or a boot channel. Its read-only source contains the running
image; it sees none of that image's runtime mounts. It exits when its parent dies.

## Alternatives Considered

- Keep capabilities in a renamed coordinator: preserves the authority being removed.
- Give a helper arbitrary file operations: makes the interface harder to audit.
- User namespaces and UID mappings: add machinery for the same construction job.
- Remove worker chroots without replacing their filesystem boundary: weakens isolation.

## Security Considerations

Root construction jobs receive only anonymous input pipes, without host directory,
broker or device descriptors. Fetch and read jobs drop to `_update` before decoding
arguments or using body descriptors. The launcher cannot mount or chroot again.
Source mounts are read-only. Detailed job decoding happens in disposable children
after the host boundary.
The coordinator remains trusted to choose authenticated updates, but cannot change
accounts, recover UID 0 or change files outside its declared writable state.

## Reliability Considerations

Setup fails closed before publishing updater-ready. The launcher watches parent death;
children watch launcher death. Failed jobs leave scratch for the next pass. Guest tests
check credentials as well as stage, reboot, commit and shutdown. Existing rollback
checks remain in the keeper, stage0 and signed-image verifier. Linux fixtures exercise
the actual installer and refusal paths.
