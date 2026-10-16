# Offline updater installation

## Summary

Confine offline apk installation inside the updater's state directory. Only the
candidate package root is writable, and the installer cannot create sockets.

## Background

The updater already fetches packages without privilege, reclaims the cache and
authenticates its contents before starting offline apk. That apk keeps ownership
capabilities, but previously had access to the running machine's paths.

Landlock alone cannot contain this installer: chmod and chown by pathname are not
mediated. An empty chroot also cannot execute apk's dynamic loader and libraries.

## Goals

- Preserve package ownership, links, modes and signature checks.
- Keep installation away from the running machine's files and devices.
- Bound the installer's writable paths and refuse network access.
- Keep the existing child process, timeout and output limit.

## Non-Goals

- Remove the coordinator's root identity before its remaining duties are split.
- Add a general privileged service, setuid executable or file capabilities.
- Change signing keys, package selection, rollback or activation policy.

## Detailed design

The broker accepts one updater-only operation, `installer-runtime`, with no
arguments. It opens `/data/svc/autoupdate/usr` without symlinks, checks its root
ownership and modes, and binds immutable `/usr` there read-only, nosuid and nodev.
It reuses an existing bind to that same inode and unmounts it before shutdown.
The source's execute permission remains available; `/data` itself stays noexec.
Repositories and public keys are copied per pass and removed afterward.

The existing tool child closes all inherited descriptors except its output and
standard streams. It chroots to `/data/svc/autoupdate`, changes directory to `/`,
and opens its Landlock grants there. Fixed root/cache pairs select either
`/work/root` and `/cache/root`, or `/work/kernel` and `/cache/kernel`.

The runtime and matching cache are read-only. The candidate root permits normal
files, directories, links and FIFOs, including cross-directory renames. No rule
grants devices or execution from the candidate. Only apk and its immutable loader
receive execute permission. The child retains the existing installation mask,
without SETUID, SETGID, SETPCAP, SYS_CHROOT or mount capabilities.

A syscall allowlist admits the file operations apk needs, with socket creation
and mounts refused. No environment or package scripts are allowed. The tool's
existing deadline and output limit still apply.

The chroot contains the cache and updater state as well as the candidate. This
keeps the cache reusable without copying package archives. Landlock protects
their contents; pathname metadata operations remain confined to this chroot.
The coordinator, not the installer, verifies freshness and final slot policy.

## Drawbacks

One read-only bind remains attached for the boot, requiring shutdown cleanup.
No package archive or library is copied, and no extra process is introduced.

## Alternatives Considered

- Rename the coordinator: its capabilities would preserve its existing authority.
- Landlock alone: does not contain pathname chmod and chown.
- Hard-link the runtime: metadata changes would affect the running image's files.
- Copy executables into state: `/data` is noexec and must remain so.
- Give a helper arbitrary file operations: enlarges the privileged interface.
- Build through user namespaces: adds UID mapping and kernel machinery for this job.

## Security Considerations

The installer has no directory descriptor outside its chroot, cannot chroot again,
and cannot mount or obtain an external descriptor through a socket. A package's
absolute symlink resolves inside the chroot. Public keys and libraries come from
the immutable running image; a downloaded package supplies none of the runtime.
The coordinator remains privileged and is still an explicit service exception.
Package indexes still name packages by SHA-1; forging needs a second preimage.
SHA-1 signatures remain refused.

## Reliability Considerations

Failure to provision or confine the runtime fails the pass before installation. A
failed or killed installer leaves only scratch data for the next pass to remove.
Tests exercise real confinement on Linux and the existing updater flow.
