# Fast local test iteration

**Status:** Implemented · **Date:** 2026-10-16

## Summary

Keep one disposable form VM running, then compile, copy, and run one native test
driver in seconds. The driver still runs as its declared user under its normal `leash`
policy; the clean `howl test --with FORM` remains the release gate.

## Background

Native tests exercise private TCP and Unix-socket interfaces from inside the guest.
Their clean suite rebuilds and reboots by design, which is valuable release evidence but
slow while editing only a test client. Published forms must not gain SSH, a shell, or
general test tools to make that edit loop faster.

## Goals

- Reuse one local QEMU boot across driver edits.
- Upload and execute a selected driver under its declared identity and policy.
- Preserve output, exit status, run context, and expected-case validation.
- Rebuild when image inputs change; reset state and stop the VM explicitly.

## Non-Goals

- Replace the clean native suite or provide release evidence.
- Add SSH, BusyBox, or test binaries to a published form.
- Support remote machines, cross-architecture emulation, or file watching.

## Detailed design

`howl test --with FORM --iterate` creates a deterministic, disposable QEMU machine for
the host architecture. It generates a form over the production form containing only
immutable driver paths and service descriptors from `test/native.json`, then uses the
existing developer SSH listener and managed key, with `--dev=ssh` instead of `--dev`.
This profile adds no BusyBox or form-specific developer tools. Root's command adapter
is `sh-shim`; it accepts one executable and arguments, without shell syntax or scripts.

```sh
howl test --with postgresql --iterate
howl test --with postgresql --iterate --driver test-postgres
howl test --with postgresql --iterate --driver test-postgres --phase verify
howl test --with postgresql --iterate --reset
howl test --with postgresql --iterate --stop
```

The VM fingerprint includes the production form, native plan, generated instrumentation,
boot inputs, guest and builder sources, package locks, and the form's config fixture.
A changed image input deletes and rebuilds the VM. Driver source is deliberately
excluded: every selected run cross-compiles only that Zig driver, so an edit does not
rebuild or reboot the guest.

The host copies the new binary to a temporary name with SCP, copies the run/phase
context to `/run/config`. A small compiled utility promotes the uploads, checks service
paths, and enters the selected immutable descriptor directory before invoking leash.
It has no daemon, command language, or arbitrary descriptor upload. The immutable
`/usr/lib/werewolf/test-NAME` symlink chooses the executable; the host validates exactly
the cases declared for the selected phase.

Normal writable filesystems remain `noexec`. For a checked `werewolf.debug=1` boot with
Howl's `/run/config/dev` marker, init adds one `nosuid,nodev,nosymfollow` executable
tmpfs at `/run/howl-dev`. Fence admits execution there only when that mount exists.
`sshd-dev` alone retains `CAP_SETPCAP`, allowing a root SSH session to start a nested
leash; that leash drops the bounding set, identity, Landlock rights, seccomp calls, and
cgroup limits before the uploaded driver runs. Ordinary SSH keeps its existing
capability set.

PostgreSQL iteration uploads the `psql`-driving client, then runs it as `postgres` with
only the database socket and `/usr/bin/psql`. Greenbone uses the same mechanism for each
GMP, OSP, PostgreSQL, and Valkey client, preserving their distinct users, groups,
sockets, ports, config files, and programs. Private services need no host relay.

The VM and encrypted data disk persist between runs. `--reset` deletes both and creates
a new run ID; `--stop` stops QEMU. The final change still runs the clean command,
including seed, reboot, verify, production comparison, and shell-free boot, before
publication.

## Drawbacks

The iteration VM adds root SSH, its privilege-separation dependencies, the command
adapter, and executable upload RAM. Its seal stays enforced; it adds no interactive
console shell or blanket DEV posture exceptions. State persists, so a seed test may
require `--reset`. Developers need Zig, QEMU, SSH, and SCP.

## Alternatives Considered

### Reboot for every edit

This is the clean release path, but repeats image construction and slow service startup.

### Run `leash` directly from ordinary SSH

Ordinary SSH has already discarded `CAP_SETPCAP`, so a nested leash cannot safely reduce
the capability bounding set. Granting it only to `sshd-dev` keeps that exception local.

### Add test services or a control daemon

Runit services collide with production identity-sharing checks; a new privileged daemon
adds a protocol and lifecycle. The existing authenticated command channel is sufficient.

## Security Considerations

Only a local developer VM gets the key, listener, executable mount, fence rule, and
extra capability. Its port binds to loopback and host keys are pinned per machine.
Uploaded code runs only after the local key authenticates, and test policy still comes
from the immutable image. Iteration output is never accepted as release evidence.

## Reliability Considerations

Uploads use temporary names and atomic rename, and the host rejects missing, duplicate,
stale, foreign, or failed case records. Fingerprints prevent reuse after image changes.
Reset recovers contaminated state; the clean suite remains the reproducible final check.
