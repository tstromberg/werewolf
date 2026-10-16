# Fast local test iteration

**Status:** Proposal  
**Date:** 2026-10-15

## Summary

Keep one disposable form VM running while a developer edits a native test driver.
Recompile, `scp`, and run only that driver; keep `howl test --with FORM` as the release
gate.

## Background

Native tests boot a generated test image and run shell-free clients under each driver's
declared `leash` policy. This covers private protocols such as PostgreSQL peer
authentication and Greenbone's Unix sockets, but repeats slow service startup after a
client-only edit.

## Goals

- Reuse one local QEMU boot across driver edits.
- Run the selected driver under its existing identity and `leash` policy.
- Show test records, output, and exit status; reset the VM when desired.

## Non-Goals

- Replace the native release gate or create release evidence.
- Add SSH, a shell, or test tools to published forms.
- Support remote VMs, interactive sessions, or source watching.

## Detailed design

`howl test --with FORM --iterate [--driver NAME]` builds and starts a disposable test
image once. Without `--driver`, it leaves the VM ready. With a driver, it compiles that
driver for the guest architecture, uploads it with `scp`, and runs it. Repeating the
command reuses the running VM, so edits rebuild only the selected client. `--reset`
recreates the VM's data disk and reboots; `--stop` ends the VM.

The iteration image adds OpenSSH, `sh-shim`, and one root account. These exist only in
this test image. SSH and SFTP use one loopback forward. Use one Howl-managed developer
key at `$XDG_DATA_HOME/howl/keys/dev/ssh-ed25519`; install its public half as root's
authorized key. Never accept unauthenticated or arbitrary keys. `sh-shim` dispatches
only the fixed `test-control` executable; it rejects shell syntax, PTYs, and forwarding
are disabled. `scp` uploads to `/tmp/test-upload`. This is a trusted, local developer
VM: root SFTP can modify the guest. Discard it after iteration; never publish it or
treat its results as release proof.

`--dev` automatically adds SSH for local development VMs, using the same managed key
and `howl ssh` path. It permits root command execution by design. The native test image
remains separate: it has no BusyBox, and its proposed SSH command path only dispatches
`test-control` before running drivers through `leash`.

`test-control run DRIVER` accepts only a name in `test/native.json`. It atomically
promotes that driver's uploaded binary, then invokes its existing fixed service entry
through `leash`. The plan supplies the identity, groups, paths, programs, and expected
cases; host input cannot supply policy or an executable path. The helper returns the
driver's case records and exit status. The host validates only that driver's cases.

The VM and data disk persist between runs, so a driver may see state from prior runs.
Reset is explicit. Native seed, reboot, and verify tests remain unchanged and must pass
before publication. Begin with Greenbone's GMP driver and PostgreSQL's `psql` driver.

## Drawbacks

This adds a test-only SSH path and allows the local operator to modify the disposable
guest through SFTP. The VM is stateful and must be reset when a clean data disk is
needed. Developers need Zig, QEMU, `ssh`, and `scp`.

## Alternatives Considered

### Reboot for every edit

Simpler control flow, but repeats expensive service startup, especially for Greenbone.

### Add an interactive shell

BusyBox broadens the image and command surface. The fixed `sh-shim` command is enough;
serial output remains available for logs.

### Relay private sockets to the host

This avoids SSH but adds a relay and host-side protocol clients. Running the driver in
the guest preserves Unix peer credentials.

## Security Considerations

Only the disposable local test image gains SSH from this design. Its forwarded port
binds to loopback and requires Howl's managed developer key. This design trusts the
local operator and makes no claim that root SFTP is confined. The command path is
limited by `sh-shim`; driver execution still uses the plan's `leash` policy. Native
tests remain the release gate.

## Reliability Considerations

Reusing a VM preserves service startup but also preserves test state; provide reset and
stop operations. Report the VM's serial log on a failed driver run. Driver-only edits
must not rebuild the form image; changes to the form, plan, or helper require a rebuild.
