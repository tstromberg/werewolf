# Shell-free

Built; proposed 2026-10-06 (cmd/leash, cmd/runit-stage and the other
programs in cmd/; posture's `programs-*` checks). See *Open* for the rest.

## Summary

A production werewolf machine carries no shell and no interpreter. Every
program it runs is an ELF binary from the image, started by a binary, and
each service is declared in a file of fixed keys, not written as a script.

## Background

werewolf once booted, stopped and supervised through shell scripts, with
busybox `sh` in every image. Removing it matters because:

- **Exec rules stop new binaries, not scripts.** fence's Landlock, and IPE
  once built ([verified-boot.md](verified-boot.md)), judge what is
  executed, not what an interpreter reads. Without one, code that takes
  over nginx cannot `sh -c`, pipe a download into a shell, or chain tools.
- **It is one claim to check**, for root and PID 1 as for services; a
  service file shows its whole reach; no shell parses config at boot.
- Chainguard's images, from the same Wolfi packages, have no shell and a
  `-dev` variant for debugging. We take the same shape.

## Goals

- posture's `programs-no-shell`, `programs-no-interpreters` and
  `programs-services-no-shell` pass on every production form.
- `make check` boots every form as it ships (`check-shellfree-FORM`) and
  fails on any posture failure its form.yaml does not excuse.

## Non-Goals

- **Forms that log people in** (`sshd`, `lima`, `prod-ssh`) carry
  busybox-full; runtime forms (`python`, `node`, `php`, `jre`) carry their
  interpreter. Each names the failure in `weaknesses:` (forms/README.md).
- **bite**, which runs on the victim's distro; an interpreter inside a
  program (nginx's njs); other binaries, such as init's `blkid`.

## Detailed design

**Programs for scripts.** Each script became a small Zig program in cmd/:
runit's three stages (`runit-stage`, under three names), `reboot`,
`grub-setenv`, `slot-keep`, `power-button`, `debug-shell`, `ssh-host-key`,
`sshd-start`, `bite-cleanup`, and `mount`, since busybox's cannot set
`noexec`. init ends in `exec fence runit`, so runit stays PID 1.

**Service files.** A service someone else wrote is `/etc/sv/NAME/service`,
with `run` linked to leash and `finish` to leash-reap. A line is a key and
words, `"` groups words, and there are no escapes, variables or
conditionals ([cmd/leash/README.md](../../cmd/leash/README.md) lists the
directives). The build parses each file as leash does (`lib/compose.zig`).
Every service in `/etc/sv` starts at boot: a machine without one is
another form. Per-machine values come as files in the config tar or as
settings ([docs/forms.md](../forms.md#private-configuration-files)), never
by templating at boot. `forms/nginx` is the worked example.

**Checks.** posture looks for shells and interpreters by name in the
program directories and checks each `/etc/sv/*/run` is ELF
([docs/posture.md](../posture.md)). A `system(3)` call fails on the check
boot; `initdb`'s did, so `popen-shim` runs its one command. `DEV=1` adds
busybox-full for debugging and test/checks, and `make dist` refuses it.

**Open.** init could stay PID 1 for life and read the power button; runit
as PID 1 with Zig stages was the first step. postdoc asked leash for a
delegated cgroup, `nice` and an OOM score; leash has `memory` (MiB) and
`nofile`. A value a program takes only as a flag cannot vary per machine.

## Drawbacks

- Debugging uses another image (`DEV=1`), so a fix is confirmed on the
  shipped image after. Each daemon that shells out needs a fix or a shim.
- posture checks names, not contents: a renamed interpreter, or one
  outside the program directories, is not found.

## Alternatives Considered

- **Keep the shell, rely on Landlock.** It covers leashed services, not
  root, PID 1 or anything started outside leash.
- **systemd.** Its units are the same idea and inspired several keys, but
  it is much of the size and surface werewolf exists to avoid.
- **dinit, or s6 with execline.** Either replaces runit and neither
  sandboxes; leash would still be ours.
- **A build scan refusing `#!` files.** Without an interpreter a script
  cannot run, and posture checks the image as booted.

## Security Considerations

- An exploited service has only its process and what its file grants;
  root and PID 1 have no shell either.
- The one root shell, on the console of a `DEV=1` build booted with
  `werewolf.debug=1`, needs a marker only that build's root carries.

## Reliability Considerations

- No shell quoting or word splitting at boot. A bad service file fails the
  build, or parks the service with its line number.
- The console is the debugger: each service's output, leash's line per
  start, the posture line, and audit records of refused execs.
