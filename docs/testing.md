# Testing

```sh
make test           # the updater's unit tests
make check          # boot every form, and a slot, and check each one
make -j check       # the same, side by side
make lima-ci        # the CI job, in an Ubuntu VM under Lima
```

`make check` needs, beyond the build's tools, QEMU, `expect` and `mke2fs`
(e2fsprogs). On a Mac: `brew install qemu e2fsprogs`; `expect` ships with
macOS.

## What `make check` does

It builds every form and boots each under QEMU, then boots a slot the way
bite leaves one. On each machine it runs [test/checks](../test/checks) as
root on the serial console, then powers it off. A machine passes when it
boots, every check comes out as expected, and it shuts down cleanly.

The checks try what an attacker would and expect to be refused: lower
lockdown, read `/dev/mem` or another process's memory, undo a one-way
sysctl, find a setuid file, listen on a port. Where a refusal and an
ordinary error look alike, a check also asks for the kernel's own line
saying it refused. One check runs first, before any attack: that nothing
was refused during boot, which catches a protection breaking a service.

The slot boot covers what direct boot cannot: stage0 finding `root.erofs`
by filesystem UUID, the overlay, `/victim` read-only, and the `commit`
service making the slot GRUB's default once it has stayed healthy for a
minute. The victim is a 128 MiB ext4 that `mke2fs -d` fills with what bite
leaves: the root image in slot a and GRUB's environment block. The slot
uses the `bitten` form, which has no updater to reach the network once
committed.

```
ok     sshd               lockdown
ok     sshd               proc-mem
gap    sshd               tmp-noexec
pass   sshd               all checks
```

Each machine gets a blank disk and no config, and forwards no ports, so
machines never share state and `make -j` runs them together. Nothing waits a
fixed time: [test/boot](../test/boot) waits for each thing it needs to see,
up to a limit, so a fast machine finishes fast and a slow one, emulated in
CI, still passes. On an M4, `make -j8 check` takes about 25 s for the forms
and a further minute for the slot to commit.

Logs are in `build/<arch>/check/`: `<form>-build.log` for each build, and
`<form>.log` for each console, kernel messages and all.

## Writing a check

A check is one line of `test/checks`: a kind, a name and one line of sh,
run as root in a subshell, exiting 0 when the property holds.

```
ok  ptrace-off       grep -qx 3 /proc/sys/kernel/yama/ptrace_scope && ! sysctl -w kernel.yama.ptrace_scope=0
gap tmp-noexec       d=$(mktemp -d) && cp "$(command -v busybox)" $d/ && ! $d/busybox true; r=$?; rm -rf $d; exit $r
```

- **ok** must hold on every machine. A check that applies to some machines
  only decides for itself: `slot-commits` passes at once unless the machine
  booted from a slot.
- **gap** is a known weakness from [security.md](security.md), "Not yet",
  and must not hold. When work closes one, its check starts holding, and
  `make check` fails until the line becomes `ok` and the docs say so. So
  the docs cannot claim a protection the machines lack, or miss one they
  have.

Test the attack, not the setting: `ptrace_scope` reading 3 proves less than
`cat /proc/1/mem` being refused. And make a check fail before trusting it
to pass: point it at a machine without the protection, or invert it.

## CI

[.github/workflows/check.yml](../.github/workflows/check.yml) runs `make
test`, `make lint` and `make check` on GitHub's x86_64 and arm64 Ubuntu
runners. [test/ci-setup](../test/ci-setup) installs the tools: Ubuntu's
packages, and apko and Zig pinned by version and sha256; `ci-setup apko`
installs apko alone, for jobs that only resolve packages. Each job keeps its
logs when it fails.

`make lima-ci` runs the same job here, in an Ubuntu 24.04 VM, `werewolf-ci`,
with nested virtualization for KVM. The tree is copied in fresh each run,
without `config/` or `.git`; the VM, its tools and its build cache stay
between runs. `limactl delete -f werewolf-ci` starts over.
