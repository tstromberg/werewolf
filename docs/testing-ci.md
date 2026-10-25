# Debugging and CI

## Debugging a failure

A FAIL reports the last progress line, the first kernel error (stall, blocked task,
panic) and host details: kernel, QEMU, accelerator, CPUs and load. Check boots panic on
a CPU stalled for 20 s or a task blocked for two minutes, reporting the kernel's reason.
An unresponsive machine dumps every virtual CPU's state into its log before failing.

```sh
make check-one FORM=playground REPEAT=20             # how often does it fail?
make check-one FORM=playground REPEAT=20 ACCEL=tcg   # without the hypervisor
BOOT_TIMEOUT=20 make check-minimal                   # see a hang sooner
```

`check-one` keeps each failing boot's console as `FORM-one-N.log`. Every boot prints
where its time went, `werewolf: up in 1.470s (the kernel 0.225s, userland 1.245s)`,
phase by phase (kernel, disk, slot, root, init's steps, seal), and keeps it in
`/run/werewolf/boot`. The console shows only warnings and worse (`loglevel=5`); `dmesg`
keeps every line.

## CI

[check.yml](../.github/workflows/check.yml) runs host tests on both architectures,
four `forms` shards, three `shellfree` shards, and four platform groups.
[test/ci-forms.zig](../test/ci-forms.zig) checks existing targets one form at a time,
cleans successful images/disks, and retains logs, locks, and native results.
Failures keep their images. Platform boots share CPUs within their memory budget.
[test/ci-setup](../test/ci-setup) installs pinned tools.

Hosted arm64 lacks KVM: `vm-arm64` uses Ampere for all forms, then
`make check-platform` (the rest of `make check`), on pushes/maintainers' PRs.
`make check-native` attacks roots in `systemd-nspawn` ([test/cage](../test/cage)).

`make ci` copies fresh source (no `config/` or `.git`) into a 16 GiB Lima VM with KVM.
VM and caches persist; `limactl delete -f werewolf-ci-24.04` starts over.
