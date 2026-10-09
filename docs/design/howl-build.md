# howl builds images

Stage 2 and the ports built, 2026-10-09: howl builds every image; make asks it.

## Summary

howl makes a form's image itself, in Zig, for users and the checks alike.
The Makefile keeps the programs' compiles, tests, lint, checks and releases.

## Background

Before stage 1, make built every image howl made, as shell and awk in a
1,940-line Makefile and two scripts, the split [cli.md](cli.md) chose. howl
depended on make's target names and `--debug=b` output, and:

- A released howl cannot build without a checkout and make, against
  [custom-updates.md](custom-updates.md)'s goal that it needs no Zig.
- The updater (`cmd/slot-update/slot.zig`) does module order, decompression,
  the zboot unwrap and verity in Zig too: twice, in two languages.

## Goals

- `howl build`, `run` and `create` run make only for the programs,
  melange's packages and the tutorials' applications.
- One copy of each shared step, in `lib/image.zig`, used by howl and the updater.
- With `FREEZE=1`, every form builds byte-identical `root.erofs`,
  `stage0*.zst`, `initramfs.zst`, disks and manifests to the old recipes.
- The Makefile falls below 600 lines, and `make help` fits on a screen.

## Non-Goals

- Compiling werewolf's programs in howl: that needs Zig. howl takes them
  from `build/ARCH/programs` until custom-updates publishes them as packages.
- Replacing apko, bsdtar, mkfs.erofs, zstd, mtools, mke2fs, qemu-img or `make check`.

## Detailed design

**lib/image.zig** holds what howl and the updater share, as functions of
bytes, never paths: module order and `werewolf.modules`; gunzip; the zboot
unwrap and x86 `vmlinux`; the kernel config's rules; mkfs.erofs's options
and version check. Module order is the Makefile's; the updater's is not yet.

**cmd/howl/build.zig** (with `packages.zig` and `slot.zig`) runs the
pipeline as steps, each skipped when its output is newer than its inputs,
howl's executable among them: config, locks, rootfs and kernel (apko), meta
(`lib/compose.zig`), overlay, root.erofs and verity, both stage0s,
initramfs, slot, disk, each to a temporary name, renamed. `disk.zig` and
`manifest.zig` replaced `boot/mkdisk` (with the GPT in process, from
`boot/gpt.zig`) and `release/manifest`. make compiles the programs first
and, where a form needs them, melange's packages and the tutorials'
applications, with make's own variables cleared, so an outer make passes
it nothing.

**What identity takes.** The same tools with the same arguments, and the
`layer` macro's normalisation in Zig: a file laid over another keeps the
first's mode, as cp leaves it, and names are listed as find lists them.
zstd writes a frame's content size only for a file, so the initramfs's
second cpio still goes through `bsdtar | bsdtar | zstd`.

**Stage 2.** `run` and `create` build with build.zig on every engine. QEMU's
command line is `qemu.zig`'s; the Lima-managed template, `lima.zig`'s. The
Makefile's `image`, `slot`, `disk` and `OUT/disk.qcow2` wrap `howl _build`,
passing BUILD, PROGRAMS, DEV, APP, FREEZE and DISK, DISK_MIB and DISK_ARGS
(`Spec.disk_path`, `Spec.disk`; the qcow2 takes the size alone);
`_dist-form` runs `howl build`. Gone: the image recipes, the run, lima, demo
and webshell targets, `examples/vm.mk`, `test/gcp`, `test/lima-demo`, the
scripts and `build/host/gpt`. make keeps the locks' rules, for CI's
`release-inputs`, which runs with apko and the form tool alone. The
Makefile is 1,112 lines, mostly `make check`. The gate (FREEZE=1,
fresh roots) matched 11 aarch64 builds (DEV=1, `--app`, ad hoc) and x86_64
minimal and prod-ssh; then the wrappers, the tutorials and vaultwarden;
then the ports' disks (both arches, other sizes and arguments) and release files.

## Drawbacks

A bug in `lib/image.zig` reaches the build and every machine's updates.

## Alternatives Considered

- **Keep make** (cli.md): the duplication with the updater, and the coupling.
- **build.zig**: it still shells out to apko and mkfs.erofs, and a released
  howl would carry the build runner.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A form's path escapes the build directory | refuse `..` and absolute paths, as compose does |
| The build host leaks into the image | the same bsdtar normalisation; the byte-identical gate |
| apko verification is skipped | the same apko commands and keyrings |

## Reliability Considerations

The module step refuses an empty list, or a bitten one without a native
module. apko retries network errors (howl; make, for locks). zstd dates
`stage0.zst` to its cpio's second, so the step dates it now, or the next
build would rebuild it. A disk is rebuilt by file times alone, so each
machine's disk has its own path. Open: a tagged leaf named before an
untagged one sharing a dependency loads first (no form has such a pair;
fix it with the updater's).
