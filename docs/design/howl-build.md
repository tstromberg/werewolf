# howl builds images

Stage 1 built, 2026-10-09: `howl build` is native; run and create still use make.

## Summary

`howl build` makes a form's image itself, in Zig. The Makefile shrinks to
what contributors run: compiling werewolf's programs, tests, lint, `make
check` and releases. Users and the checks build through one path: howl.

## Background

Before stage 1 every image howl made came from `make`: `howl build` ran
`make _dist-form`, `howl run` runs `make image` and `make run`, the other
engines `make disk` or `make slot`. The Makefile (1,850 lines) holds the
pipeline as shell and awk. [cli.md](cli.md) chose that split; it costs:

- Contributors must read make recipes to learn how an image is made, and
  howl depends on make's target names and the `--debug=b` output it parses.
- A released howl cannot build without a checkout and make, against
  [custom-updates.md](custom-updates.md)'s goal that it needs no Zig.
- The updater (`cmd/slot-update/slot.zig`) does module order, decompression,
  the zboot unwrap and verity in Zig too: twice, in two languages.

## Goals

- `howl build`, `run` and `create` never run make.
- One copy of each shared step, in `lib/image.zig`, used by howl and the updater.
- With `FREEZE=1`, every form on both arches, with and without `DEV`,
  builds byte-identical `root.erofs`, `stage0*.zst`, `initramfs.zst` and
  module tars to the Makefile's.
- The Makefile falls below 600 lines, and `make help` fits on a screen.

## Non-Goals

- Compiling werewolf's programs in howl: that needs Zig. howl takes them
  from `build/ARCH/programs` until custom-updates publishes them as packages.
- Replacing apko, bsdtar, mkfs.erofs, zstd or qemu-img, or `make check`.

## Detailed design

**lib/image.zig** holds what howl and the updater share, as functions of
bytes, never paths: module order and `werewolf.modules`; gunzip; the zboot
unwrap and x86 `vmlinux` extraction; the kernel config's rules; mkfs.erofs's
options and version check. Module order is the Makefile's (the chain's,
tagged and untagged mixed); the updater's is not yet.

**cmd/howl/build.zig** (with `packages.zig` and `slot.zig`) runs the
pipeline as steps, each skipped when its output is newer than its inputs,
howl's executable among them as the Makefile was: config, locks, rootfs and
kernel (apko), meta (`lib/compose.zig`, then a few records), overlay,
root.erofs and verity, both stage0s, initramfs, slot, disk (`boot/mkdisk`).
Each writes a temporary name, renames it, and logs a line with its time.
make compiles the programs (`make programs`) and, where a form needs them,
melange's packages and the tutorials' applications. `howl _build --with
FORM GOAL...` builds make's image, slot, disk, qcow2 and vmlinux targets.

**What identity takes.** The same tools with the same arguments, and the
`layer` macro's normalisation done in Zig: a file laid over another keeps
the first's mode, as cp leaves it, and the names are listed by walking the
staged tree, as find does. zstd writes a frame's content size when it reads
a file and none from a pipe, so the initramfs's second cpio still goes
through `bsdtar | bsdtar | zstd`. The gate (FREEZE=1, fresh roots on both
sides) matched every compared file of aarch64 minimal, prod, prod-ssh,
prod-ssh DEV=1, sshd, bastion, lima, postgresql, caddy, python with
`--app`, an ad-hoc form, and x86_64 minimal and prod-ssh.

**Switching over.** build.zig writes where make did (`build/ARCH/FORM`),
so make's targets can call `howl _build`. Then run and create stop calling
make, and the Makefile's image, run, lima, demo and webshell targets go,
with `examples/vm.mk`, `test/gcp` and `test/lima-demo`.

## Drawbacks

- A large port of shell that works; the byte-identical gate makes it safe.
- A bug in `lib/image.zig` reaches the build and every machine's updates.

## Alternatives Considered

- **Keep make as the build system** (cli.md): it keeps the duplication with
  the updater and the coupling between howl and make.
- **build.zig**: it still shells out to apko and mkfs.erofs, and a released
  howl would carry the build runner.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A form's path escapes the build directory | refuse `..` and absolute paths, as compose does |
| The build host leaks into the image | the same bsdtar normalisation; the byte-identical gate |
| apko verification is skipped | the same apko commands and keyrings |

## Reliability Considerations

The module step refuses an empty list, and a bitten list that lacks a
native module, as the Makefile does since the `$(MODULES)` bug left bite's
stage0 without modules. apko's retry on network errors moved with it.
Open: the Makefile's order lists a tagged module where its leaf is, so a
tagged leaf named before an untagged one that shares a dependency loads
before it; today's forms name no such pair. Fix it in both at once.
