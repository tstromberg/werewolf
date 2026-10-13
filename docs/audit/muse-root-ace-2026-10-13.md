# Root arbitrary-code-execution audit — 2026-10-13

Scope: the `werewolf-run` playground machine on Lima (`vz`, aarch64, kernel
6.18.56-0-virt), attacked from its root SSH shell, plus a read of the
confinement code that shell runs under (`cmd/fence`, `lib/seal.zig`,
`lib/sandbox.zig`, `cmd/leash`, `cmd/mount-broker`, `cmd/slot-update`,
`cmd/init`). The question asked: with root in the shell, can a random program
still be kept from running?

## TL;DR

Arbitrary code execution was achieved, outside every confinement layer, by
the previously documented boot-chain route (astra audit F-03, still open):
confined root replaced the machine's `sshd`, used its stream-local
forwarding to speak to the mount-broker as uid 0, had the broker mount the
ESP writable, and overwrote slot a's `stage0.zst` with an attacker
initramfs. On the next boot the attacker's program ran as initramfs PID 1.
Nothing else tried in the running system escaped: direct, loader, preload,
fd-based, and `chroot` execution, mounts, device creation, namespace entry,
sysctl writes, helper abuse, leash, and the seal all refuse.

## Proven ACE: broker → ESP → stage0 (F-03, confirmed live)

The in-boot layers do their job (see "Held" below), so the chain leaves the
boot through the one writable door:

1. **Replace `sshd`.** `sv down /etc/sv/sshd` stops the supervised listener
   (existing sessions survive). Root then runs `/usr/bin/sshd -D` with a
   config and host key written under `/data`, with
   `AllowStreamLocalForwarding yes` and `AllowTcpForwarding yes` — the
   opposite of the shipped `AllowStreamLocalForwarding no` in
   `forms/sshd/sshd_config`. The new listener binds port 22, a port the
   fence grants. This step is itself a secondary finding: confined root
   can kill and replace in-domain root services (see below).
2. **Reach the broker.** The shipped sshd forbids forwarding precisely so
   a session cannot "reach a local socket for someone else"; with the
   replacement, `ssh -N -L /tmp/broker.sock:/run/werewolf/mount-broker.sock`
   makes the root `sshd-session` process connect to the broker socket.
   The broker's only check is `SO_PEERCRED` uid 0 (`lib/broker.zig`,
   `cmd/mount-broker/mount-broker.zig` `authorized`). It passes.
3. **Mount the ESP.** Sending the one word `esp` returns
   `ok /run/werewolf/mnt/esp`; the broker (outside Landlock, holding
   `CAP_SYS_ADMIN`) mounts `/dev/vda1` read-write there. The confined
   shell may write beneath `/run`, so the ESP is now writable by root:
   a marker file written to `/run/werewolf/mnt/esp/PWNED.txt` persisted
   on the ESP.
4. **Replace the boot files.** The ESP holds `EFI/BOOT/BOOTAA64.EFI`
   (systemd-boot), `loader/entries/werewolf-a.conf`, and
   `werewolf/a/{vmlinuz,stage0.zst}`. The genuine `stage0.zst`
   (sha256 `9f4deb3168aff4c9b7202419e02eb08790ceb1ee8697194968c0257c061dff99`)
   was replaced with a 1,561,181-byte zstd initramfs whose `/init` is a
   static aarch64 musl ELF built for this test, plus a copy of the
   genuine stage0 for self-restore. Result on the ESP:
   sha256 `e6a2b40cb2124fdf5ebb6746178b82c1681be47c4f4fbba7bae5ae04ba708c74`.
5. **Reboot.** The serial console (`~/.lima/werewolf-run/serialv.log`)
   records the program executing as the initramfs init, before stage0,
   PID 1, fence, seal, or Landlock exist:

   ```text
   RANDOM_PROGRAM_RAN: attacker initramfs init executing outside every fence
   ```

   Its attempt to mount the ESP and restore the genuine stage0 itself
   failed (`esp mount failed` — the node check in the test init was
   wrong), so it powered off each boot. The genuine `stage0.zst` was
   restored from the host with `mtools` against the real Lima disk
   (`~/.lima/werewolf-run/disk`, ESP at offset 1048576; read-back sha256
   matches the genuine hash above) and the marker file removed. The
   machine then booted clean: `sshd` and `autoupdate` running, posture
   back to its baseline of 82 pass / 8 fail / 6 skip, `/data` and `/tmp`
   free of test artifacts.

Why it works here: Lima `vz` has no Secure Boot (posture `boot-secure-boot`
is skipped, and `files-signed-image`, `boot-rollback-counter`,
`boot-ipe-enforced` fail), so nothing authenticates `vmlinuz`/`stage0.zst`
before the firmware and kernel run them. This is astra F-03's
"`/data`-resident root replaces a slot" item, confirmed end-to-end rather
than at the mount step. On a form and provider with Secure Boot or signed
UKIs enforced, the same write should fail verification and fall back; that
was not testable on this provider.

## Held: what confined root could not do

Each was tried from the root shell on the live machine unless noted:

- **Run a random ELF.** A static aarch64 test binary copied to `/tmp`
  and `/data`: `Permission denied` on direct exec (noexec tmpfs/ext4 and
  no Landlock `EXECUTE` outside `/usr`, `/oci`). `/usr/lib/ld-linux-aarch64.so.1
  /tmp/hello`: `failed to map segment from shared object` — the loader
  under `/usr` cannot map segments from a noexec mount. `LD_PRELOAD` of
  a crafted `.so`: ignored with the same mapping error.
  `bash enable -f /tmp/libevil.so`: same refusal. Exec via
  `/proc/self/fd/3` of the planted binary: `Permission denied`.
  Hardlink/symlink indirections into writable dirs do not change the
  answer. `posture --attack` (copy-and-exec probes in every writable
  directory, memfd exec probe) passes.
- **Script interpreters are not a native bypass.** `sh /tmp/script`
  runs, as the security model states; in this playground form bash and
  shell scripts are declared weaknesses, not findings.
- **`chroot`.** A rootfs assembled under `/data/r` (busybox, loader,
  libc): `chroot: can't execute '/bin/busybox': Permission denied` —
  chroot changes the path, not the Landlock rights of the inodes.
- **Mounts.** `mount -t tmpfs` from the shell: permission denied
  (`CAP_SYS_ADMIN` is dropped from the bounding set; the
  `/usr/lib/werewolf/mount` helper fails the same way from the shell —
  its `keepOnly(CAP_SYS_ADMIN)` capset cannot raise what the bounding
  set no longer holds). Its forced `NOEXEC`/`NOSUID` option handling
  was also read and only ever tightens.
- **Devices and namespaces.** `mknod` in `/tmp`: permission denied
  (`CAP_MKNOD` dropped). `nsenter -t <broker> -m …`: cannot open
  `/proc/<pid>/ns/mnt`. User namespaces are disabled
  (`/proc/sys/user/max_user_namespaces` is 0). Signals to the broker
  and `seal-watch` return `EPERM` (Landlock signal scoping).
- **Sysctls and kernel helpers.** `sysctl -w kernel.hostname=…`:
  permission denied; `/proc` is read-only under the fence, the
  modprobe/hotplug/core-pattern paths are empty, `memfd_noexec` is 2,
  and MDWE (`PR_MDWE_REFUSE_EXEC_GAIN`) is inherited from init.
- **apk.** A crafted unsigned `.apk` (planted `/bin/evil` plus a
  `.pre-install` script) installed with `apk add --root /data/r2
  --allow-untrusted` never produced a runnable binary: the archives
  built for the test were rejected (`BAD archive`), and the model it
  would have to beat — script and payload execution resolving to
  noexec `/data` inodes — is the same one that refused the direct and
  chroot attempts. No apk path to native execution was demonstrated.
- **Code read as fail-closed.** `leash` (grant parsing, dep closure,
  `openat2` root confinement, exec-fd close guard, capability drop
  order), `seal`/`seal-watch` (enforce mode never continues a notified
  syscall; per-promise and socket-family argument filters),
  `mount-broker` (fixed one-word protocol, device identity pinned by
  serial/UUID, detached `nosuid,nodev,noexec` mounts, restrictions-only
  seccomp), `grub-setenv` (one record rewritten byte-for-byte, no new
  records or variables), `people` account parsing (rejects the name
  `root`, existing names, and uid collisions), and the `fence` ruleset
  construction all match their documented behavior; no flaw was found
  in them during this pass.

## Secondary observations

- **Confined root can replace in-domain root services.** The ACE chain
  depends on it: `sv down` plus a root-run `/usr/bin/sshd` with a
  `/data` config yields a listener with forwarding the shipped config
  forbids. Any root-running werewolf service compromised inside the
  fence (for example the updater) inherits the same move against
  `sshd`. This is inside the stated model (root is one principal) but
  worth naming: the fence does not separate root services from each
  other, and SSH entry-point policy lives only in the supervised
  instance's config file.
- **Broker words are broad by design.** Any uid-0 process in the one
  mount namespace may ask for `victim` (the data filesystem, writable),
  `esp`, `grub`, or `shutdown`, at any time, or write under those
  mounts while the updater holds them. `cmd/mount-broker/README.md`
  already records this as open; the live run shows the ask path needs
  no werewolf binary at all — any uid-0 client that can open a unix
  stream socket suffices (here, `sshd-session`).
- **A fake broker is possible in principle.** `lib/broker.zig` notes a
  root process could place its own listener at the socket path in the
  shared mount namespace; askers verify only the returned static path.
  Impact is bounded (the askers then write boot files onto plain
  `/run` tmpfs), but the protocol has no authentication beyond the
  returned string.

## Not audited (gaps, not findings)

- `cmd/slot-update`'s composition path end-to-end: apk/tar extraction
  into the next slot root (`Root` resolution, link handling), the
  cached-package checks in `lib/apk.zig`, tier/CVE feed parsing, and
  the `try`/local-update trust decisions. The README's open item —
  root apk following links signed packages lay — was not exercised.
- DHCP packet parsing in `cmd/dhcp-client` beyond its parent/engine
  split and lease revalidation, and the other network-facing helpers
  (`iface-up`, `cloud-metadata`'s user-data handling past `people`).
- OCI and adhoc forms (`cmd/init/oci.zig` binds and the execute grant
  on image roots) — this image has no `/oci`; only the code was read.
- Other forms and providers (bitten/GRUB machines, QEMU, cloud with
  Secure Boot or IPE), the host-side `howl` Lima driver, and kernel
  vulnerabilities reachable through the sealed syscall surface.

## Recommendations

1. Treat ESP writability by confined root as the load-bearing gap it
   proved to be: on providers without Secure Boot, prefer signed-UKI
   forms and say, in the form's weaknesses, that root persists through
   reboot; do not let the posture `skip` read as coverage.
2. Narrow the broker if the threat model wants root-in-fence contained
   across a reboot: a read-only `esp` word for readers, mount lifetimes
   tied to the asking connection (already true) plus refusing `esp`/
   `victim` while a boot is committed and healthy would each cut the
   chain; all trade against updater ergonomics and are design calls.
3. Keep the sshd hardening load-bearing: the shipped
   `AllowStreamLocalForwarding no` is what forced the service
   replacement step. A posture check that the *listening* sshd's
   effective config (`sshd -T`) still forbids stream-local forwarding
   would notice a replaced listener.
4. Audit slot-update's extraction and the DHCP parser next; they are
   the largest remaining root- and network-reachable parsers.

## Remediation status

Recommendation 2 is implemented. There is no `esp` mount word: the
broker performs fixed ESP operations itself on a detached mount
(`esp-status`, `esp-commit`, `esp-disarm`, `esp-arm`, `esp-inspect`,
`esp-install`), and native slot files move through digest-checked
`slot-root`/`slot-decl`/`slot-meta` instead of a lent `victim` mount.
Only the supervised `slot-keep` and `slot-update` services may ask,
proven by binary, argv, cwd and the supervising `runsv` — read through
a private `task-links` helper that alone keeps `CAP_SYS_PTRACE`, since
the broker's dropped tracing authority cannot read non-dumpable
services' `/proc` links. `grub`/`victim` are lent only on bitten
boots (plus the updater's TPM retirement on native boots), and
`shutdown` only to runit stage 3; every refusal is logged. Verified by
unit tests (`identityMatches` forged-shell cases, request parsers),
`make check-persist` (`ok demo slot-commits`) and
`make check-updater` (install, boot and commit of the other slot).
The Lima playground's QEMU Secure Boot guest currently spins in
firmware before the kernel, so the same checks were run under the
project's QEMU gates rather than over SSH; that boot failure is
unrelated to the broker and remains open.

## Second hunt: staged command line (found and fixed)

A follow-up hunt for another path to arbitrary code execution found
one remaining unauthenticated input to the boot chain. Every artifact
`esp-install` copies is named by size and SHA-256 — except the staged
`cmdline` file, which the broker read from slot-update's work
directory and merged into the trial slot's loader entry unchecked.
That directory is on `/data`, writable by the confined root this
system exists to contain. During any genuine update (a window of
seconds to minutes while the broker copies the kernel and initramfs),
root could replace the staged command line after the updater wrote
it; `withSlot` then lets the replacement override same-named boot
arguments and add new ones. Proven at unit level with the real merge
and parse code: a staged line carrying
`werewolf.grubenv=UUID:/werewolf werewolf.ip=10.9.9.9/24
werewolf.seal=learn werewolf.debug=1` produces a parsing entry for
slot b treated as a bitten boot on the attacker's network identity,
with relaxed seal/debug words.

Payloads were chased and bounded: dm-verity (hash sealed in the
digest-checked initramfs) refuses a redirected root, stage0's IPE
still governs execution, `seal=learn` and `debug=1` are honored only
on DEV builds, and native UKI boots exclude unsigned loader options
entirely. So this was not a standalone ACE on release builds — but it
was a forgery of the trial boot's context (bitten treatment unlocks
the broker's `grub` mount and slot-keep's GRUB commit path, including
a `grub-setenv` write into the victim filesystem), and it broke the
digest chain every sibling artifact obeys. Fixed: `esp-install` now
carries the command line as a fourth digest artifact (`c=`), the
updater hashes the staged file it wrote, and the broker verifies
size and SHA-256 before touching the ESP or deriving any options.
Requests without `c=` are refused.

Also examined and ruled out this round: the `try`/declaration
operator path (re-arms only an existing verified slot), staged-file
TOCTOU in `copyChecked` (single pass, rename only on digest match),
the `task-links` helper (seccomp-confined to readlinkat on a private
socket), DHCP/cloud-metadata children (fixed argv, memory-safe
parsers), and kernel-command-line environment injection (leash
builds service environments from declarations, and stage0 passes
init only `WEREWOLF_BOOT`).
