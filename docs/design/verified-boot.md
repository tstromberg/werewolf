# Verified boot

Proposed, 2026-10-06.

A werewolf machine should run only code we built and signed: its kernel, its
modules, and every executable and library. Anything else is refused, even
for root, and a reboot returns the machine to what we signed. ChromeOS does
this with firmware it controls. We do it with what our stack and the clouds
offer: dm-verity, IPE, and UEFI Secure Boot where a provider takes our keys.

## Today

Alpine's `linux-virt` 6.18.55 has dm-verity (as a module), lockdown (off by
default), Landlock, Yama and audit. It lacks IPE, IMA and a TPM driver, and
its dm-verity cannot check a signed root hash. So:

- Any user can write a binary to `/tmp`, `/run`, `/dev/shm` or a memfd and
  run it.
- root can remount the root writable, or anything `exec`, and run what it
  writes, write into running processes, and `kexec` a kernel of its
  choosing.
- On a bitten machine, root can rewrite the kernel, stage0, the root image
  or GRUB's config, and keep them across reboots.
- The updater builds slots on the machine. A key the machine can use, root
  can use, so no signature on such a slot could mean anything.

## Not goals

- **The host.** The hypervisor and the provider can change any guest; they
  are trusted.
- **Kernel exploits.** A kernel bug defeats all of this. Lockdown and the
  closed module loader shrink what root can reach in the kernel; they do not
  remove bugs.
- **Scripts.** IPE judges exec and mmap, not an interpreter reading a file.
  busybox `sh`, in every form, runs any script; a script can do only what
  the image's tools do, which is one more reason forms carry few.
- **Exploits in memory.** An exploited process can still map anonymous
  executable memory. This design stops new binaries and persistence, not
  exploitation.

## Threat model

| Attacker | Today | When done |
| --- | --- | --- |
| Code running as a service's user | runs any binary it writes to `/tmp`, `/run`, `/dev/shm` or a memfd | cannot: those are `noexec`, and IPE refuses anything not in the root image |
| root, during a boot | runs anything it writes; writes into running processes; `kexec`s another kernel | runs only the release's binaries, and scripts through them; no `kexec`, `/dev/mem` or ptrace |
| root, across a reboot | direct boot: keeps only `/data`, which nothing executes. Bitten: replaces anything in the slot or GRUB's config | direct boot and Secure Boot: keeps only `/data`. Bitten: can still replace the kernel or stage0, which nothing checks |
| The network, or a compromised mirror | stopped by apk's signatures | stopped by the manifest's signature, serial and expiry |
| Someone editing a disk snapshot | bitten: changes anything in the slot | bitten: a changed root image will not run, but a changed kernel or stage0 will. Secure Boot: nothing changed boots |

## Design

### The chain

```
host or firmware  ->  kernel, stage0, command line
stage0            ->  root.erofs under dm-verity; the release's IPE policy loaded
/init             ->  activates the policy; from here only root.erofs runs
```

Who checks the first step depends on how the machine boots:

| Boot | Kernel and stage0 checked by |
| --- | --- |
| Direct: QEMU, Lima, VZ, Firecracker | the host, which chooses them; the guest cannot change them |
| Secure Boot, on a custom image | the firmware, against our boot key |
| Bitten | nothing: GRUB is the distro's, and Secure Boot is off ([docs/bite.md](../bite.md)) |

Bitten machines get everything below except a checked kernel. Closing that
needs the provider to take our Secure Boot key, and a provider that does
would boot our image without bite.

### The kernel

We build Alpine's `linux-virt` ourselves: Alpine's APKBUILD, patches and
config, at the version Alpine ships, in an Alpine container in CI, with:

```
CONFIG_SECURITY_IPE=y                      # and in CONFIG_LSM
CONFIG_IPE_PROP_DM_VERITY=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_VERITY=y
CONFIG_SYSTEM_TRUSTED_KEYS="image.crt"     # IPE accepts policies signed by it
CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y
CONFIG_MODULE_SIG_FORCE=y
# CONFIG_KEXEC is not set
```

Modules are signed with the kernel build's own generated key, which never
leaves the build, and the kernel refuses any others. The kernel keeps
Alpine's version numbers, so the updater's kernel CVE report keeps working.
CI publishes it, and the Makefile pins it by digest, as it pins Alpine's apk
now.

There is no developer key. A certificate built into the kernel is trusted
wherever that kernel runs.

### The root image

`root.erofs` carries a dm-verity hash tree after its data (veritysetup's
`--hash-offset`). stage0 opens it with the release's root hash and mounts it
read-only, directly at `/`. There is no overlay, because whatever is written
into an overlay can be run, and because IPE judges a file by its own
filesystem's block device: through an overlay, a file from the verified root
has none, and nothing would run at all. A block that does not match its hash
fails to read.

Direct boot has no disk for the root image, so the initramfs carries it:
stage0's cpio, then a second, uncompressed cpio holding `root.erofs`, which
the kernel unpacks after the first. stage0 attaches it to a loop device. The
compressed image stays in RAM; the files read from it are cache. One boot
path serves every form, and the RAM root, the overlay and their differences
go away.

The writable places are `/data`, as now, and tmpfs on `/run`, `/tmp` and
`/dev/shm`, which init already mounts `nosuid,nodev,noexec` with the
one-way `mount` every form now carries (cmd/mount/mount.zig); busybox's cannot
set those.

What init and the services write in the root today moves to `/run`:

| Written today | Instead |
| --- | --- |
| `/etc/resolv.conf` | a symlink to `/run/resolv.conf` |
| `/etc/passwd`, `shadow`, `group` (Lima's user) | symlinks to copies in `/run/werewolf`, which init appends to itself: `adduser` replaces files by renaming within `/etc` |
| `/etc/hostname` | `hostname` set from `/run/config/hostname`; `/etc/hostname` a symlink, for readers |
| `/root/.ssh`, `/home/<user>/.ssh` | `AuthorizedKeysFile /run/werewolf/keys/%u` |
| `/etc/ssh/ssh_host_*` (`ssh-keygen -A`) | `HostKey`s in `/run/sshd` |
| `/etc/sv/*/supervise` (runsv) | symlinks to `/run/runit/supervise.<service>` |
| `/etc/runit/stopit`, `reboot` (runit-init) | symlinks into `/run/runit`, as Void Linux ships them |
| `/etc/sv/debug-shell/down` | the console service parks itself without `werewolf.debug=1` |
| `mkdir /data /victim` | directories in the image |

### The execution policy

IPE, the Integrity Policy Enforcement LSM (Linux 6.12), judges every exec,
executable mmap and module load by where the file comes from. Each release
carries a policy that allows its own root image and nothing else:

```
policy_name=werewolf policy_version=1.0.0
DEFAULT action=DENY
op=EXECUTE dmverity_roothash=sha256:<this release's root hash> action=ALLOW
```

CI signs it with the image key (`openssl smime -sign -noattr -nodetach
-nosmimecap -outform der`); the kernel loads only policies signed by a key
built into it. The policy names a root hash rather than allowing any signed
root (`dmverity_signature=TRUE`), so a machine runs this release's code and
nothing else: not an older release, not another form's tools, though we
signed both.

- **Before the policy, everything runs.** There is no boot policy; until one
  is active, the only code that has run is the kernel and stage0, which the
  boot chain delivered.
- **stage0 loads it** into `/sys/kernel/security/ipe/new_policy`, opens the
  root with the hash beside it, and hands over. The policy cannot live in
  the root image, whose hash it names.
- **init activates it first**, before anything else runs. A release's root
  image carries `/usr/share/werewolf/enforce`; if that is present and no
  policy is active, init exits, the kernel panics, and the machine falls
  back to the previous slot.
- **Nothing can switch it off.** init starts runit with `CAP_MAC_ADMIN`
  dropped from the bounding set, so no process can load a policy or put IPE
  in permissive mode. IPE checks the capability of whoever opened the
  securityfs file, so nothing may hold one open across the drop. The other
  switch, `ipe.enforce=0` on the command line, is as safe as the command
  line: fixed on direct boot and in a UKI, open to root on a bitten machine.
- **stage0's files are dead once it is active.** They are still reachable
  (stage0 moves the root over the initramfs rather than deleting it), but
  the policy does not allow them. The deadman already runs only shell
  builtins after it wakes, and must keep to that.

IPE audits each refusal, and with no audit daemon the kernel prints it, so
refusals reach the console like every other event.

Phase 1's settings stay: `lockdown=integrity`, now built in;
`vm.memfd_noexec=2`; and `kernel.yama.ptrace_scope=3`, which stops root
writing code into a running process through ptrace or `/proc/<pid>/mem`.

### Keys

| Key | Signs | Checked by | Kept |
| --- | --- | --- | --- |
| image, RSA-4096 | IPE policies, release manifests | our kernel, which has its certificate built in; the updater | a GitHub environment secret, used only by the release workflow |
| boot, RSA-2048 | UKIs | firmware, from `db` | a KMS, used only by the release workflow |
| PK, KEK | `db` updates | firmware | offline |

The boot key is RSA-2048 because that is what every UEFI firmware accepts.
The image key rotates with a kernel release, which can carry the old and new
certificates for a while. The boot key rotates with a `db` update signed by
the KEK.

### Releases

Every 15 minutes CI resolves what the published forms would be built from:
the packages, the kernel, and werewolf's own files. When that has changed,
it builds them twice on each architecture, requires the builds to match
byte for byte, boot-tests each, and publishes a release unless every image
is the same as the latest release's. werewolf's files therefore update like
everything else, without being packaged as apks. This much is done, for
`minimal` and `prod-ssh` without the hash tree or policy
([docs/releases.md](../releases.md)).

| File | Contents |
| --- | --- |
| `vmlinuz` | our kernel |
| `stage0.zst` | stage0: the form's modules, veritysetup, the signed policy and the root hash |
| `root.erofs` | the root image and its hash tree |
| `initramfs.zst` | for direct boot: stage0 and the root image |
| `werewolf.efi` | for Secure Boot: a UKI of the kernel, `initramfs.zst` and the command line |
| `manifest.json`, `manifest.json.sig` | what follows, signed with the image key |

```json
{
  "format": "werewolf-release/1",
  "form": "autoupdate",
  "arch": "aarch64",
  "serial": "20261006T124216Z",
  "expires": "2026-10-13T12:42:16Z",
  "build": "ad5c83649ab367c6",
  "kernel": "linux-virt-6.18.55-r0",
  "files": {
    "vmlinuz": {"sha256": "…", "size": 36306944},
    "stage0.zst": {"sha256": "…", "size": 9799706},
    "root.erofs": {"sha256": "…", "size": 23945216}
  },
  "packages": [{"name": "busybox-full", "version": "1.38.0-r2", "origin": "busybox"}]
}
```

The signature is RSA over the file's bytes (`openssl dgst -sha256 -sign`),
with no PKCS#7 around it, so Zig's `std.crypto` can check it. The `format`
field keeps anything else we sign from passing as a manifest.

**Before publishing**, CI boots each release under QEMU with
`werewolf.debug=1` and checks, as root on the console, that it commits; that
a copy of `/usr/bin/busybox` in `/tmp` will not run, even with `/tmp`
remounted `exec`; that `insmod` fails; and that lockdown and the policy are
active. A release that fails is not published.

### The updater

The updater stops building. Each check:

1. Fetches the manifest for its form and architecture, and checks its
   signature against the image certificate in the image.
2. Refuses it if it has expired (logging `stale`) or is older than the
   running release, by `serial`. Does nothing if `build` is the running
   build, or one that rolled back before.
3. Reports the package changes and the CVEs they fix, as now, from the
   manifest's packages against the running image's.
4. Downloads the files, checks each size and sha256, installs them in the
   other slot as now, and reboots into it once.

`outcome`, the reports, the log and the bad-build list stay. apk's version
comparison, which the CVE windows need, moves into the updater as a tested
function, so the image drops apk-tools, erofs-utils, zstd and Alpine's keys.

The manifest guards what the kernel cannot check on a bitten machine: the
kernel and stage0. A root image that is not the one its policy names runs
nothing, and the slot falls back.

CI signs a fresh manifest daily, valid for seven days, so a frozen mirror
cannot hold a machine on an old release in silence. That relies on the
clock, which comes from the hypervisor.

### Development builds

`make` builds what CI builds, without the signatures: no hash tree
(veritysetup does not run on macOS) and no policy. stage0 mounts the root
image directly and says on the console that the build is unsigned; IPE stays
inactive and everything runs, as now. To see enforcement, boot a CI release.

## Phases

Each phase ships on its own.

1. **Lockdown and sysctls**, on Alpine's kernel. Done. init raises lockdown
   to integrity through securityfs and sets `kernel.yama.ptrace_scope=3`
   and `vm.memfd_noexec=2`. root cannot lower the first two; it can lower
   the third, which binds non-root code until IPE refuses memfds outright
   in phase 4. Doing it in init
   rather than on the command line reaches every boot path, and machines
   bite took over earlier with their next image, since nothing rewrites
   their GRUB entries. Stops `kexec`, `/dev/mem`, unsigned modules, ptrace
   and executable memfds. Also done, ahead of phase 2: `/tmp`, `/run` and
   `/dev/shm` `nosuid,nodev,noexec`, `/run` writable by root alone, no user
   namespaces, the kernel's link and sticky-directory protections, and
   `hidepid=invisible` (docs/security.md). Stops users running what they
   write.
2. **A read-only root**, on Alpine's kernel. stage0 boots every form; direct
   boot carries the root image in the initramfs; no overlay; the root's
   writes moved to `/run`. Stops anyone changing the running root. root can
   still remount. Done: `make check` proves the root refuses writes and
   unlinks, and that `posture` reports it.
3. **Signed releases**: CI builds reproducibly, boot-tests and signs (done,
   [docs/releases.md](../releases.md)); it adds the hash tree, and the
   updater installs releases (under way). Until
   phase 4, dm-verity catches corruption, not attackers. Removes building
   from the machine, and brings werewolf's own files into updates.
4. **Our kernel and IPE**: the kernel above, the per-release policy, and
   `CAP_MAC_ADMIN` dropped. Stops root running anything the release does not
   carry.
5. **Secure Boot**, for providers that take our keys: AWS (`register-image
   --uefi-data`) and GCP (an image's signature database). A signed UKI per
   slot on the ESP, with the firmware's `BootNext` and `BootOrder` in place
   of GRUB's `next_entry` and default. Relies on DHCP, which init uses
   when the command line names no address, since a signed command line
   cannot carry a machine's address. Stops
   persistence on those machines.

## Alternatives considered

- **noexec alone.** root remounts, or mounts its own tmpfs in a user
  namespace.
- **The BPF LSM.** Alpine's kernel builds it but leaves it out of
  `CONFIG_LSM`; `lsm=` would turn it on without a kernel build. Its
  self-protection against root (unloading, the `bpf` syscall, its pins)
  would be ours to get right.
- **IMA appraisal, or fs-verity with IPE.** A signature per file, kept in
  xattrs or by a filesystem that supports it. One root hash covers the image.
- **Signed root hashes** (`dmverity_signature=TRUE`). One policy for every
  release, but every root image we ever signed would run.
- **Signing on the machine.** A key the machine can use, root can use.
  Sealing it to a TPM needs a TPM driver, and the TPM still signs for root
  while the machine is in its good state.
- **ChromeOS's vboot.** Needs firmware we control.

## Open questions

- **IPE on 6.18.** Answered; see *IPE, tested*.
- **Key custody.** The image key is a GitHub environment secret, which
  openssl signs with directly, PKCS#7 included. Moving it to a KMS would
  need a PKCS#11 provider, or the PKCS#7 built around a KMS signature.
- **Rollback.** An older signed release still boots if root installs it on a
  bitten machine, or writes an older UKI to the ESP. TPM counters, as
  ChromeOS uses, would stop that; our kernel can carry the TPM driver.
- **stage0's size.** veritysetup brings libcryptsetup and its libraries;
  `dmsetup` with a table may be smaller.
- **Hosting.** GitHub Releases, for now. How long old releases stay.
- **Reproducible kernels.** The generated module key makes each build's
  modules differ.

## IPE, tested

On 2026-10-06, Alpine's `linux-virt` 6.18.55 config built with the options
under *The kernel* (kernel image only, 2 min 14 s on 8 cores), with a
throwaway certificate, booted the `crypt` image under QEMU. `test/boot` ran
these as root on the console, in order; each came out as below.

| | |
| --- | --- |
| No policy loaded | a copy of busybox in `/tmp` runs |
| A signed policy, loaded and activated through securityfs | accepted |
| busybox on the dm-verity image the policy names | runs |
| busybox on another dm-verity image, verified but not named | refused |
| A copy in `/tmp` | refused |
| `ld.so` loading the unnamed image's busybox | refused, at mmap |
| A copy written into the initramfs, with `boot_verified=TRUE` allowed | runs |
| root writing 0 to `/sys/kernel/security/ipe/enforce` | accepted; the `/tmp` copy then runs, until 1 is written back |

Each refusal reached the console as an audit record naming the hook, the
path, its device and the rule:

```
audit: type=1420 ... ipe_op=EXECUTE ipe_hook=BPRM_CHECK enforcing=1 pid=539 comm="ash" path="/tmp/tmp.eBs3zE/busybox" dev="tmpfs" ino=7 rule="DEFAULT op=EXECUTE action=DENY"
```

IPE's source (`security/ipe/`) agrees: every securityfs write, `enforce`
included, needs `CAP_MAC_ADMIN` in the initial user namespace, checked
against the opener's credentials (`file_ns_capable`); with no active policy
it allows everything; activation refuses only a lower version than the
active policy's; and `ipe.enforce` is a boot parameter. The Kconfig names
above are the kernel's.

So the design holds as written, with two rules made firm: no policy may
trust `boot_verified` once the root is mounted, since the initramfs stays
writable and its files count as verified; and `CAP_MAC_ADMIN` must go from
the bounding set, since root holding it can turn enforcement off.
