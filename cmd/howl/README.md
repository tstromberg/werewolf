# howl

## Summary

Howl builds and runs machines ([design](../../docs/design/implemented/cli.md)).
Each combines a [form](../../docs/forms.md), image and init configuration.

## Background

| Verb | Does |
| --- | --- |
| `forms [FORM\|SEARCH]` | lists forms or shows setup and run/test commands; uses the checkout when present, `--published` checks signed image availability, `--arch ARCH` filters and `--json` emits records |
| `versions [--with FORM]` | lists published base image tags from GitHub; filters by `--on` and `--arch`, with `--json` for scripts |
| `build --with FORM` | builds what `create` deploys: with every protection a bundle, `FORM-PROVIDER-ARCH` in `dist` (`--on lima\|qemu`), signed with your keys as CI signs werewolf's, following the channel `--ipe-updates URL` names at `--image-index N`; with `--disable=…` the disk and manifest `FORM-ARCH.json` byte for byte as the Makefile's recipes did ([howl-build.md](../../docs/design/implemented/howl-build.md)), `--format raw\|vhd\|vmdk` converting with qemu-img |
| `test --with FORM [--arch ARCH]` | runs declared native clients without DEV, or a runtime's hello-world application, plus production boot; logs in `build/ARCH/check/`; either suite failing returns failure; `--iterate` reuses a disposable SSH VM for development |
| `pack --with FORM` | writes the config tar (`-o FILE`) or only checks it (`-n`); `-h` lists FORM's flags |
| `create NAME --with FORM` | builds and boots a machine, or gives an existing one a new config; `--version SERIAL\|TAG` selects the initial download; `--build` builds this checkout's bundle with your keys and enrolls it as a download; it follows a channel only if `IPE_UPDATES` names one (with `IMAGE_INDEX`; `IPE_UPDATES_CA` on Lima and QEMU), else changes take a reinstall ([design](../../docs/design/implemented/secure-local-deployment.md)) |
| `apply FILE [--name NAME] [-n]` | prepares and publishes an enrolled declaration as signed `local-NAME`; `updates.from` is its HTTPS repository, `--to ssh://HOST/PATH` selects SSH upload ([manifest.md](../../docs/design/implemented/manifest.md)) |
| `run` | secure `create` of `werewolf-run`, reusing an unchanged protected VM and resuming a stopped one; default playground downloads a protected image; `--build` uses local sources, reinstalling the VM when they change |
| `owner [NAME] status\|check\|try\|outcome\|pause\|resume` | fixed host-private QEMU operations without guest SSH; [details](../../docs/owner-control.md) |
| `ssh`, `console`, `stop`, `delete` | reach or read a machine; stop keeps protected local state, delete removes it; without NAME, run's |
| `upload DISK --on gcp\|aws\|azure` | makes a release disk a cloud image and prints its name |
| `build-apk RECIPE` | builds a form's package from a melange recipe as `build` would (`melange.zig`), and lists what each package links |
| `form [-f FILE] ... -o DIR` | writes a form from a manifest and the line, whose flags are form.yaml's keys ([docs/design/implemented/adhoc.md](../../docs/design/implemented/adhoc.md)); build, run, create and pack take the same |
| `_build`, `_bhyve`, `_firecracker`, `_tpm`, `_unpack` | internal: the Makefile's image, slot, disk and qcow2 targets (`--build`, `--programs`, `--app-root`, `--disk`, `--disk-mib`, `--disk-args` take make's BUILD, PROGRAMS, APP, DISK, DISK_MIB, DISK_ARGS); `--boot-native --tpm`, `--image-index` and `--update-ca` make a protected slot; three supervisors, the last a protected machine's swtpm (`swtpm.zig`); the OCI unpacker ([oci.md](../../docs/design/implemented/oci.md)); `_build-helper` and `_native-firmware` serve tools/enroll-boot ([macOS builds](../../docs/macos-builds.md)) |

## Goals

- One command from form to running machine; pack and the machine make the same
  checks.
- Records: `build/machines/NAME`; keys: `$XDG_DATA_HOME/howl`
  (`~/.local/share/howl`).

## Non-Goals

- Managing cloud accounts, IAM or cloud networks.

## Detailed design

Run/create, build, pack and test accept repeated or comma-separated `--variant NAME`.
Every form offers `--ssh`; see [variants](../../docs/variants.md).

**Forms.** Names use the signed index, falling back to `./forms/NAME` with a warning.
Path forms are never updated. Progress goes to stderr, the machine record to stdout.

**Config tar.** Services declare flags with `config`, `setting` and `render`; `pack
-h` lists all flags. FILE flags read paths or stdin; guests validate values. The tar
is sorted root-owned ustar, 0600, dated 1970, within init and metadata limits.

**Engines.** Protected defaults are Lima (macOS), QEMU (Linux) and x86_64 bhyve
(FreeBSD), which download a [protected
image](../../docs/design/implemented/published-secure-boot.md). Clouds take protected
`--build` images: werewolf publishes none yet. Firecracker builds an IPE image with
host-pinned boot files, warning that UEFI Secure Boot and TPM rollback protection are
unavailable. Other providers and `--dev=ssh` require [disabling
protections](../../docs/security.md#protections-a-machine-can-be-made-without).
Missing tools fail. Local VMs use the host architecture, 4 GiB and 2 CPUs (4 under
QEMU and Lima-managed).

| `--on` | How | Needs |
| --- | --- | --- |
| lima | default QEMU with enrolled firmware, IPE and persistent TPM; `--disable=…` uses VZ | limactl, qemu, swtpm, firmware tools |
| bhyve | FreeBSD x86_64: enrolled Secure Boot, IPE and persistent TPM, using the signed x86 QEMU image channel and its SLIRP network. TAP for images built for it; network selection persists across stop/start. ARM64 remains experimental and requires explicit protection disablement ([limits](../../docs/testing-live.md#bhyve)). | doas/sudo, vmm, bhyve-firmware, swtpm, virt-firmware, libslirp; TAP needs an existing bridge; ARM64 needs u-boot-bhyve-arm64 |
| firecracker | IPE and dm-verity, with boot files pinned on the trusted host; no UEFI Secure Boot or TPM, with a warning explaining the risks. Automatic namespace confinement, tap filtering, bounded logs and I/O limits. Image changes require host rebuilds. Explicit `--disable=secureboot,tpm,ipe` retains legacy A/B boot selection. Per machine a tap, a /30 of 172.16.0.0/16 and NAT, undone by delete | /dev/kvm, Firecracker 1.17+, bubblewrap with user namespaces, prlimit, timeout, mtools, iptables/ip6tables, sudo/doas, image build tools |
| qemu | `qemu-system` in the background, its own disk booted by edk2 from its slots, so it updates in place (`qemu.zig`): hvf, kvm or nvmm, else tcg; user networking, ssh and web on free loopback ports | qemu, edk2 |
| proxmox | `qm` over ssh to `PROXMOX_HOST`; disks on `PROXMOX_STORAGE` (local-lvm), network on `PROXMOX_BRIDGE` (vmbr0); x86_64 only | ssh to a node as root |
| gcp | image via a `gs://PROJECT-werewolf-images` bucket; C4, C4A and N4 boot from `hyperdisk-balanced` | gcloud |
| aws | AMI written straight into an EBS snapshot | aws CLI |
| azure | managed disk via azcopy; a specialized VM on a copy | az, azcopy, a default group |

Local engines and Proxmox attach the tar read-only; clouds take base64 user data and
a `werewolf-FORM-ARCH-DIGEST` image (`image.zig`), which a build uploads once and
delete keeps. Cloud ports start closed; create's `--allow-from me|CIDR` opens the
form's.

**SSH.** See [Howl SSH connections](../../docs/design/implemented/howl-ssh.md) for
account defaults, developer access, forwarded agents and cloud firewall behavior.

**Second create.** The machine keeps its disk and takes the new config.
`howl export NAME [--service NAME] [--output FILE]` writes a private data archive.
`howl import NAME ARCHIVE [--service NAME]` restores empty data and leaves the
machine stopped. See [data storage](../../docs/data.md) for supported adapters,
image requirements and exclusions. `create --import`, directory seeds and `sync`
are no longer supported.

## Drawbacks

Local builds need the checkout and build tools; clouds need their provider CLIs.

## Security Considerations

| Risk | Control |
| --- | --- |
| Secrets in `ps` or shell history | FILE flags take a path or stdin, never a value |
| Shell injection through names | argument lists only; machine names `[a-z][a-z0-9-]*`, at most 32 |
| Console escapes drive the terminal | `console` passes only valid UTF-8 without C0, DEL or C1 controls to a tty |
| howl changes a machine it did not make | delete and create skip or refuse one without the `werewolf-form` tag |
| Config tar left readable | written 0600 and renamed into place; delete removes `build/machines/NAME` |
| Untrusted OCI layers | `_unpack` runs with no environment; on Linux, Landlock confines it |
| A forged or swapped form | a name's form is taken only as the packages key's index lists it (`lib/apk.zig`) |
