# howl

## Summary

Howl builds and runs machines ([design](../../docs/design/cli.md)).
Each combines a [form](../../docs/forms.md), image and init configuration.

## Background

| Verb | Does |
| --- | --- |
| `forms [FORM\|SEARCH]` | lists forms or shows setup and run/test commands; uses the checkout when present, `--published` checks signed image availability, `--arch ARCH` filters and `--json` emits records |
| `versions [--with FORM]` | lists published base image tags from GitHub; filters by `--on` and `--arch`, with `--json` for scripts |
| `build --with FORM` | builds what `create` deploys: with every protection a bundle, `FORM-PROVIDER-ARCH` in `dist` (`--on lima\|qemu`), signed with your keys as CI signs werewolf's; with `--disable=…` the disk and manifest `FORM-ARCH.json` byte for byte as the Makefile's recipes did ([howl-build.md](../../docs/design/howl-build.md)), `--format raw\|vhd\|vmdk` converting with qemu-img |
| `test --with FORM [--arch ARCH]` | runs declared native clients (PostgreSQL uses psql without DEV), or legacy checks, plus production boot; logs in `build/ARCH/check/`; either suite failing returns failure |
| `pack --with FORM` | writes the config tar (`-o FILE`) or only checks it (`-n`); `-h` lists FORM's flags |
| `create NAME --with FORM` | builds and boots a machine, or gives an existing one a new config; `--version SERIAL\|TAG` selects the initial download; `--build` builds this checkout's bundle and enrolls it as a download, a rerun offering the next as an update |
| `apply FILE [--name NAME] [-n]` | prepares and publishes an enrolled declaration as signed `local-NAME`; `updates.from` is its HTTPS repository, `--to ssh://HOST/PATH` selects SSH upload ([manifest.md](../../docs/design/manifest.md)) |
| `run` | secure `create` of `werewolf-run`, reusing an unchanged protected VM; default playground downloads a protected image; `--build` uses local sources |
| `owner [NAME] status\|check\|try\|outcome\|pause\|resume` | fixed host-private QEMU operations without guest SSH; [details](../../docs/owner-control.md) |
| `ssh`, `console`, `stop`, `delete` | reach or read a machine; stop keeps protected local state, delete removes it; without NAME, run's |
| `upload DISK --on gcp\|aws\|azure` | makes a release disk a cloud image and prints its name |
| `build-apk RECIPE` | builds a form's package from a melange recipe as `build` would (`melange.zig`), and lists what each package links |
| `form [-f FILE] ... -o DIR` | writes a form from a manifest and the line, whose flags are form.yaml's keys ([docs/design/adhoc.md](../../docs/design/adhoc.md)); build, run, create and pack take the same |
| `_build`, `_bhyve`, `_firecracker`, `_unpack` | internal: the Makefile's image, slot, disk and qcow2 targets (`--build`, `--programs`, `--app-root`, `--disk`, `--disk-mib`, `--disk-args` take make's BUILD, PROGRAMS, APP, DISK, DISK_MIB, DISK_ARGS); two supervisors; the OCI unpacker ([oci.md](../../docs/design/oci.md)) |

## Goals

- One command from form to running machine; pack and the machine make the same checks.
- Records in `build/machines/NAME`; keys in `$XDG_DATA_HOME/howl`
  (`~/.local/share/howl`).

## Non-Goals

- Managing cloud accounts, IAM or cloud networks.

## Detailed design

**Forms.** Names use the signed index, falling back to `./forms/NAME` with a warning.
Path forms are never updated.

**Config tar.** Services declare flags with `config`, `setting` and `render`;
`pack -h` lists all flags. FILE flags read paths or stdin; guests validate values.
The tar is sorted root-owned ustar, 0600, dated 1970, within init and metadata limits.

**Engines.** Protected defaults are Lima (macOS) and QEMU (Linux). Missing tools fail.
Other providers and `--dev` require [disabling
protections](../../docs/security.md#protections-a-machine-can-be-made-without).
Downloads require the provider's [protected
profile](../../docs/design/published-secure-boot.md). Local VMs use the host
architecture, 2 GiB and 2 CPUs (4 under QEMU and Lima-managed).

| `--on` | How | Needs |
| --- | --- | --- |
| lima | default QEMU with enrolled firmware, IPE and persistent TPM; `--disable=…` uses VZ | limactl, qemu, swtpm, firmware tools |
| bhyve | FreeBSD x86_64 or arm64, supervised by howl; TAP by default; explicit `--network slirp` | doas/sudo, vmm, Python 3; bhyve-firmware (x86_64) or u-boot-bhyve-arm64; libslirp for SLIRP |
| firecracker | its own UEFI disk, under `howl _firecracker`, which plays systemd-boot (picks the entry, spends a try, boots that slot's kernel and stage0), so it updates in place; per machine a tap, a /30 of 172.16.0.0/16 and iptables NAT (and ip_forward, if off), undone by delete | /dev/kvm, firecracker, mtools, sudo/doas |
| qemu | `qemu-system` in the background, its own disk booted by edk2 from its slots, so it updates in place (`qemu.zig`): hvf, kvm or nvmm, else tcg; user networking, ssh and web on free loopback ports | qemu, edk2 |
| proxmox | `qm` over ssh to `PROXMOX_HOST`; disks on `PROXMOX_STORAGE` (local-lvm), network on `PROXMOX_BRIDGE` (vmbr0); x86_64 only | ssh to a node as root |
| gcp | image via a `gs://PROJECT-werewolf-images` bucket | gcloud |
| aws | AMI written straight into an EBS snapshot | aws CLI |
| azure | managed disk via azcopy; a specialized VM on a copy | az, azcopy, a default group |

bhyve's ARM64 runtime remains experimental; its TAP soak hit a virtio TX panic.
See [live tests](../../docs/testing-live.md#bhyve) for networking and runtime limits.

Local engines and Proxmox attach the tar read-only; clouds take base64 user data, and
their images are `werewolf-FORM-ARCH-DIGEST` (`image.zig`): a build uploads once, and
delete keeps the image. Nothing gets in until `--allow-from me|CIDR` opens the ports.

**Second create.** The machine keeps its disk and takes the new config; another form,
`--app`, or `--import` is refused. `howl run` reuses matching protected inputs and
resumes a stopped VM; changed inputs replace it. `--import DIR` is a read-only disk the
form reads once, while its data is first made ([data.md](../../docs/data.md)); a cloud
cannot attach it. Progress goes to stderr and the machine record to stdout.

## Drawbacks

Local builds need the checkout and build tools; clouds need their provider CLIs.

## Alternatives Considered

[Make, SDKs and Terraform](../../docs/design/cli.md#alternatives-considered).

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

## Reliability Considerations

Content names make uploads and creates retryable; console works after a failed boot.
Partial failures leave named resources. Proxmox still needs testing on a real node.
