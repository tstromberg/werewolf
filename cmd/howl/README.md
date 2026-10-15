# howl

## Summary

howl builds images, packs boot config, and creates, updates, reaches and deletes
machines here or in a cloud ([docs/design/cli.md](../../docs/design/cli.md)). A machine
is a *form* ([docs/forms.md](../../docs/forms.md)), its image, and a config tar init
reads from a disk or user data ([docs/cloud.md](../../docs/cloud.md)).

| Verb | Does |
| --- | --- |
| `forms [FORM\|SEARCH]` | lists forms or shows setup and run/test commands; uses the checkout when present, `--published` checks signed image availability, `--arch ARCH` filters and `--json` emits records |
| `build --with FORM` | builds what `create` deploys: with every protection a bundle, `FORM-PROVIDER-ARCH` in `dist` (`--on lima\|qemu`), signed with your keys as CI signs werewolf's; with `--disable=…` the disk and manifest `FORM-ARCH.json` byte for byte as the Makefile's recipes did ([howl-build.md](../../docs/design/howl-build.md)), `--format raw\|vhd\|vmdk` converting with qemu-img |
| `test --with FORM [--arch ARCH]` | runs declared native clients (PostgreSQL uses psql without DEV), or legacy checks, plus production boot; logs in `build/ARCH/check/`; either suite failing returns failure |
| `pack --with FORM` | writes the config tar (`-o FILE`) or only checks it (`-n`); `-h` lists FORM's flags |
| `create NAME --with FORM` | builds and boots a machine, or gives an existing one a new config; `--build` builds this checkout's bundle and enrolls it as a download, a rerun offering the next as an update |
| `apply FILE [--name NAME] [-n]` | prepares and publishes an enrolled declaration as signed `local-NAME`; `updates.from` is its HTTPS repository, `--to ssh://HOST/PATH` selects SSH upload ([manifest.md](../../docs/design/manifest.md)) |
| `run` | secure `create` of `werewolf-run`, reusing an unchanged protected VM; default playground downloads a protected image; `--build` uses local sources |
| `ssh`, `console`, `stop`, `delete` | reach or read a machine; stop keeps protected local state, delete removes it; without NAME, run's |
| `upload DISK --on gcp\|aws\|azure` | makes a release disk a cloud image and prints its name |
| `build-apk RECIPE` | builds a form's package from a melange recipe as `build` would (`melange.zig`), and lists what each package links |
| `form [-f FILE] ... -o DIR` | writes a form from a manifest and the line, whose flags are form.yaml's keys ([docs/design/adhoc.md](../../docs/design/adhoc.md)); build, run, create and pack take the same |
| `_build`, `_bhyve`, `_firecracker`, `_unpack` | internal: the Makefile's image, slot, disk and qcow2 targets (`--build`, `--programs`, `--app-root`, `--disk`, `--disk-mib`, `--disk-args` take make's BUILD, PROGRAMS, APP, DISK, DISK_MIB, DISK_ARGS); two supervisors; the OCI unpacker ([oci.md](../../docs/design/oci.md)) |

## Goals

- One command from form to running machine; pack and the machine make the same checks.
- Machine records in `build/machines/NAME`; keys and repositories in
  `$XDG_DATA_HOME/howl` (`~/.local/share/howl`), never in `build/`.

## Non-Goals

- Compiling werewolf's programs, or managing cloud accounts, groups, IAM or networks.

## Detailed design

**Forms.** A name is NAME-form, from werewolf's repository by its signed index
(`published.zig`), which the machine updates; one not published yet is `./forms/NAME`,
with a warning. A path is the caller's own, never updated.

**Config tar.** Each service's `config`, `setting` and `render` lines declare a flag
(`lib/service.zig`); howl adds `--config DIR`, `--hostname`, `--ip/--gw/--dns`,
`--data-key`, `--root-keys`, `--update-policy`. A FILE flag reads a file or `-`, never a
value, and the guest's code checks every value first. The tar is ustar, sorted, root's,
0600, dated 1970, within init's and cloud-metadata's limits.

**Engines.** Protected create defaults to Lima (macOS) and QEMU (Linux); missing
prerequisites fail. Other providers and `--dev` need `--disable=secureboot,tpm,ipe`
([why](../../docs/security.md#protections-a-machine-can-be-made-without)); a download
needs its provider's [protected profile](../../docs/design/published-secure-boot.md).
A local machine takes the host's arch, 2 GiB and 2 CPUs (4 under QEMU and Lima-managed).

| `--on` | How | Needs |
| --- | --- | --- |
| lima | default QEMU with enrolled firmware, IPE and persistent TPM; `--disable=…` uses VZ | limactl, qemu, swtpm, firmware tools |
| bhyve | under `howl _bhyve` via daemon(8); slirp, loopback forwards | doas/sudo, vmm, bhyve-firmware |
| firecracker | its own UEFI disk, under `howl _firecracker`, which plays systemd-boot (picks the entry, spends a try, boots that slot's kernel and stage0), so it updates in place; per machine a tap, a /30 of 172.16.0.0/16 and iptables NAT (and ip_forward, if off), undone by delete | /dev/kvm, firecracker, mtools, sudo/doas |
| qemu | `qemu-system` in the background, its own disk booted by edk2 from its slots, so it updates in place (`qemu.zig`): hvf, kvm or nvmm, else tcg; user networking, ssh and web on free loopback ports | qemu, edk2 |
| proxmox | `qm` over ssh to `PROXMOX_HOST`; disks on `PROXMOX_STORAGE` (local-lvm), network on `PROXMOX_BRIDGE` (vmbr0); x86_64 only | ssh to a node as root |
| gcp | image via a `gs://PROJECT-werewolf-images` bucket | gcloud |
| aws | AMI written straight into an EBS snapshot | aws CLI |
| azure | managed disk via azcopy; a specialized VM on a copy | az, azcopy, a default group |

Local engines and Proxmox attach the tar read-only; clouds take base64 user data, and
their images are `werewolf-FORM-ARCH-DIGEST` (`image.zig`): a build uploads once, and
delete keeps the image. Nothing gets in until `--allow-from me|CIDR` opens the ports.

**Second create.** The machine keeps its disk and takes the new config; another form,
`--app`, or `--import` is refused. `howl run` reuses matching protected inputs and
resumes a stopped VM; changed inputs replace it. `--import DIR` is a read-only disk the
form reads once, while its data is first made ([data.md](../../docs/data.md)); a cloud
cannot attach it. Progress goes to stderr and the machine record to stdout.

## Drawbacks

- `--build` and path forms need a checkout, make, Zig, melange, compilers, cloud CLIs.

## Alternatives Considered

Make alone, SDKs and Terraform:
[cli.md](../../docs/design/cli.md#alternatives-considered).

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

- Images are named by content: a retried upload or create finds them; `console` works
  whether or not the machine came up. create does not roll back: a partial failure
  leaves named leftovers. Open: Proxmox has never run on a real node.
