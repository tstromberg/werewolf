# howl

## Summary

howl is werewolf's command-line tool. It builds a form's image, packs the
config tar a machine boots with, and creates, reaches and deletes machines,
here or in a cloud. The design is [docs/design/cli.md](../../docs/design/cli.md).

## Background

A machine is a *form* ([docs/forms.md](../../docs/forms.md)), its image, and a
config tar of secrets and settings that init reads from a block device or from
cloud user data ([docs/cloud.md](../../docs/cloud.md)).

| Verb | Does |
| --- | --- |
| `build --with FORM` | builds the image itself, byte for byte as the Makefile's recipes did ([howl-build.md](../../docs/design/howl-build.md)): boot disk (`disk.zig`, with mtools and e2fsprogs) and manifest `FORM-ARCH.json` (`manifest.zig`) in `dist`; `--format raw\|vhd\|vmdk` converts with qemu-img |
| `pack --with FORM` | writes the config tar (`-o FILE`) or only checks it (`-n`); `-h` lists FORM's flags |
| `create NAME --with FORM` | builds and boots a machine, or gives an existing one a new config; `--build` puts this checkout's programs in, not the published ones the machine updates |
| `run` | `create` of `werewolf-run`, replacing the last; default form lima on Lima, else prod-ssh |
| `ssh`, `console`, `stop`, `delete` | reach, read or remove a machine; with no NAME, run's |
| `upload DISK --on gcp\|aws\|azure` | makes a release disk a cloud image and prints its name |
| `build-apk RECIPE` | builds a form's package from a melange recipe as `build` would (`melange.zig`), and lists what each package links |
| `form ... -o DIR` | writes an ad-hoc form ([docs/design/adhoc.md](../../docs/design/adhoc.md)); build, run, create and pack take the same flags |
| `_build`, `_bhyve`, `_firecracker`, `_unpack` | internal: the Makefile's image, slot, disk and qcow2 targets (`--build`, `--programs`, `--app-root`, `--disk`, `--disk-mib`, `--disk-args` take make's BUILD, PROGRAMS, APP, DISK, DISK_MIB, DISK_ARGS); two supervisors; the OCI unpacker ([oci.md](../../docs/design/oci.md)) |

## Goals

- One command from form to running machine; what pack accepts, the machine
  accepts, because both run the same checks.
- No state but `build/machines/NAME`; each platform lists its own machines.

## Non-Goals

- Compiling werewolf's programs, or managing cloud accounts, groups, IAM or networks.

## Detailed design

**Config tar.** pack reads FORM's chain in `./forms`; each service's `config`,
`setting` and `render` lines declare a flag (`lib/service.zig`). howl's own
flags are `--config DIR`, `--hostname`, `--ip/--gw/--dns`, `--data-key`,
`--root-keys` and `--update-policy`. A FILE flag reads a file or `-` (stdin),
never a value on the line. The guest's code (`lib/settings.zig`, `network.zig`,
`update-policy.zig`) checks every value first. The tar is ustar, sorted, root's,
0600 and dated 1970, so the same inputs give the same bytes. Names are at most
100 bytes of `[A-Za-z0-9._-/]`, files at most 1 MiB. Clouds add cloud-metadata's
limits (32 files, 32 KiB each, 48 KiB in all) and AWS's and Azure's caps on user data.

**Engines.** Without `--on`, create picks Lima (macOS), bhyve (FreeBSD
x86_64), Firecracker (Linux with KVM, if sudo needs no password), else QEMU.
Local machines run the host's arch with 2 GiB and 2 CPUs, 4 under QEMU and a
Lima-managed machine; howl builds each one's image itself, as `build` does.

| `--on` | How | Needs |
| --- | --- | --- |
| lima | vz VM; Lima-managed if the form has sshd and bash (howl's template boots the image directly, on a blank `build/ARCH/disk.img` Lima copies), else its own disk on vzNAT and the DHCP lease | limactl |
| bhyve | under `howl _bhyve` via daemon(8); slirp, loopback forwards | doas/sudo, vmm, bhyve-firmware |
| firecracker | kernel and stage0 booted directly under `howl _firecracker`; per machine a tap, a /30 of 172.16.0.0/16 and iptables NAT (and ip_forward, if off), undone by delete | /dev/kvm, firecracker, sudo/doas |
| qemu | `qemu-system` in the background, booted directly (`qemu.zig`): hvf, kvm or nvmm, else tcg, and EL2 on aarch64 where the host lends it; `data.img` as vda; user networking, ssh and web on free loopback ports | qemu |
| proxmox | `qm` over ssh to `PROXMOX_HOST`; disks on `PROXMOX_STORAGE` (local-lvm), network on `PROXMOX_BRIDGE` (vmbr0); x86_64 only | ssh to a node as root |
| gcp | image via a `gs://PROJECT-werewolf-images` bucket | gcloud |
| aws | AMI written straight into an EBS snapshot | aws CLI |
| azure | managed disk via azcopy; a specialized VM on a copy | az, azcopy, a default group |

Local engines and Proxmox attach the tar as a read-only disk; clouds take it as
base64 user data. Cloud images are `werewolf-FORM-ARCH-DIGEST` (`image.zig`), so
a build uploads once and delete keeps the image. A cloud machine lets nothing in:
`--allow-from me|CIDR` opens the form's TCP ports, or create prints the commands.

**Second create.** Under QEMU, create replaces the machine and keeps /data.
Elsewhere a machine of the same form keeps its disks and takes the new config
after a hard stop (werewolf ignores shutdown requests), a graceful stop under
Lima, or a restart in a cloud. Another form, or `--app`, is refused.

## Drawbacks

- howl needs a checkout, make and Zig (stage0's and forms' own programs; all
  of them under `--build`), melange, compilers, and provider CLIs that change.

## Alternatives Considered

[cli.md](../../docs/design/cli.md#alternatives-considered) weighs Make alone, SDKs and Terraform.

## Security Considerations

| Risk | Control |
| --- | --- |
| Secrets in `ps` or shell history | FILE flags take a path or stdin, never a value |
| Shell injection through names | argument lists only; machine names `[a-z][a-z0-9-]*`, at most 32 |
| Console escapes drive the terminal | `console` passes only valid UTF-8 without C0, DEL or C1 controls to a tty |
| howl changes a machine it did not make | delete and create skip or refuse one without the `werewolf-form` tag |
| Config tar left readable | written 0600 and renamed into place; delete removes `build/machines/NAME` |
| Untrusted OCI layers | `_unpack` runs with no environment; on Linux, Landlock confines it |

## Reliability Considerations

- Images are named by content, so a retried upload or create finds them, and
  `console` works whether or not the machine came up.
- create does not roll back: a partial failure leaves named leftovers.
- Open: Proxmox has never run on a real node.
