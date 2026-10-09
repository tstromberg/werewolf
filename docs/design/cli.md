# howl: the werewolf command

Built, 2026-10-07 (cmd/howl, [README](../../cmd/howl/README.md)). Run end
to end on Lima, GCP, AWS and Azure; bhyve, Firecracker and Proxmox are
experimental, Proxmox never run on a node. `pack --image` is not built.

## Summary

`howl` builds a form's image, packs a machine's config tar, and puts both
on a machine, here or in a cloud. Users run howl; contributors run make.

## Background

A machine is a *form* ([forms.md](../forms.md)), which says what runs and
changes only by a rebuild, plus a *config tar* of per-machine settings and
secrets ([cloud.md](../cloud.md)). Before howl, make was the interface: it
ignored unknown variables, checked nothing, and left users packing the tar
by hand.

## Goals

- A bastion or Tailscale router from a clean checkout in one command.
- Every config error the host can find, it finds, naming the file.
- The same inputs give the same tar, and the same image with a manifest.
- Any hypervisor that attaches two disks runs werewolf with no howl code.

## Non-Goals

- A daemon, a state file, plugins, prompts, `start`/`stop`, a `bite` verb.
- Building the application, or `make` deploying machines. (Building
  without make was a non-goal; [howl-build.md](howl-build.md) makes it one.)

## Detailed design

`build` makes a *file*, by itself and byte for byte as make's `_dist-form`
did ([howl-build.md](howl-build.md)), never with `DEV`, so every image has a
release's manifest ([releases.md](../releases.md)).
`create` makes a *machine*: it builds if stale, packs, uploads only an
image the cloud lacks, starts the machine, waits for init's `up in`, and
prints `NAME ADDRESS FORM`. `run` is `create` of one throwaway machine,
`werewolf-run`. Each platform is driven by its own tool (`limactl`, `qm`,
`gcloud`, `aws`, `az`…) with argument lists: no SDK, no state file.

| Target | Choice, and why |
| --- | --- |
| lima | vzNAT unless the form has sshd and bash, which Lima's probes need; bash in every image costs too much |
| firecracker | `root.erofs` as a drive: in the initramfs it pins 20 MB of RAM and boots 10–15 ms slower |
| proxmox | `qm` over ssh: the REST API has no serial log, and no address without a guest agent |
| aws | an EBS snapshot written directly: VM Import took 6–10 minutes and a hand-made bucket and role |

### CONFIG: the config tar from flags

`pack`, `run` and `create` take the same flags. Beyond howl's own, the
form declares them: a service's `config NAME PATH` line is a `--NAME FILE`
flag and `setting NAME TYPE` a `--NAME VALUE` one ([settings.md](settings.md)),
so the list grows with the form, not with howl:
`howl create router --with tailscale --auth-key - --routes 10.20.0.0/24`.
howl refuses a chain that declares a name twice; qualifying the names
would rename a flag whenever a service is added. `--ip`/`--gw`/`--dns`
write the `network` file, which init reads from a config disk but never
from cloud user data ([lib/README.md](../../lib/README.md#network)). `pack`
makes no host key: [ssh-host-key](../../cmd/ssh-host-key/README.md) makes
one on the machine, so its private half never leaves.

## Drawbacks

- **Two interfaces**, and `howl run` and `create` call make until howl-build.md's stage 2.
- **Flags from service files are indirect**: a typo there is a missing flag.
- **Five provider CLIs** change output and flags on their own schedules.
- **Azure copies a disk per machine**: a reusable image needs a root agent.

## Alternatives Considered

- **Keep make.** It cannot validate a variable, read a service file, or
  write a deterministic tar without shell.
- **Other verbs.** One `boot` would hide that `run` keeps one unnamed
  machine; `check` is `make check`; `create`/`delete` is every cloud's pair.
- **Per-form flags in howl, or a generic `--set K=V`.** The first changes
  howl for every form; the second makes users spell guest paths.
- **Declarations in the manifest, for `--image`.** A second source of truth.
- **A provider SDK, or Terraform.** A dependency per cloud, or a daemon's
  worth of state; an argument list is auditable.

## Security Considerations

- **The host checks with the guest's code** (`lib/service.zig`,
  `settings.zig`, `network.zig`), so the two cannot drift; the guest's
  check still counts. A value fills only a key the image declared.
- **Proxmox's `qm` runs through the node's shell**, so `PROXMOX_*` values
  must be plain words.
- **Whoever sets user data holds root's keys** ([cloud.md](../cloud.md)).
  Open: `create` does not say which account set it.

## Reliability Considerations

- **No state to lose**: a machine left by a laptop that died mid-`create`
  is in the provider's list, for `delete`. Failures leave named leftovers.
- **Open: tested by hand.** `make check` uses `howl pack`; the cloud
  checks run `create` and `delete`, but nothing runs them on a schedule.
