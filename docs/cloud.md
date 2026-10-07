# Clouds

On GCP, AWS, Hetzner Cloud and Azure, a werewolf machine can take its config from
the cloud's metadata server: the same config tar a config disk carries,
set as the instance's user data. `prod`, and every form on it, asks.

## Setting it up

Make the config tar as for a config disk ([README](../README.md#configure-it)),
then hand it to the cloud in base64:

```sh
tar -cf config.tar -C config .
base64 <config.tar >config.b64

# GCP: the instance's user-data attribute
gcloud compute instances create web-1 --metadata-from-file user-data=config.b64 ...
# AWS: the instance's user data, as text
aws ec2 run-instances --user-data file://config.b64 ...
# Hetzner Cloud
hcloud server create --name web-1 --user-data-from-file config.b64 ...
# Azure: the tar itself, which az encodes in base64
az vm create --name web-1 --user-data config.tar ...
```

There is no address to give: the machine asks DHCP.

## What happens at boot

init looks for a config tar on a disk and beside the victim, and for
NoCloud, as always. Only where it finds none does it run
`/usr/lib/werewolf/cloud-metadata`, after the network is up:

1. It reads the firmware's DMI strings. `Google Compute Engine`, `Amazon
   EC2` or `Hetzner` is a cloud it knows, as is Hyper-V's `Virtual
   Machine` with the chassis asset tag only Azure sets; anything else, a
   desktop's Hyper-V included, and it asks no one. A neighbour on a flat network could answer for 169.254.169.254; a
   cloud's own hypervisor answers it there.
2. It asks the metadata server for the user data: GCP with
   `Metadata-Flavor: Google`, AWS through IMDSv2's session token, Hetzner
   plainly, Azure with `Metadata: true`. Four tries over at most half a minute.
3. It decodes the base64 and checks the tar entry by entry: regular files
   and directories only, names of letters, digits and `. _ - /`, no
   absolute paths and no `..`, at most 32 entries of 32 KiB each.
4. It writes a new tar of what passed, every entry owned by root and mode
   0600 (0700 for directories), to `/run/werewolf/cloud/config.tar`, and
   init extracts that.

User data that is not base64, such as a `#cloud-config`, is logged as
`none` and ignored. A tar with anything else in it is `refused` whole.

```
cloud-metadata: {"time":"2026-10-06T16:43:32Z","event":"config","provider":"aws","files":["authorized_keys","hostname"]}
```

## Separation

The program is two processes ([programs.md](programs.md)):

- **The fetcher** speaks HTTP. It runs as `_cloud` (uid 68), chrooted to
  the empty `/var/empty`, with no capabilities, under a seccomp filter
  that allows an IPv4 TCP socket and little else, and reads at most 128
  KiB.
- **The parent** decodes, checks and writes. It never touches the network.
  It has no capabilities at all, Landlock lets it write only beneath
  `/run/werewolf/cloud`, and seccomp allows only reading the fetcher's
  pipe and writing its file.

A fetcher that misbehaves can hand the parent no more than a well-formed
config, which whoever sets the user data can do anyway: because the parent
writes the tar afresh, nothing in the fetched one but names and contents
reaches init.

## Limits

- **Only `_cloud` can reach the metadata server's port 80.** fence's
  routing rules refuse everyone else, root included
  ([docs/design/fence.md](design/fence.md)), so the user data, and any secret
  in it, stays out of other processes' reach. Root could delete the rules
  until the seal takes `CAP_NET_ADMIN` away.
- **Whoever sets the user data is root on the machine**: it carries root's
  ssh keys. That is the cloud account's owner, as with cloud-init.
- **Not cloud-init.** Users, packages and scripts in a `#cloud-config` are
  not applied.
- **Four clouds.** Another is a row in the table in `cmd/cloud-metadata/cloud-metadata.zig`:
  its DMI strings, its path, and its header.
- **Azure only as a specialized VM.** Azure reboots a VM made from a
  generalized image unless an agent reports it ready, and werewolf has
  none; a VM whose OS disk is attached as it is needs no agent
  ([releases.md](releases.md#deploying)).
- Every cloud is tested against stand-ins under QEMU, with the firmware's
  strings and the metadata server faked, on every `make check`
  ([testing.md](testing.md)); GCP also for real, by `make check-gcp`.
