# Service VMs in Lima, GCP and AWS

Use this with the [Tailscale](../forms/tailscale/README.md) tutorial; the
[bastion](../forms/bastion/README.md) needs no boot configuration. Those
tutorials set `FORM`, `VM` and `CONFIG_DIR`, and say which files to create;
run the commands from the repository root.
The form declares packages, accounts, service restrictions and network
policy; the boot configuration carries what differs per machine, routes
and credentials ([cloud.md](cloud.md)), so one image serves several VMs.
Install the [build tools](../examples/README.md#build-host) and, for the
local case, [Lima](https://lima-vm.io/docs/installation/) on macOS. The
commands use Lima's VZ driver and your Mac's native architecture:

```sh
export ARCH=$(uname -m | sed 's/arm64/aarch64/')
export SERVICE_BUILD="$PWD/build/$ARCH/$FORM"
mkdir -p "$SERVICE_BUILD"
umask 077
printf '%s\n' "$VM" >"$CONFIG_DIR/hostname"
make howl
build/host/howl pack --with "$FORM" -o "$SERVICE_BUILD/config.tar" --config "$CONFIG_DIR"
```

`howl pack` checks the directory against what the form declares before it
writes anything: a missing key, or a route the VM would refuse, fails here
and names the file, and it lists the targets the tar fits. `howl pack
--with "$FORM" -h` lists the form's files and settings, which can also be
given as flags. The tar holds secrets: keep it out of git.

## Local Lima VM

```sh
export VM_IP=$(build/host/howl create "$VM" --with "$FORM" --config "$CONFIG_DIR" | cut -f2)
printf '%s\n' "$VM_IP"
```

`howl create` packs and checks the config as `pack` does, with the same
flags, builds a boot disk for this VM, with A/B update slots and persistent
`/data`, and starts it under Lima's VZ driver. It prints the VM's name,
address and form. The config tar goes in as a second Lima disk,
`$VM-config`, attached unformatted, where werewolf finds it at boot; keep
`~/.lima` private. The VM gets a second network,
[vzNAT](https://lima-vm.io/docs/config/network/vmnet/), which your Mac
reaches directly; `create` waits for the address macOS's DHCP server gives
it, since these machines run no ssh for Lima to wait on. If it reports no
address, or the service is not up, `build/host/howl console "$VM"` reads
the serial console. Then return to the tutorial.

Another `create` of the same name and form replaces its config and restarts
it ([below](#change-boot-configuration)); a changed form is a new disk, so
`build/host/howl delete "$VM"`, which removes the VM, its `/data` and its
config disk, and create it again.

## GCP VM

On the default network, `howl create` does what this section does:

```sh
build/host/howl create "$VM" --with "$FORM" --on gcp --config "$CONFIG_DIR"
build/host/howl console "$VM" --on gcp
build/host/howl delete "$VM" --on gcp     # the VM; its image stays, for others of the build
```

It uses gcloud's project and zone (`CLOUDSDK_COMPUTE_ZONE` picks another),
uploads the image once per build, and prints the VM's address. On every
cloud a new machine lets nothing in: `create` ends by printing the lines
that open the form's TCP ports to your address alone (a GCP firewall rule,
an AWS security-group rule, an Azure NSG rule), and `delete` removes what
they make. `--allow-from me` runs them; `0.0.0.0/0` or a CIDR opens wider.

The steps below do it by hand, for a VPC and subnet of your own. Complete
the [GCP project setup](../examples/README.md#prepare-gcp-once), make a
bucket for the upload (`gcloud storage buckets create gs://NAME
--uniform-bucket-level-access`), and set `GCP_PROJECT`, `GCP_BUCKET`
(without `gs://`) and `GCP_ZONE` (for `aarch64`, one with `t2a-standard-1`). With a new
image and VM name for each deployment, build a pristine disk, without Lima's network
arguments, and package it for [manual
import](https://docs.cloud.google.com/compute/docs/import/import-existing-image):

```sh
export GCP_NETWORK=your-vpc
export GCP_SUBNET=your-subnet
export GCP_IMAGE="$VM-$ARCH-v1"
make FORM="$FORM" ARCH="$ARCH" DEV= "build/$ARCH/$FORM/disk.qcow2"
mkdir -p "$SERVICE_BUILD/gcp"
qemu-img convert -f qcow2 -O raw "$SERVICE_BUILD/disk.qcow2" \
  "$SERVICE_BUILD/gcp/disk.raw"
COPYFILE_DISABLE=1 tar --format=gnutar -czf "$SERVICE_BUILD/gcp/image.tar.gz" \
  -C "$SERVICE_BUILD/gcp" disk.raw
base64 <"$SERVICE_BUILD/config.tar" >"$SERVICE_BUILD/gcp/config.b64"
gcloud --project="$GCP_PROJECT" storage cp --if-generation-match=0 \
  "$SERVICE_BUILD/gcp/image.tar.gz" "gs://$GCP_BUCKET/$GCP_IMAGE.tar.gz"
```

The image holds no credentials; the config goes in as instance metadata,
which operators with instance permissions can read. The VM gets no service
account and no Secure Boot, which werewolf's bootloader does not support yet:

```sh
case "$ARCH" in
  aarch64) GCP_ARCH=ARM64; GCP_MACHINE=t2a-standard-1; GCP_NIC=GVNIC ;;
  x86_64) GCP_ARCH=X86_64; GCP_MACHINE=e2-medium; GCP_NIC=VIRTIO_NET ;;
esac
gcloud --project="$GCP_PROJECT" compute images create "$GCP_IMAGE" \
  --source-uri="gs://$GCP_BUCKET/$GCP_IMAGE.tar.gz" \
  --architecture="$GCP_ARCH" --guest-os-features=UEFI_COMPATIBLE,GVNIC
gcloud --project="$GCP_PROJECT" compute instances create "$VM" \
  --zone="$GCP_ZONE" --machine-type="$GCP_MACHINE" --image="$GCP_IMAGE" \
  --boot-disk-type=pd-balanced \
  --network-interface="network=$GCP_NETWORK,subnet=$GCP_SUBNET,nic-type=$GCP_NIC" \
  --tags="$VM" --no-service-account --no-scopes --no-shielded-secure-boot \
  --metadata-from-file="user-data=$SERVICE_BUILD/gcp/config.b64"
```

The VM gets an external IP for outbound HTTPS; the VPC must allow DNS and
HTTPS out, and the tutorial supplies any inbound rule. `gcloud compute
instances get-serial-port-output "$VM" --zone="$GCP_ZONE"` shows the boot,
and `describe "$VM" --format='get(networkInterfaces[0].accessConfigs[0].natIP)'`
the address for `VM_IP`.

## AWS VM

`howl create` makes the machine in the aws CLI's region (`aws configure`,
or `AWS_REGION` and `AWS_PROFILE`), in the default VPC:

```sh
build/host/howl create "$VM" --with "$FORM" --on aws --config "$CONFIG_DIR"
build/host/howl console "$VM" --on aws
build/host/howl delete "$VM" --on aws     # the instance, its volume and security group; the AMI stays
```

The first `create` of a build writes its disk straight into an EBS snapshot
through EBS's direct API, only the blocks that hold data, and registers it
as an AMI named `werewolf-FORM-ARCH-DIGEST` (UEFI, ENA, IMDSv2 alone);
later ones find the AMI, and nothing is set up first. The instance is a
`t4g.medium` (Graviton) or a `t3.medium`, 4 GB (`--size` picks another),
with no instance profile and the config tar in base64 as its user data
(16 KiB; `howl pack --on aws` says whether it fits). Its security group,
`werewolf-NAME`, lets nothing in until you run the lines `create` prints
([above](#gcp-vm)). `create` needs EC2 and EBS's direct snapshot API
(`ebs:StartSnapshot`, `ebs:PutSnapshotBlock`, `ebs:CompleteSnapshot`).

## Change boot configuration

In Lima and on AWS, run the same `howl create` with the changed files or
flags: it checks the new config, stops the machine (in Lima a power cut,
since it asks only a guest that answers ssh to shut down), replaces the
config disk or user data, and starts it again; the boot disk and `/data`
stay, and with them a Tailscale node's identity. On AWS the public address
changes unless it is an Elastic IP. On GCP, regenerate `config.b64` as
above, then replace the metadata and reboot:

```sh
gcloud --project="$GCP_PROJECT" compute instances add-metadata "$VM" \
  --zone="$GCP_ZONE" --metadata-from-file="user-data=$SERVICE_BUILD/gcp/config.b64"
gcloud --project="$GCP_PROJECT" compute instances reset "$VM" --zone="$GCP_ZONE"
```

Both slots read the same boot configuration, so an image rollback does not
roll back routes or credentials. Ports and service privileges are the
form's: change them by building and deploying a new one.

## Clean up GCP

Deleting the instance deletes its boot disk and data with it; the bucket
and local credentials remain. Remove a retired node from your tailnet.

```sh
gcloud --project="$GCP_PROJECT" compute instances delete "$VM" --zone="$GCP_ZONE"
gcloud --project="$GCP_PROJECT" compute images delete "$GCP_IMAGE"
gcloud --project="$GCP_PROJECT" storage rm "gs://$GCP_BUCKET/$GCP_IMAGE.tar.gz"
```
