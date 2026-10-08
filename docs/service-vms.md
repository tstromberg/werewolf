# Service VMs in Lima, GCP and AWS

Use this with the [bastion](../forms/bastion/README.md) or [Tailscale](../forms/tailscale/README.md) tutorial.
Those tutorials set `FORM`, `VM` and `CONFIG_DIR`, and explain
which files to create. Run commands from the repository root.

The form declares packages, accounts, service restrictions and network
policy. Boot configuration carries destinations/routes and instance credentials. Keeping those inputs
separate lets several VMs use the same image with different keys.

Install the [build tools](../examples/README.md#build-host). For the local
case, install [Lima](https://lima-vm.io/docs/installation/) on macOS. The
commands below use its VZ driver and your Mac's native architecture:

```sh
export ARCH=$(uname -m | sed 's/arm64/aarch64/')
export SERVICE_BUILD="$PWD/build/$ARCH/$FORM"
mkdir -p "$SERVICE_BUILD"
umask 077
printf '%s\n' "$VM" >"$CONFIG_DIR/hostname"
make werewolf
build/host/werewolf pack "$FORM" -o "$SERVICE_BUILD/config.tar" --config "$CONFIG_DIR"
```

`werewolf pack` checks the directory against what the form declares
before it writes anything: a missing key, or a destination or route the
VM would refuse, fails here and names the file. It lists the targets the
tar fits; cloud metadata limits the config to 32 files of at most 32 KiB,
and AWS's user data to 16 KiB. `werewolf pack "$FORM" -h` lists the
form's files and settings, which can also be given as flags. The tar
contains secrets. Keep it private and out of Git. Base64 is an encoding,
not encryption.

## Local Lima VM

```sh
export VM_IP=$(build/host/werewolf create "$FORM" "$VM" --config "$CONFIG_DIR" | cut -f2)
printf '%s\n' "$VM_IP"
```

`werewolf create` packs and checks the config as `werewolf pack` does,
builds a boot disk for this VM, with A/B update slots and persistent
`/data`, and starts it under Lima's VZ driver. It prints the VM's name,
address and form; the line above keeps the address. It takes the same
flags as `pack`, so a setting can also be given on the line.

The config tar goes in as a second Lima disk, `$VM-config`, attached
unformatted, where werewolf finds it at boot. Lima's instance file holds
no copy of a secret, but the disk does: keep `~/.lima` private. The VM
gets a second network, [vzNAT](https://lima-vm.io/docs/config/network/vmnet/),
which your Mac reaches directly. Its MAC is derived from the VM's name,
and `create` waits for the address macOS's DHCP server gives it, since
these machines run no ssh for Lima to wait on.

If `create` reports no address, or the service is not up, read the VM's
serial console:

```sh
build/host/werewolf console "$VM"
```

Return to the service tutorial to verify forwarding or tailnet access.
Use a subnet the VM can reach; avoid advertising a subnet already local
to your test client, which may send traffic directly instead of through
Tailscale.

Another `create` of the same name and form replaces its config and
restarts it; see [changing it](#change-boot-configuration). A changed form
is a new disk, so delete the VM and create it again. To remove the VM,
with its `/data` and its config disk:

```sh
build/host/werewolf delete "$VM"
```

## GCP VM

On the default network, `werewolf create` does what this section does:

```sh
build/host/werewolf create "$FORM" "$VM" --on gcp --config "$CONFIG_DIR"
build/host/werewolf console "$VM" --on gcp
build/host/werewolf delete "$VM" --on gcp     # the VM; its image stays, for others of the build
```

It uses gcloud's project and zone (`CLOUDSDK_COMPUTE_ZONE` picks another),
uploads the image only once per build, and prints the VM's address.

On every cloud, a new machine lets nothing in, and `create` ends by
printing the lines that open the TCP ports its form listens on, to your
address alone, to paste as they are; `delete` removes what they make. For
a form that listens on 22 and 8080, on GCP:

```
werewolf: web: nothing reaches it yet; to let this host in on ports 22 8080:
ME=$(curl -fsS https://checkip.amazonaws.com)
gcloud compute firewall-rules create web-allow --project PROJECT --target-tags web --source-ranges "$ME/32" --allow tcp:22,tcp:8080
```

On AWS they are `aws ec2 authorize-security-group-ingress` lines for the
machine's own security group, and on Azure an `az network nsg rule create`
for its network security group. Or let `create` run them itself:
`--allow-from me` opens the ports to your address, `--allow-from
0.0.0.0/0` to everyone, for a public service, and any IPv4 CIDR to a
network.

The steps below do it by hand, for a VPC and subnet of your own.

Complete the [GCP project and bucket setup](../examples/README.md#prepare-gcp-once).
Set `GCP_PROJECT`, `GCP_BUCKET` and `GCP_ZONE`. Choose a subnet that can reach
your destinations, and set these values to its VPC and regional subnet names:

```sh
export GCP_NETWORK=your-vpc
export GCP_SUBNET=your-subnet
export GCP_IMAGE="$VM-$ARCH-v1"
```

Use a new image and VM name for each deployment. For `aarch64`, choose a
zone supporting `t2a-standard-1`. Build a pristine disk without Lima's
network arguments, then package it for [manual import](https://docs.cloud.google.com/compute/docs/import/import-existing-image):

```sh
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

The imported image contains no credentials. Pass the config separately in
instance metadata. These [instance flags](https://docs.cloud.google.com/sdk/gcloud/reference/compute/instances/create)
give the VM no service account and disable Secure Boot, which Werewolf's
bootloader does not yet support:

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

Metadata is readable by operators with the corresponding instance
permissions. Restrict those permissions and protect `config.b64` like the
original secrets. Werewolf's metadata fetcher validates the tar and init
extracts it into root-only `/run/config`; leash gives each service only its
named copies. See [cloud configuration](cloud.md).

The commands assign an external IP for outbound HTTPS. Your VPC must allow
DNS and HTTPS. The service tutorial supplies any required inbound rule;
review existing VPC rules too, since an additional narrow rule does not
cancel a broader one. Inspect boot messages with:

```sh
gcloud --project="$GCP_PROJECT" compute instances get-serial-port-output \
  "$VM" --zone="$GCP_ZONE"
export VM_IP=$(gcloud --project="$GCP_PROJECT" compute instances describe \
  "$VM" --zone="$GCP_ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
```

## AWS VM

`werewolf create` makes the machine in the aws CLI's region (`aws
configure`, or `AWS_REGION` and `AWS_PROFILE`), in the default VPC:

```sh
build/host/werewolf create "$FORM" "$VM" --on aws --config "$CONFIG_DIR"
build/host/werewolf console "$VM" --on aws
build/host/werewolf delete "$VM" --on aws     # the instance, its volume and security group; the AMI stays
```

The first `create` of a build writes its disk straight into an EBS
snapshot through EBS's direct API, only the blocks that hold data, and
registers it as an AMI named `werewolf-FORM-ARCH-DIGEST` (UEFI, ENA,
IMDSv2 alone); later ones find the AMI. There is nothing to set up first:
no bucket and no VM Import role. The instance is a `t4g.small` (Graviton)
or a `t3.small` (`--size` picks another), with no instance profile, the
config tar in base64 as its user data, and the metadata service reachable
only from the machine itself (IMDSv2, one hop). Its security group,
`werewolf-NAME`, lets nothing in until you run the lines `create` prints
([above](#gcp-vm)).

AWS user data holds 16 KiB, so the tar's base64 must fit; `werewolf
pack --on aws` says whether it does. A second `create` of the same name
and form stops the instance, replaces its user data and starts it again,
with its volume and `/data` kept; its public address changes unless it
is an Elastic IP.

Whoever runs `create` needs EC2 (images, snapshots, instances, security
groups, subnets) and EBS's direct API for snapshots (`ebs:StartSnapshot`,
`ebs:PutSnapshotBlock`, `ebs:CompleteSnapshot`).

## Change boot configuration

In Lima, run the same `werewolf create` with the changed files or flags.
It checks the new config, stops the VM, replaces its config disk and
starts it again; the boot disk and `/data` stay, and with them a Tailscale
node's identity. The stop is a hard one, a power cut: Lima sends its
request to shut down only to a guest that answers ssh on Lima's network,
and a werewolf machine does not. On AWS, run the same `werewolf create`
too. For GCP, update the source files, regenerate the tar/base64 using the packing
commands above, then replace the metadata and reboot:

```sh
gcloud --project="$GCP_PROJECT" compute instances add-metadata "$VM" \
  --zone="$GCP_ZONE" --metadata-from-file="user-data=$SERVICE_BUILD/gcp/config.b64"
gcloud --project="$GCP_PROJECT" compute instances reset "$VM" --zone="$GCP_ZONE"
```

Reboot interrupts connections. Both update slots reread the same boot
configuration, so image rollback does not roll back routes, destinations
or credentials. Change permitted ports or service privileges by building
and deploying a new form. Preserve the Tailscale node's data across reboots.

## Clean up GCP

To remove the test deployment, delete the instance, image and upload.
Deleting the instance also deletes its auto-delete boot disk and data:

```sh
gcloud --project="$GCP_PROJECT" compute instances delete "$VM" --zone="$GCP_ZONE"
gcloud --project="$GCP_PROJECT" compute images delete "$GCP_IMAGE"
gcloud --project="$GCP_PROJECT" storage rm "gs://$GCP_BUCKET/$GCP_IMAGE.tar.gz"
```

The bucket and local credential files remain. The bastion tutorial also
removes its firewall rule; remove a retired Tailscale node from your tailnet.
