# SSH bastion

Run a forwarding-only SSH service with [the bastion form](apko.yaml).
See its [security precautions](../../examples/bastion/README.md#security-precautions).
The image supplies the service restrictions; boot configuration supplies each
VM's destinations and keys.

Run these commands from the repository root:

```sh
export FORM=bastion VM=werewolf-bastion
export CONFIG_DIR="$PWD/config/bastion-vm"
umask 077
mkdir -p "$CONFIG_DIR/bastion"
```

## Destinations and keys

Create `$CONFIG_DIR/bastion/settings.json`:

```json
{"destinations": ["10.20.0.10:22", "10.20.0.11:22"]}
```

Replace those addresses with machines reachable from the VM: your LAN for
Lima, or your VPC for GCP. Clients must request exactly those addresses.
Empty `destinations` denies all forwarding. The renderer accepts at most
32 literal IP:port pairs, including bracketed IPv6; it rejects hostnames,
wildcards, extra fields and injected SSH directives.

Copy the public key of a permitted client:

```sh
cp ~/.ssh/id_ed25519.pub "$CONFIG_DIR/bastion/authorized_keys"
chmod 600 "$CONFIG_DIR/bastion/authorized_keys"
```

Use your own public-key path. The bastion makes its own host key on its
first boot, as a distribution does, keeps it in `/data`, and logs its
fingerprint and public half on the console at every boot; the private
half never leaves the VM. Without `/data` it stays down rather than take
a new identity at each boot. Keys and `settings.json` stay out of the
image. Leash makes private copies, then the
unprivileged renderer writes only the declared `PermitOpen` directive.
Missing credentials or invalid settings keep the service down. Omitted
destinations leave the image's `PermitOpen none` default in force.

The base form's outgoing TCP policy permits port 22. For another port,
create a descendant form, copy its service file and add the port to
`connect`; add `connect bastion tcp/PORT` to the descendant's `.net` file.
Boot settings cannot grant a port the image denies.

## Local Lima

Follow [the Lima steps](../../docs/service-vms.md#local-lima-vm) with the variables above.
`howl create` builds a boot disk, attaches your files as a config disk
and sets `VM_IP`. Pin the host key the VM logged, then forward a port:

```sh
build/host/howl console "$VM" |
  sed -n 's/^ssh-host-key: .*"public":"\([^"]*\)".*/\1/p' | tail -n 1 |
  awk -v host="$VM" '{ print host " " $0 }' >"$SERVICE_BUILD/known_hosts"
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes \
  -o HostKeyAlias="$VM" -o UserKnownHostsFile="$SERVICE_BUILD/known_hosts" \
  -o StrictHostKeyChecking=yes -N \
  -L 127.0.0.1:2200:10.20.0.10:22 "bastion@$VM_IP"
```

In another terminal, authenticate to the destination with its own user/key:

```sh
ssh -p 2200 -o HostKeyAlias=10.20.0.10 destination-user@127.0.0.1
```

Verify the destination's host fingerprint independently. A command such as
`ssh bastion@VM_IP true` should be refused; forwarding uses `-N` and opens
no session. Stop the forwarding client with Ctrl-C.

## GCP

Follow [the GCP steps](../../docs/service-vms.md#gcp-vm). They pass the same config files
as a base64 tar in instance `user-data` metadata. Give the VM a reachable VPC
subnet, and allow the destination's TCP 22 from the bastion's internal IP.
For access to the bastion itself, restrict the source CIDR:

```sh
export GCP_SOURCE_RANGES=203.0.113.4/32  # replace with your public IP/CIDR
gcloud --project="$GCP_PROJECT" compute firewall-rules create "$VM-ssh" \
  --network="$GCP_NETWORK" --allow=tcp:22 \
  --source-ranges="$GCP_SOURCE_RANGES" --target-tags="$VM"
```

Pin the host key and forward as for Lima, reading the console with
`howl console "$VM" --on gcp` and using the GCP `VM_IP`. Review
existing VPC rules: this narrow rule does not cancel broader access.
After removing the test VM, remove its rule too:

```sh
gcloud --project="$GCP_PROJECT" compute firewall-rules delete "$VM-ssh"
```

## Configuration and updates

The form declares the VM's privileges; boot settings declare its permitted
forwarding destinations. Change the source settings, then restart with the
updated boot config using [these instructions](../../docs/service-vms.md#change-boot-configuration).
Never edit the generated runtime file.

On a native A/B installation, Werewolf updates packages and the kernel,
keeping the verified policy and rereading boot configuration. Changing the
service or its permitted ports needs a new image. Both slots share data;
rollback does not undo boot-config changes. See [updater.md](../../docs/updater.md).

Hybrid post-quantum key exchange is required. Host/user signatures remain
Ed25519. A `ProxyJump` destination negotiates its own exchange; apply the
same requirement there if needed. See [OpenSSH's explanation](https://www.openssh.org/pq.html).
