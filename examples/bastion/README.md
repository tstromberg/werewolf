# SSH bastion on Werewolf

The [bastion form](../../forms/bastion/apko.yaml) runs a forwarding-only OpenSSH
server. Clients authenticate to the bastion, then forward TCP connections
to explicitly permitted destinations. The destination authenticates them
separately.

## Security precautions

- OpenSSH runs as `bastion` (uid/gid 205). Its only capability is binding
  a privileged port. Landlock confines writes to its own service directories,
  and seccomp limits the calls it can make.
- Only public-key authentication is enabled. The form disables shell and
  command sessions, SFTP, PTYs, remote forwarding, agent forwarding,
  Unix-socket forwarding and tunnels.
- Hybrid post-quantum key exchange is required. Host and user signatures
  remain Ed25519. Each connection through `ProxyJump` negotiates separately;
  the destination needs its own post-quantum policy.
- `PermitOpen` defaults to `none`. Restricted boot settings supply exact
  destination addresses and ports. The kernel separately limits outgoing
  TCP ports; it does not restrict destination IPs.
- The host key is made on the VM's first boot and kept in `/data`; its
  private half never leaves the VM, and its fingerprint is on the console
  at every boot. Authorized keys travel outside the image: leash copies
  only that named file into its private directory under `/run/svc`, owned
  by `bastion`, mode `0600`. Missing keys keep SSH down.

The inherited `prod` image has a verified, read-only root. Build without
`DEV=1` to keep debug tools out of the deployment. Verify the host-key
fingerprint before connecting, and restrict the cloud firewall to your
clients. See [OpenSSH's post-quantum explanation](https://www.openssh.org/pq.html).

## Basic usage

Start with [destinations and keys](../../forms/bastion/README.md#destinations-and-keys),
then follow either [local Lima](../../forms/bastion/README.md#local-lima) or
[GCP](../../forms/bastion/README.md#gcp). Both use `bastion/settings.json` and
`authorized_keys` supplied outside the image, in a config tar: a disk under
Lima, user-data on GCP.

The tutorial includes pinned host-key verification, a forwarding example,
firewall setup, updates and cleanup.
