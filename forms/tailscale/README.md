# Tailscale subnet router

Give allowed tailnet clients access to a subnet using [the Tailscale form](apko.yaml).
See its [security precautions](../../examples/tailscale/README.md#security-precautions).
The image supplies the network and service restrictions; boot configuration
supplies routes and enrollment credentials.

Run these commands from the repository root:

```sh
export FORM=tailscale VM=werewolf-router
export CONFIG_DIR="$PWD/config/router-vm"
umask 077
mkdir -p "$CONFIG_DIR/tailscale"
```

## Routes and enrollment

Create `$CONFIG_DIR/tailscale/settings.json`:

```json
{"routes": ["10.20.0.0/24"]}
```

Use a subnet reachable from the VM: your LAN for Lima, or your VPC for GCP.
For a meaningful routing test, use a client outside that subnet. Empty
`routes` advertises nothing. The renderer accepts up to 32 IPv4/IPv6 network
CIDRs, rejects host bits and default routes, and rejects all other fields.
It merges only `advertiseRoutes` into the image's Tailscale configuration.
Boot settings cannot enable SSH, alter the auth-key source or change the
service's privileges or ports. Omitted routes retain the image's empty list.

In your tailnet policy, define a router tag and a narrow grant. For example:

```json
{
  "tagOwners": {"tag:subnet-router": ["autogroup:admin"]},
  "grants": [{
    "src": ["you@example.com"],
    "dst": ["10.20.0.0/24"],
    "ip": ["tcp:22", "tcp:443"]
  }]
}
```

Use your own identity/subnet and merge carefully with your existing policy.
Grants are additive; review any existing allow-all rule. Create a tagged,
preauthorized, non-ephemeral [auth key](https://tailscale.com/docs/features/access-control/auth-keys)
for `tag:subnet-router`. Use a single-use key for one VM. Paste it into
`$CONFIG_DIR/tailscale/auth_key` with your editor, then:

```sh
chmod 600 "$CONFIG_DIR/tailscale/auth_key"
```

Use a fresh key for a second VM, including when moving from Lima to GCP.
Leash supplies a private copy to the daemon. The key is required at service
start; preserve the file even after enrollment. Persist `/data`: the node
identity is in `/data/svc/tailscale`. Never clone that identity to another
router. Auth-key expiration does not itself revoke an enrolled node.

## Local Lima

Follow [the Lima steps](../../docs/service-vms.md#local-lima-vm). Your settings and auth
key travel on the VM's config disk. After the router appears in the
Tailscale admin console, approve its advertised subnet. Route approval and
client grants are separate requirements.

On a Linux client, enable route acceptance:

```sh
sudo tailscale set --accept-routes=true
```

From an allowed tailnet client outside the subnet, test a real destination:

```sh
ssh destination-user@10.20.0.10
curl -f https://YOUR_SUBNET_HTTPS_HOST/health
```

Use a hostname resolving to the advertised subnet and its valid TLS
certificate. Confirm that a client without a grant cannot connect. Use the
admin console and boot log to check the router; it has no login SSH server.
See [Tailscale's subnet-router setup](https://tailscale.com/docs/features/subnet-routers).

## GCP

Follow [the GCP steps](../../docs/service-vms.md#gcp-vm) with a fresh auth key. They send
these same files as a base64 config tar in instance metadata. Advertise the
selected VPC subnet and approve this new node's routes in the tailnet.

No public inbound firewall rule is needed. Permit outbound DNS/HTTPS, and
allow the subnet destination's application ports from the router's internal
IP. Repeat the client tests above. Destinations see the router's address
because userspace networking proxies the connections.

The initial policy permits TCP 22 and 443, plus DNS. Direct UDP transport
is blocked, so tailnet connections use DERP relays over HTTPS. This form is
not a general UDP/ICMP router. To add a TCP application port, use a
descendant form and add it to both the service's `connect` directive and
`connect tailscale tcp/PORT` in its `.net` file. Host policy limits ports;
tailnet grants limit clients and subnet destinations.

## Configuration and updates

Declare routes in the source settings file and refresh the boot config
using [these instructions](../../docs/service-vms.md#change-boot-configuration). The generated
runtime configuration is replaced on every start.

Werewolf updates Tailscale with the image; Tailscale's own updater is
disabled. Native A/B updates keep the node's data and reread boot settings.
Policy/port changes need a new image. Both slots share data; rollback does
not undo routes or credentials supplied at boot. The image uses Tailscale's
`alpha0` configuration schema; check [schema changes](https://tailscale.com/docs/reference/tailscaled/tailscaled-config-file)
when upgrading. Remove retired test nodes from the tailnet after deleting
their VMs.
