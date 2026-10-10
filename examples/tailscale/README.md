# Tailscale subnet router on Werewolf

The [tailscale form](../../forms/tailscale/form.yaml) gives permitted tailnet
clients access to machines in an advertised subnet. It runs Tailscale's
userspace network stack as `tailscale` (uid/gid 206).

## Security precautions

- The daemon has no capabilities, TUN device or permission to change the
  host firewall. Landlock confines writes to its own service directories,
  and seccomp limits its system calls.
- The base configuration advertises no routes. You must declare the subnet,
  approve it in the tailnet and grant clients access to its addresses and
  ports. Existing broad grants still apply: grants are additive.
- The initial host policy allows TCP 22 and 443, plus DNS. It limits the
  service user and ports, not destination CIDRs; the tailnet supplies client
  access controls.
- The transport uses DERP relays over HTTPS. The host policy grants no
  public listener or arbitrary UDP egress. This trades direct-path
  performance for fewer permitted network operations.
- Tailscale SSH and the web client are disabled. The configuration is
  locked, and the daemon does not accept other routers' routes or tailnet
  DNS settings.
- Enrollment uses a private auth-key file supplied outside the image.
  Leash copies only that file to `/run/svc/tailscale/auth-key`, mode `0600`.
  Persist the node identity in `/data/svc/tailscale`; never clone it into
  another router.

The inherited `prod` image has a verified, read-only root. Build without
`DEV=1`. Tailscale's own updater is disabled; Werewolf updates the package
with the image. Userspace forwarding makes destinations see the router's
address. This form supports the declared application ports, rather than
general-purpose UDP or ICMP routing.

## Basic usage

Start with [routes and enrollment](../../forms/tailscale/README.md#routes-and-enrollment),
then follow either [local Lima](../../forms/tailscale/README.md#local-lima) or
[GCP](../../forms/tailscale/README.md#gcp). Both use `tailscale/settings.json` and a
private `auth-key` file. Lima carries them as NoCloud data files; GCP carries
them in a base64 config tar.

The tutorial includes a narrow tailnet grant, route approval, client tests,
updates and cleanup. Use a new single-use enrollment key for each VM.
