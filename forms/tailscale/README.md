# Tailscale - Hardened VM

A [Tailscale](https://tailscale.com) subnet router. The image supplies the service. Boot configuration supplies the routes and the auth key. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/tailscale/index.html).

## Security Posture

- tailscaled runs as its own user. The root is read-only. State is on `/data`.
- The auth key is a file you pass in. It is not in the image.
- The router connects out. It does not listen for the public internet.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
mkdir -p config/tailscale
printf '%s\n' '{"routes":["10.20.0.0/24"]}' >config/tailscale/settings.json
printf '%s' 'tskey-auth-REPLACE' >config/tailscale/auth-key
howl create tailscale --with tailscale --config config
```

Replace `tskey-auth-REPLACE` with a tagged, preauthorized, single-use key before you create the machine. Approve the advertised subnet in the admin console. Routes and grants are in [Tailscale's documentation](https://tailscale.com/kb/1019/subnets).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
mkdir -p config/tailscale
printf '%s\n' '{"routes":["10.128.0.0/20"]}' >config/tailscale/settings.json
printf '%s' 'tskey-auth-REPLACE' >config/tailscale/auth-key
howl create tailscale --with tailscale --on gcp --allow-from me --config config
```

`--allow-from` opens no port. Use a fresh key, and a subnet of the VPC.

### Importing data

The tailnet already has its nodes. This machine starts empty and joins with the auth key. There is no database to import.

### Known Quirks

- `routes` is a list of CIDRs in `settings.json`. The key file has no newline.
- A key that has been used will not enroll a second machine.

### Network Exposure

- connect: tcp/443 global
