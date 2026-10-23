# Pi-hole - Hardened VM

DNS for a home network that answers ad and tracker names with `0.0.0.0`:
[Pi-hole](https://pi-hole.net), from its own image, the web interface behind Caddy. The
form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/pi-hole/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names. The
  root is read-only. `/data` is what survives.

- Refreshing the lists runs bash, curl and coreutils from the image, as the Pi-hole
  user. pihole-FTL itself is one program. The host image has no shell.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/pi-hole
openssl rand -base64 18 >config/pi-hole/password
howl create pi-hole --with pi-hole --config config \
	--domain dns.home.arpa
```

Open `https://dns.home.arpa/admin/` and sign in with the password in
`config/pi-hole/password`. Point the name at the address howl prints, then point one
device at the machine for DNS. Lists and local names are in [Pi-hole's
documentation](https://docs.pi-hole.net/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/pi-hole
openssl rand -base64 18 >config/pi-hole/password
howl create pi-hole --with pi-hole --on gcp --allow-from me \
	--config config --domain dns.example.com
```

Sign in at `https://dns.example.com/admin/`. A house more often runs on Proxmox. Keep
port 53 on that network:

```text
howl create pi-hole --with pi-hole --on proxmox \
	--allow-from 192.168.0.0/16 --config config \
	--domain dns.home.arpa
```

Upstreams and lists are changed in the web interface and kept on `/data`. The password
comes from the config. Fence admits DNS clients only from connected subnets;
dnsmasq binds the machine's network interface and leaves unwound's loopback
address free.

### Importing data

This machine starts empty. What it must remember is in the create command or `--config`.
Gravity's lists are fetched after it is up. There is no database to copy in.

### Known Quirks

- Quad9 (9.9.9.9 and 149.112.112.112) and Steven Black's list are set on the first
  start.
- Lists refresh when the machine starts, if they are missing or older than a week. A
  failed fetch keeps the old lists.
- The web interface's Update Gravity button does not work. Restart with `sv restart
  pi-hole`, or wait for the next boot.
- DHCP and NTP are off.
- Shared memory lives on `/data`, because an image service has no tmpfs of its own.

### Network Exposure

- listen: udp/53 *
- listen: tcp/53 *
- listen: tcp/80 *
- listen: tcp/443 *
