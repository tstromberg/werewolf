# Home Assistant - Hardened VM

A home's devices and automations: [Home Assistant](https://www.home-assistant.io),
the stable image, behind Caddy. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/home-assistant/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names.
  The root is read-only. `/data` is what survives.
- HTTP's stable configuration is set at each start: loopback behind Caddy, without
  a pending trial that would revert after five minutes without UI confirmation.
- mDNS (UDP/5353) discovers devices on the LAN. Fence limits discovery to
  directly connected subnets and the standard mDNS multicast group;
  off-subnet unicast to those listeners is dropped, including forged replies.

- The image contains Python. Only `python3 -m homeassistant` is started. Integrations
  you add later run as that same user.

- `kernel-write-xor-execute`: Python's `ctypes` needs libffi's native callback
  trampolines at startup, so the form permits `jit`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >owner-password
howl create home-assistant --with home-assistant \
	--domain home.home.arpa --owner me --owner-password owner-password \
	--time-zone America/New_York --country US
```

Open `https://home.home.arpa` and sign in as `me`. The password is in
`owner-password`, 12 to 72 bytes. Names under `.home.arpa` get a certificate from
Caddy's own CA. Integrations are in [Home Assistant's
documentation](https://www.home-assistant.io/docs/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >owner-password
howl create home-assistant --with home-assistant --on gcp --allow-from me \
	--domain home.example.com --owner me --owner-password owner-password \
	--time-zone Europe/Berlin --country DE
```

Sign in at `https://home.example.com`. A public name gets a certificate from Let's
Encrypt. A house more often runs on Proxmox. Omit `--domain` there and Caddy serves
plain HTTP on port 80, which is reasonable only on a LAN:

```text
howl create home-assistant --with home-assistant --on proxmox \
	--allow-from 192.168.0.0/16 --owner me \
	--owner-password owner-password --time-zone Europe/Berlin --country DE
```

The owner's password is set back to the file at each start.

### LAN discovery

Use a multicast-capable kernel (kernel policy revision 4 enables reception).
Attach the VM to the same LAN as its devices with a bridge or equivalent network
that carries multicast. QEMU's user networking, Firecracker's usual NAT, and Lima's
shared networking do not by themselves provide access to the home's multicast.
Forwarding UDP/5353 through NAT is not a substitute for a LAN attachment.

Discovery uses Home Assistant's Network settings to select interfaces. Firewall
LAN subnets are fixed at boot; changing the VM's address plan requires a reboot.
A cloud VM discovers devices on its attached network, not your home's network.
Do not forward these discovery ports from an Internet router.

### Importing data

Home Assistant keeps its state in `/data`, and the host cannot write that directory.
Restore a backup from the web UI after this machine is up.

### Known Quirks

- Onboarding is already finished. The first visitor is not offered the setup.
- mDNS discovery is enabled. SSDP stays off: upstream starts an additional HTTP
  server on a random port. DHCP packet sniffing, Bluetooth and USB remain off;
  the service has no raw packet or device access. A network Zigbee
  coordinator can be reached through MQTT.
- Location starts as the settings you passed. Change it later under Settings, System,
  General.
- The image is large. Give the machine 4 GB.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
- listen: udp/5353 LAN (mDNS)
