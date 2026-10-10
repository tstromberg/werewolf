# Home Assistant

A home's devices and automations: [Home Assistant](https://www.home-assistant.io), the stable image, behind Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
printf %s 'a long owner password' >owner-password
howl create home --with home-assistant --on lima \
	--domain home.home.arpa --owner me --owner-password owner-password \
	--time-zone America/New_York --country US
```

Open `https://home.home.arpa` and sign in as `me`. Names under `.home.arpa` get a certificate from Caddy's own CA. The password must be 12 to 72 bytes.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
printf %s 'a long owner password' >owner-password
howl create home --with home-assistant --on proxmox \
	--domain home.example.com --owner me --owner-password owner-password \
	--time-zone Europe/Berlin --country DE
```

A public name gets a certificate from Let's Encrypt. Omit `--domain` and Caddy serves plain HTTP on port 80, which is reasonable only on a LAN or a tailnet. The owner's password is set back to the file at each start, so a forgotten one is recovered by editing that file and restarting.

### Known Quirks

- Onboarding is already finished. The first visitor is not offered the setup.
- Discovery, Bluetooth and USB are off. A Zigbee coordinator is reached over the network, through MQTT, not a dongle.
- Location starts as the settings you passed. Change it later under Settings, System, General.
- The image is large. Give the machine 4 GB.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Home Assistant is on loopback, and may call devices on the ports its integrations use, and the public internet on 80 and 443.

### Security Weaknesses

- The image contains Python. Only `python3 -m homeassistant` is started. Integrations you add later run as that same user.
