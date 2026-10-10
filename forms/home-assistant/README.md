# Home Assistant

A home's devices and automations: [Home Assistant](https://www.home-assistant.io), the stable image, behind Caddy. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- The image contains Python. Only `python3 -m homeassistant` is started. Integrations you add later run as that same user.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >owner-password
howl create home-assistant --with home-assistant \
	--domain home.home.arpa --owner me --owner-password owner-password \
	--time-zone America/New_York --country US
```

Open `https://home.home.arpa` and sign in as `me`. The password is in `owner-password`, 12 to 72 bytes. Names under `.home.arpa` get a certificate from Caddy's own CA. Integrations are in [Home Assistant's documentation](https://www.home-assistant.io/docs/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >owner-password
howl create home-assistant --with home-assistant --on gcp --allow-from me \
	--domain home.example.com --owner me --owner-password owner-password \
	--time-zone Europe/Berlin --country DE
```

Sign in at `https://home.example.com`. A public name gets a certificate from Let's Encrypt. A house more often runs on Proxmox. Omit `--domain` there and Caddy serves plain HTTP on port 80, which is reasonable only on a LAN:

```text
howl create home-assistant --with home-assistant --on proxmox \
	--allow-from 192.168.0.0/16 --owner me \
	--owner-password owner-password --time-zone Europe/Berlin --country DE
```

The owner's password is set back to the file at each start.

### Migrating data in

Home Assistant keeps its state in `/data`, and the host cannot write that directory. Restore a backup from the web UI after this machine is up.

### Known Quirks

- Onboarding is already finished. The first visitor is not offered the setup.
- Discovery, Bluetooth and USB are off. A Zigbee coordinator is reached over the network, through MQTT, not a dongle.
- Location starts as the settings you passed. Change it later under Settings, System, General.
- The image is large. Give the machine 4 GB.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Home Assistant is on loopback, and may call devices on the ports its integrations use, and the public internet on 80 and 443.
