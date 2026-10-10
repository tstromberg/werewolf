# Mosquitto - Hardened VM

An MQTT broker for the devices on a network: [Mosquitto](https://mosquitto.org) 2.1. The form's manifest is [form.yaml](form.yaml).

## Security Posture

Mosquitto runs as its own user. There is no shell. Landlock and seccomp hold it to port 8883 and to `/data/svc/mosquitto`. The root is read-only.

- Nothing anonymous, and nothing plain. TLS is 1.2 at least.
- `$SYS` topics are off. A device that floods is held by the limits.
- A listener on 1883 is two lines in a form of your own, for a LAN that must have one.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
mkdir -p config/mosquitto
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
	-subj /CN=mqtt.home.arpa -keyout config/mosquitto/tls.key -out config/mosquitto/tls.crt
printf '%s\n' 'user sensor' 'topic write home/sensor/#' >config/mosquitto/acls
howl create mosquitto --with mosquitto --config config
```

`config/mosquitto/passwords` is what `mosquitto_passwd` writes, one user a line. Without it the broker stays down. Clients use `mqtts://ADDRESS:8883`. Topics and ACLs are in [Mosquitto's documentation](https://mosquitto.org/man/mosquitto-conf-5.html).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
mkdir -p config/mosquitto
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
	-subj /CN=mqtt.example.com -keyout config/mosquitto/tls.key -out config/mosquitto/tls.crt
printf '%s\n' 'user sensor' 'topic write home/sensor/#' >config/mosquitto/acls
howl create mosquitto --with mosquitto --on gcp --allow-from me --config config
```

`--allow-from me` admits your address to port 8883. Use a certificate clients already trust. The password file is the same one.

### Migrating data in

The broker starts empty. Clients publish to the address howl prints. Retained messages on the old broker stay there. There is no dump to copy in.

### Known Quirks

- Retained messages and queues are in `/data/svc/mosquitto`.
- There are no bridges.

### Network Exposure

tcp/8883
