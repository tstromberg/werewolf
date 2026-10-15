# OpenBao - Hardened VM

[OpenBao](https://openbao.org) stores secrets. You bring the TLS certificate, the unseal
key, and an admin password. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/openbao/index.html).

## Security Posture

- OpenBao runs as its own user. The root is read-only. Secrets live on `/data`.
- The unseal key, the certificate, and the admin password are files you pass in. They
  are not in the image.
- The API listens on the address you name. There is no shell.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
mkdir -p config/openbao
openssl rand -out config/openbao/unseal-key 32
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
	-subj /CN=bao.home.arpa -addext subjectAltName=DNS:bao.home.arpa \
	-keyout config/openbao/tls.key -out config/openbao/tls.crt
printf '%s' 'a long admin password' >config/openbao/admin-password
howl create openbao --with openbao --config config --api-addr https://bao.home.arpa:8200
```

Initialize and unseal at `https://bao.home.arpa:8200`. The first steps are in [OpenBao's
documentation](https://openbao.org/docs/concepts/seal/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
mkdir -p config/openbao
openssl rand -out config/openbao/unseal-key 32
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
	-subj /CN=bao.example.com -addext subjectAltName=DNS:bao.example.com \
	-keyout config/openbao/tls.key -out config/openbao/tls.crt
printf '%s' 'a long admin password' >config/openbao/admin-password
howl create openbao --with openbao --on gcp --allow-from me --config config \
	--api-addr https://bao.example.com:8200
```

`--allow-from me` admits your address to port 8200. Use a certificate for the name
clients will use.

### Importing data

There is no database import. Initialize this server, then unseal it with the key file. A
second create keeps the data disk and refuses a new import.

### Known Quirks

- The unseal key is 32 bytes. The admin password file has no newline.
- The certificate's name must match `--api-addr`.

### Network Exposure

- listen: tcp/8200 *
