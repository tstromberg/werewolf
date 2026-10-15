# step-ca - Hardened VM

[step-ca](https://smallstep.com/docs/step-ca/) is a private certificate authority. You bring the root and the intermediate. The root key stays off the machine. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/step-ca/index.html).

## Security Posture

- step-ca runs as its own user. The root is read-only.
- The intermediate key and its password are files you pass in. The root key is not on the machine.
- Issued certificates are the CA's. This form does not copy another CA's database.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create step-ca --with step-ca --config config \
	--names ca.home.arpa --domains home.arpa
```

`config/step-ca` holds `root.crt`, `intermediate.crt`, `intermediate.key`, and `password`. Clients trust `root.crt`. Issuing a certificate is in [step-ca's documentation](https://smallstep.com/docs/step-ca/certificate-authority-server-production/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create step-ca --with step-ca --on gcp --allow-from me --config config \
	--names ca.example.com --domains example.com
```

`--allow-from me` admits your address to port 443. `--names` is the CA's name. `--domains` are the names it may issue.

### Importing data

Issued certificates stay on the old server. This machine starts its own CA from the files in `--config`.

### Known Quirks

- The password file unlocks `intermediate.key`. It is not the root's password.
- A name outside `--domains` is refused.

### Network Exposure

- listen: tcp/443 *
