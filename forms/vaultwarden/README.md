# Vaultwarden - Hardened VM

[Vaultwarden](https://github.com/dani-garcia/vaultwarden) is the Bitwarden-compatible
server. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/vaultwarden/index.html).

## Security Posture

- Vaultwarden runs as its own user. The root is read-only. The vault is on `/data`.
- The admin token is a file you pass in. It is an Argon2id PHC string, not the
  password itself.
- Signups follow the server's config. The domain is the one clients will use.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/vaultwarden
howl create vaultwarden --with vaultwarden --config config \
	--domain https://vault.home.arpa
```

Put the admin token in `config/vaultwarden/admin-token`. Make it with `vaultwarden
hash`. Open `https://vault.home.arpa`. Clients are in [Vaultwarden's
documentation](https://github.com/dani-garcia/vaultwarden/wiki).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/vaultwarden
howl create vaultwarden --with vaultwarden --on gcp --allow-from me --config config \
	--domain https://vault.example.com
```

`--allow-from me` admits your address to port 8080. Point the name at the machine.

### Importing data

Export the old vault as JSON and import it in the web vault after this one is up.
There is no database import.

### Known Quirks

- `--domain` is the public URL, with the scheme. Clients reject a mismatch.
- The admin token file is the PHC string from `vaultwarden hash`, not a plaintext
  password.

### Network Exposure

- listen: tcp/8080 *
