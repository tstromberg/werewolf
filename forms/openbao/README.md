# OpenBao

The `openbao` form is `prod` with OpenBao 2.5, secrets on a machine where
root cannot read another process's memory. Vault is not planned: Wolfi's
`vault` is 1.14, the last MPL release; OpenBao is its API-compatible fork.

| | |
| --- | --- |
| Listens | tcp/8200, TLS, every address: the API and the UI. raft's cluster port, 8201, on loopback alone |
| Sends | nothing: the seal is a key on the machine. A cloud KMS is a form of your own, with `connect openbao tcp/443` and `metadata openbao` |
| Runs as | `openbao` (a uid of its own, its name's hash), leashed |
| Keeps | integrated storage (raft) in `/data/svc/openbao` |
| Config | `openbao/unseal-key` (32 random bytes), `openbao/tls.crt` and `tls.key`, `openbao/admin-password` (the admin's first); settings `api-addr` (required) and `unseal-key-id` |

```sh
umask 077; mkdir -p config/openbao
openssl rand -out config/openbao/unseal-key 32
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
	-subj /CN=bao.example.com -addext subjectAltName=DNS:bao.example.com \
	-keyout config/openbao/tls.key -out config/openbao/tls.crt
printf '%s' 'the admin password' >config/openbao/admin-password      # no newline: it is the password
build/host/howl pack --with openbao -o config.tar --config config --api-addr https://bao.example.com:8200
```

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

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

Open `https://bao.home.arpa:8200` and sign in as `admin`. The password file has no newline. The unseal key is 32 random bytes. Keep both.

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

`--allow-from me` admits your address to port 8200. Use a certificate clients already trust. Change the admin password at the first login.

### Migrating data in

This machine starts empty. Initialize and unseal it as its own setup describes. There is no database to import.

### Network Exposure

tcp/8200


## Unsealed by a key, set up by itself

werewolf reboots itself into every update; with Shamir shares, every
update would leave the secrets sealed until enough operators came back.
So the seal is `static`, the key in the config (`seal "static"`), and
OpenBao's `initialize` stanza, in the image (`etc/openbao/openbao.hcl`),
does on the first start what `bao operator init` and the first logins
would:

1. an `admin` ACL policy with every capability, the `userpass` method,
   and a user `admin` whose password is the config's file, read by the
   stanza's `file` source. Change it at the first login (`bao write
   auth/userpass/users/admin password=...`); a bcrypt hash in the config
   instead (`password_hash`) waits on an OpenBao after 2.5, which Wolfi
   ships;
2. then the root token is revoked. No recovery keys are made; the
   authenticated rotation endpoints replace them.

The `stdout` audit device, every request a line on the console, is an
`audit` stanza in the same file, not an `initialize` request, which
`sys/audit` refuses during self-initialization. Declared in the image, it
cannot be disabled over the API.

The cost is that whoever holds the config tar can unseal the data, the
same trust the tar already carries for `data.key`. Rotating the key is
`previous_key` beside `current_key` in a form of your own; the id in
`unseal-key-id` names which key encrypted storage. A form that wants a
person at every unseal uses Shamir, without `initialize`, and unseals
after each boot.

## Defaults

- The listener's TLS from the config, `tls_min_version` 1.2, and OpenBao's
  ciphers.
- The UI on: a client of the same API, behind the same TLS.
- `raw_storage_endpoint`, `introspection_endpoint` and
  `unauthenticated_metrics_access` off, as they ship, and said so in the
  file. No `plugin_directory`, and no `exec` promise: nothing here starts
  a program.
- Lease lifetimes as OpenBao ships them.
- No `disable_mlock`: OpenBao 2.5 has no such field and locks no memory;
  werewolf has no swap.
- Clustering adds `listen tcp/8201` and peers in the configuration, a
  form of your own.

## Checked

`make check-openbao` makes a key, a certificate for `localhost` and the
hash of `werewolf-check` ([forms/openbao/test/config](test/config))
and runs [forms/openbao/test/checks](test/checks): `sys/health`
says initialized and unsealed; plain HTTP is refused; the admin logs in
with that password and a wrong one is refused; the admin's token lists the
`stdout/` audit device and finds `sys/raw` gone; the cluster port is on
`127.0.0.1` alone; and the key, password and TLS key are `openbao`'s, 0600.
