# OpenBao

The `openbao` form is `prod` with OpenBao 2.5, secrets on a machine where
root cannot read another process's memory. Vault is not planned: Wolfi's
`vault` is 1.14, the last MPL release; OpenBao is its API-compatible fork.

| | |
| --- | --- |
| Listens | tcp/8200, TLS, every address: the API and the UI. raft's cluster port, 8201, on loopback alone |
| Sends | nothing: the seal is a key on the machine. A cloud KMS is a form of your own, with `connect openbao tcp/443` and `metadata openbao` |
| Runs as | `openbao` (uid 208), leashed |
| Keeps | integrated storage (raft) in `/data/svc/openbao` |
| Config | `openbao/unseal.key` (32 random bytes), `openbao/tls.crt` and `tls.key`, `openbao/admin_password` (the admin's first); settings `api-addr` (required) and `unseal-key-id` |

```sh
umask 077; mkdir -p config/openbao
openssl rand -out config/openbao/unseal.key 32
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
	-subj /CN=bao.example.com -addext subjectAltName=DNS:bao.example.com \
	-keyout config/openbao/tls.key -out config/openbao/tls.crt
printf '%s' 'the admin password' >config/openbao/admin_password      # no newline: it is the password
build/host/howl pack openbao -o config.tar --config config --api-addr https://bao.example.com:8200
```

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
`audit` stanza in the same file: declared in the image, it cannot be
disabled over the API.

The cost is that whoever holds the config tar can unseal the data, the
same trust the tar already carries for `data.key`. Rotating the key is
`previous_key` beside `current_key` in a form of your own; the id in
`unseal-key-id` names which key encrypted storage.

## Defaults

- The listener's TLS from the config, `tls_min_version` 1.2, and OpenBao's
  ciphers.
- The UI on: a client of the same API, behind the same TLS.
- `raw_storage_endpoint`, `introspection_endpoint` and
  `unauthenticated_metrics_access` off, as they ship, and said so in the
  file. No `plugin_directory`, and no `exec` promise: nothing here starts
  a program.
- Lease lifetimes as OpenBao ships them.
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
