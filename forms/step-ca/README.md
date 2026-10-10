# step-ca

The `step-ca` form is `prod` with step-ca 0.30, an internal certificate
authority, named for what runs, as `postgresql` is.

| | |
| --- | --- |
| Listens | tcp/443: ACME, and the CA's API |
| Sends | to a requester's tcp/80, ACME's http-01, and DNS to find it (`connect step tcp/80 tcp/53 udp/53`) |
| Runs as | `step` (a uid of its own, its name's hash), leashed |
| Keeps | its database (badger) in `/data/svc/step-ca/db` |
| Config | `step-ca/root.crt`, `step-ca/intermediate.crt`, `step-ca/intermediate.key` (encrypted), `step-ca/password` (the key's); settings `names` (the CA's own, required) and `domains` (what ACME may issue for, required) |

The root's key never comes to the machine: make the root and the
intermediate where the root's key lives (`step certificate create`, or
openssl as [forms/step-ca/test/config](test/config) does), and give
the machine the intermediate alone.

```sh
build/host/howl pack --with step-ca -o config.tar --config config \
	--names ca.example.internal --domains example.internal,app.example.internal
```

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create step-ca --with step-ca --config config \
	--names ca.home.arpa --domains home.arpa
```

`config/step-ca` holds `root.crt`, `intermediate.crt`, `intermediate.key` and `password`. Make them where the root key lives. That key never comes to the machine. ACME is on port 443.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create step-ca --with step-ca --on gcp --allow-from me --config config \
	--names ca.example.com --domains example.com
```

`--allow-from me` admits your address to port 443. `--domains` is what ACME may issue for, up to 32 names.

### Migrating data in

Issued certificates stay on the old server. This machine starts its own CA. There is no database to import.

### Network Exposure

tcp/443


## Defaults

- **One provisioner, ACME**, which is most of why people run one, with
  `http-01`, `tls-alpn-01` and `dns-01`. It is bound by an x509 policy
  that allows only the `domains` listed, and the service parks without
  them. The policy holds for every provisioner.
- **No remote administration** (`enableAdmin` off): `ca.json` in the
  image is the only way to change provisioners. A form of your own lays
  its `etc/step-ca/ca.json` over this one to add a JWK provisioner for
  its operators (its public key is not a secret, so it belongs in the
  image, not the config).
- **Certificates live 24 hours**, as step-ca ships; a provisioner's
  claims raise it for clients that cannot renew daily.
- TLS 1.2 at least, ECDSA suites with AEAD, no renegotiation.

## Checked

`make check-step-ca` makes a root and an intermediate for the run
([forms/step-ca/test/config](test/config)), names the CA `localhost`
and allows `example.test`, and runs [forms/step-ca/test/checks](test/checks):
`/health` and `/roots` answer over TLS; the ACME directory is served; the
rendered `ca.json` holds exactly those names and `enableAdmin: false`;
the admin API is refused; the root's key is nowhere on the machine; and
the intermediate's key and password are `step`'s, 0600.
