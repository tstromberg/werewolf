# Velociraptor - Hardened VM

Endpoint visibility: the [Velociraptor](https://docs.velociraptor.app/) server, 0.77,
behind Caddy. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/velociraptor/index.html).

## Security Posture

- The server runs as its own user. The keys are generated on the machine, into `/data`,
  the first time it starts, and are not in the image.
- The administrator is `admin`. The password is the config's, applied at every start,
  and is not written into the server config.
- The GUI, the API and monitoring listen on loopback. Clients use mutual TLS on :8000.
- The only program the server may run is itself.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create velociraptor --with velociraptor \
	--domain vr.home.arpa --admin-password admin-password
```

Open `https://vr.home.arpa` and sign in as `admin`. The password is in `admin-password`.
Give the machine 2 GB. Client installers are in the GUI, and in [Velociraptor's
documentation](https://docs.velociraptor.app/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create velociraptor --with velociraptor --on gcp --allow-from me \
	--domain vr.example.com --admin-password admin-password
```

Clients need a name that resolves to this machine and is the `--domain`, because it is
the name on the server's certificate. Open :8000 to them. The GUI stays on HTTPS at the
domain.

### Importing data

A server's datastore and filestore are directories under `/data/svc/velociraptor`. This
form does not import them. A new machine generates new keys; existing clients trust the
old ones.

### Known Quirks

- No client packages are built at boot. Download a client config from the GUI.
- The GUI's own TLS is not the certificate Caddy shows. Caddy talks to it on loopback
  and does not check that certificate.
- The password file is the password, including after a reboot. Twelve characters at
  least.

### Network Exposure

- listen: tcp/8000 *
- listen: tcp/80 tcp/443 *
- connect: udp/53 tcp/53 *
