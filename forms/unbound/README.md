# Unbound

A recursive, validating resolver for a private network: [Unbound](https://nlnetlabs.nl/projects/unbound/). It answers the addresses you allow, and no one else. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create unbound --with unbound
```

Point one machine at the address howl prints and resolve a name. A query from outside the private ranges is refused. Zone and trust-anchor options are in [Unbound's documentation](https://unbound.docs.nlnetlabs.nl/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create unbound --with unbound --on gcp --allow-from me
```

`--allow-from me` opens port 53 to the address you run this from. For a cloud's private zones, send those to the cloud's resolver:

```text
howl create unbound --with unbound --on gcp --allow-from 10.128.0.0/9 \
	--forward-zones corp.example,10.in-addr.arpa --forward-to 169.254.169.254
```

`--forward-zones` is up to 32 names, each taken as unsigned. `--forward-to` is up to 32 addresses, all on port 53. AWS's resolver is the VPC network plus two (10.0.0.2). GCP's is 169.254.169.254. Azure's is 168.63.129.16.

### Migrating data in

This machine starts empty. What it must remember is in the create command or `--config`. There is no database to import.

### Known Quirks

- It is not an open resolver. A public address gets no answer.
- Forwarded zones are not validated. You are trusting the server you named.
- There is no web interface and no query log.
- DNSSEC applies to names resolved from the root, not to a forwarded zone.

### Network Exposure

- udp/53 and tcp/53, for the networks you allow. Unbound queries the public DNS itself.
