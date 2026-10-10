# Squid

An egress proxy: [Squid](https://www.squid-cache.org) connects to port 443 of the names you list, from the networks you list, and to nothing else. No cache and no cache manager. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create squid --with squid \
	--networks 192.168.0.0/16 \
	--domains .github.com --domains pypi.org
```

On a client, `HTTPS_PROXY=http://ADDRESS:3128`, where ADDRESS is the address howl prints. A CONNECT to a listed name's port 443 returns `200 Connection established`. Anything else is 403. The directives Squid itself accepts are in [Squid's documentation](https://wiki.squid-cache.org/SquidFaq/ConfiguringSquid).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create squid --with squid --on gcp --allow-from me \
	--networks 10.0.0.0/8 \
	--domains .github.com --domains .githubusercontent.com --domains pypi.org
```

`--networks` is up to 32 ranges, besides the machine itself. `--domains` is up to 32 names: `pypi.org` is that host, `.github.com` is that name and everything under it. A whole top-level domain (`.com`) is refused.

### Migrating data in

This machine starts empty. What it must remember is in the create command or `--config`. There is no database to import.

### Known Quirks

- CONNECT is port 443 only. Port 25 and every other port are refused.
- Squid does not look inside TLS. It only decides whether the name and port are allowed.
- There is no cache, so nothing is stored, and no cache-manager port.
- The machine itself may connect. Other clients must be in `--networks`.

### Network Exposure

- tcp/3128, for the networks you name. Outbound CONNECT goes to public port 443 of a listed name.
