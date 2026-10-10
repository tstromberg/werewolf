# Squid

An egress proxy: [Squid](https://www.squid-cache.org) connects to port 443 of the names you list, from the networks you list, and to nothing else. No cache and no cache manager.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create egress --with squid --on lima \
	--networks 192.168.0.0/16 \
	--domains .github.com --domains pypi.org
```

On a client, `HTTPS_PROXY=http://ADDRESS:3128`. A CONNECT to a listed name's port 443 returns `200 Connection established`. Anything else is 403.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create egress --with squid --on gcp --allow-from 10.128.0.0/9 \
	--networks 10.128.0.0/9 \
	--domains .github.com --domains .githubusercontent.com --domains pypi.org
```

`--networks` is up to 32 ranges, besides the machine itself. `--domains` is up to 32 names: `pypi.org` is that host, `.github.com` is that name and everything under it. A whole top-level domain (`.com`) is refused. Run create again to change either list.

### Known Quirks

- CONNECT is port 443 only. Port 25 and every other port are refused.
- Squid does not look inside TLS. It only decides whether the name and port are allowed.
- There is no cache, so nothing is stored, and no cache-manager port.
- The machine itself may connect. Other clients must be in `--networks`.

### Network Exposure

- tcp/3128, for the networks you name. Outbound CONNECT goes to public port 443 of a listed name.
