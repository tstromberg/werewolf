# Blocky

DNS for a home or an office that blocks ads and trackers: [Blocky](https://0xerr0r.github.io/blocky/) 0.35, from its own image. There is no web interface.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create dns --with blocky --on lima
```

Point one device at the address howl prints. A blocked name answers 0.0.0.0. Other names resolve.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create dns --with blocky --on proxmox
```

Put the machine on the private network your devices already use, and give its address to the router's DHCP as the DNS server. To replace the defaults:

```sh
howl create dns --with blocky --on proxmox \
	--upstreams tcp-tls:dns.mullvad.net \
	--blocklists https://example.org/list.txt
```

Repeat a flag for another entry. An upstream must be `tcp-tls:` or `https:`. Plain DNS from Blocky is refused.

### Known Quirks

- The default upstreams are Quad9 and Cloudflare, over TLS. The default list is Steven Black's hosts file.
- Lists are fetched again at every boot. Until they arrive, nothing is blocked.
- There is no query log. Client addresses are not written.
- A client outside the private ranges (10/8, 172.16/12, 192.168/16, and the local ranges) is answered 0.0.0.0 and limited to a few queries a second.

### Network Exposure

- udp/53 and tcp/53. Nothing else listens.
