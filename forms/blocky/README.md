# Blocky

DNS for a home or an office that blocks ads and trackers: [Blocky](https://0xerr0r.github.io/blocky/) 0.35, from its own image. There is no web interface. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create blocky --with blocky
```

Point one device at the address howl prints. A blocked name answers 0.0.0.0. Other names resolve. Lists and upstreams are in [Blocky's configuration](https://0xerr0r.github.io/blocky/latest/configuration/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create blocky --with blocky --on gcp --allow-from me
```

`--allow-from me` opens port 53 to the address you run this from. A house more often runs on Proxmox, on the LAN the devices already use:

```text
howl create blocky --with blocky --on proxmox \
	--allow-from 192.168.0.0/16 \
	--upstreams tcp-tls:dns.mullvad.net \
	--blocklists https://example.org/list.txt
```

Give the address to the router's DHCP as the DNS server. Repeat a flag for another entry. An upstream must be `tcp-tls:` or `https:`.

### Migrating data in

This machine starts empty. What it must remember is in the create command or `--config`. There is no database to import.

### Known Quirks

- The default upstreams are Quad9 and Cloudflare, over TLS. The default list is Steven Black's hosts file.
- Lists are fetched again at every boot. Until they arrive, nothing is blocked.
- There is no query log. Client addresses are not written.
- A client outside the private ranges (10/8, 172.16/12, 192.168/16, and the local ranges) is answered 0.0.0.0 and limited to a few queries a second.

### Network Exposure

- udp/53 and tcp/53. Nothing else listens.
