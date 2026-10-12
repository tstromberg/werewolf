# Zeek - Hardened VM

A network sensor: [Zeek](https://zeek.org) 8.2 reading one interface and writing JSON logs to `/data`. The form's manifest is [form.yaml](form.yaml). Zeek runs from its project's image.

## Security Posture

- Zeek runs as its image's user and captures `eth0` with its AF_PACKET plugin. It keeps `CAP_NET_RAW` and `CAP_NET_ADMIN` for that socket and promiscuous mode. It writes logs. It reaches a resolver and nothing else. No TCP port is declared. A packet socket can still inject frames, and this process's netlink socket can change routes because the resolver pledge includes it.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create zeek --with zeek
```

Logs are JSON files in `/data/svc/zeek`. The scripts are Zeek's stock `local`, and one line so `reporter.log` exists as soon as Zeek is up. Logs are in [Zeek's documentation](https://docs.zeek.org/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create zeek --with zeek --on gcp --allow-from me
```

Put the machine on a span port or a mirror. It listens on nothing. A cloud mirror has to be arranged on the hypervisor; the guest cannot see traffic it was not sent.

### Importing data

There is nothing to import. Logs from this machine are the files under `/data/svc/zeek`.

### Known Quirks

- No packages and no Management framework. What Zeek runs is the image's `local`.
- Promiscuous mode is on, so a mirror can deliver frames addressed to other machines.

### Network Exposure

- listen: none
- connect: udp/53 tcp/53 *
