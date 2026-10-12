# Zeek - Hardened VM

A network sensor: [Zeek](https://zeek.org) 8.2 reading one interface and writing JSON logs to `/data`. The form's manifest is [form.yaml](form.yaml). Zeek runs from its project's image.

## Security Posture

- pcap-feed opens the packet socket and promiscuous mode, then becomes `_pcap` and may only copy frames. Zeek never holds those capabilities.
- Zeek runs as its image's user. It reads the fifo and writes logs. It reaches a resolver and nothing else.

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

- Inside the image the fifo is `/tmp/feed`. On the machine it is `/run/svc/zeek/feed`.
- No packages and no Management framework. What Zeek runs is the image's `local`.

### Network Exposure

- listen: none
- connect: udp/53 tcp/53 *
