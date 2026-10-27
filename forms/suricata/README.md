# Suricata - Hardened VM

A network sensor: [Suricata](https://suricata.io) 8 reading one interface and writing
alerts to `/data`. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/suricata/index.html).

## Security Posture

- Suricata runs as its own user and captures `eth0` with the AF_PACKET ring. It keeps
  `CAP_NET_RAW` and `CAP_NET_ADMIN` for that socket and promiscuous mode. It reads
  the rules cache: Emerging Threats Open, the engine's protocol rules, and one
  marker. It binds no TCP port. Its pledge has no `inet`, so it cannot fetch. A
  packet socket can still inject frames.
- rules-fetch, as `_rules`, downloads that cache onto the data partition and
  refreshes it daily. The directory is mode 0711 and the files are mode 0644, so
  Suricata can read them and cannot replace them.
- The unix control socket is off. `suricata-update` and Python are not on the
  machine. A refresh is loaded the next time Suricata starts.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create suricata --with suricata
```

Alerts are in `/data/svc/suricata`. The cache is `/data/svc/rules-fetch`: Emerging
Threats Open when the feed answers, and always the engine's protocol rules plus one
rule that looks for the string `werewolf-suricata-marker` in HTTP. Rules are in
[Suricata's documentation](https://docs.suricata.io/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create suricata --with suricata --on gcp --allow-from me
```

Put the machine on a span port or a mirror. It still listens on nothing. GCP's
network may not deliver traffic the VM did not address; a mirror on the hypervisor
does.

### Importing data

There is nothing to import. Alerts from this machine are the files under
`/data/svc/suricata`.

### Known Quirks

- The signature cache refreshes when rules-fetch starts a pass, at most daily.
  Suricata keeps the rules it loaded until it starts again.
- Promiscuous mode is on. A mirror that delivers frames addressed to other machines
  needs it; `CAP_NET_ADMIN` is what sets it.

### Network Exposure

- listen: none
- connect: rules-fetch to TCP 443 on public addresses, and to the resolver on UDP and
  TCP 53. Suricata itself connects nowhere.
