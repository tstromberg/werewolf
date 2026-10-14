# UniFi OS Server experiment

An ARM64 integration spike for UniFi OS Server 5.1.42 on Werewolf. Its
[manifest](form.yaml) includes the reusable PostgreSQL, MongoDB and
RabbitMQ forms. It is outside the released catalog while compatibility
work remains. See the [design](../../docs/design/unifi-os.md).

## Security Posture

Each application runs under its own leash. Images are pinned and baked
into the verified root. Database and broker ports are loopback-only.
The vendor's privileged initialization scripts are replaced by local
setup code; the hardware identity adapter handles one read-only call.

## Getting Started

### Local test deployment

```sh
mkdir -p config/rabbitmq
openssl rand -hex 24 >config/rabbitmq/password
howl create unifi-os --build --with ./examples/unifi-os --config ./config
```

This is a diagnostic prototype, not a working replacement console yet.
Use `howl console unifi-os` to inspect startup. The components under test
are UniFi Core and Network; identity, cloud connectivity and nginx
integration remain to be verified. No public OS console is exposed yet.

### Importing data

Use a fresh data disk. Backup restore and upgrades are not validated.

### Known Quirks

- Core uses a dedicated VM's `postgres` database for this first probe.
- Only the hardware identity call is adapted; other privileged actions fail explicitly.
- D-Bus service-state compatibility is still required.
- The image currently comes from a community mirror. Official vendor
  extraction and authentication are required before release.
- Updates are off while the prototype is being developed.

### Network Exposure

- listen: tcp/8080 *
- listen: udp/3478 *
- listen: udp/10001 *
- Database, broker and application management listeners remain on loopback.
