# UniFi OS Server experiment

An ARM64 integration spike for UniFi OS Server 5.1.42 on Werewolf. Its
[manifest](form.yaml) includes the reusable PostgreSQL, MongoDB and
RabbitMQ and nginx forms. It is outside the released catalog while compatibility
work remains. See the [design](../../docs/design/pending/unifi-os.md).

## Security Posture

Each application runs under its own leash. Images are pinned and baked
into the verified root. Database and broker ports are loopback-only.
The vendor's privileged initialization scripts are replaced by local
setup code; a native adapter answers fixed identity and OS version queries.
A separate [D-Bus adapter](cmd/unifi-systemd/README.md) reads real runit
state over a Unix socket authenticated with kernel peer credentials.
A separate [nginx supervisor](cmd/unifi-nginx/README.md) validates and
reloads its own master on Core's fixed, authenticated request. nginx reads
shared configuration and TLS files while Core's private data stays closed.

## Getting Started

### Local test deployment

```sh
mkdir -p config/rabbitmq
openssl rand -hex 24 >config/rabbitmq/password
howl create unifi-os --build --with ./examples/unifi-os --config ./config
```

This is a diagnostic prototype, not a working replacement console yet.
Use `howl console unifi-os` to inspect startup. The components under test
are UniFi Core, Network and the nginx console; identity and cloud
connectivity remain to be verified. Startup checks require both application
APIs, HTTPS serving and a real nginx worker replacement after reload.
Reboot checks compare the instance UUID and TLS certificate and require
retained MongoDB records and RabbitMQ messages.
The native test harness runs [the checks](test/tests.yaml) on startup and
after a reboot: `make check-native-tests-unifi-os`.
Identity unit tests run with `node --test examples/unifi-os/test/identity.test.mjs`.

### Importing data

Use a fresh data disk. Backup restore and upgrades are not validated.

### Known Quirks

- Core uses a dedicated VM's `postgres` database for this first probe.
- Identity and OS version queries are adapted; privileged actions fail explicitly.
- D-Bus covers service state; identity and OS agent services remain inactive.
- Fresh disks receive an atomically published version-5 instance UUID.
  Existing identities are preserved; incompatible prototype identities fail
  with guidance to use a fresh disk. Automatic identity migration is unsupported.
- Linux's shared printk rate limit can drop audit records during startup
  bursts. The full smoke check reports this logging failure; it is not excused.
- nginx uses the vendor's auth rules with packaging changes for shared
  paths, private runtime files and IPv4. The two verified HTML entry pages
  include the model metadata Core would otherwise inject at runtime.
- The image currently comes from a community mirror. Official vendor
  extraction and authentication are required before release.
- Updates are off while the prototype is being developed.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
- listen: tcp/8444 * (guest portal, after setup)
- listen: tcp/8080 *
- listen: udp/3478 *
- listen: udp/10001 *
- Database, broker, Core, and local Network API listeners bind loopback.
  Werewolf also restricts Network's other management connectors, including
  support port 28082, to local access even when vendor code binds all interfaces.
  Runtime checks query the kernel's external ingress lookup, including
  packets with forged reply source ports, and require public HTTPS to pass.
