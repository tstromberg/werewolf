# MongoDB - Hardened VM

[MongoDB](https://www.mongodb.com/docs/manual/) 8.0 for applications on
the same machine. The manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/mongodb/index.html).

## Security Posture

- MongoDB runs as its own user, with no capabilities.
- Its image is pinned by digest and baked into the verified root.
- Only declared local clients reach TCP 27017. It has no outbound network access.
- Database files survive under `/data/svc/mongodb`; the application image is
  read-only.
- Server-side JavaScript and the container's shell entrypoint are disabled.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create mongodb --with mongodb
```

This is an application dependency: include `with: [mongodb]` in your
form and give its service `connect: tcp/27017`. Connect to
`mongodb://127.0.0.1:27017`. Access is controlled by Werewolf's service
network policy; database authentication is not enabled. Use separate
machines for applications that must not share database authority.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create mongodb --with mongodb --on gcp --allow-from me
```

The database remains local to the VM. No cloud database port is opened.

### Importing data

Restore a logical dump through an application service authorized to
connect to MongoDB. There is no raw data-directory import helper.

### Known Quirks

- A single server, without replication or sharding. A consuming form can override its
  service.
- Memory is limited to 1 GiB, with a 256 MiB WiredTiger cache.
- The pinned image must be rebuilt to receive upstream fixes.

### Network Exposure

- listen: tcp/27017 127.0.0.1
