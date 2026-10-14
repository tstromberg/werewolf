# RabbitMQ - Hardened VM

[RabbitMQ](https://www.rabbitmq.com/docs/4.2/) 4.2 for applications on
the same machine. The manifest is [form.yaml](form.yaml).

## Security Posture

- RabbitMQ runs as its own user, with no capabilities.
- Its pinned image is baked into the verified root; startup uses native programs.
- AMQP and Erlang distribution are confined to loopback and declared clients.
- Broker data and its Erlang cookie survive under `/data/svc/rabbitmq`.
- The configured user has application permissions; no management plugin is enabled.

### Weaknesses

Erlang's BEAM runtime uses JIT compilation, declared in the manifest.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/rabbitmq
openssl rand -hex 24 >config/rabbitmq/password
howl create rabbitmq --with rabbitmq --config ./config
```

Include `with: [rabbitmq]` in an application form and give its service
`connect: tcp/5672`. Connect to `amqp://app:PASSWORD@127.0.0.1:5672/`,
using the configured password. `--rabbitmq.username NAME` changes `app`.
The password must be 12–256 printable ASCII characters. The user may
configure, publish and consume in the `/` vhost.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/rabbitmq
openssl rand -hex 24 >config/rabbitmq/password
howl create rabbitmq --with rabbitmq --on gcp --allow-from me --config ./config
```

The broker remains local to the VM. No cloud AMQP port is opened.

### Importing data

Move messages through an authorized AMQP application. There is no raw
broker-directory import helper.

### Known Quirks

- One broker, without clustering or a management UI.
- Changing the boot-config password updates the application user's password at restart.
- Memory is limited to 1 GiB, with a 512 MiB broker watermark.
- Upstream updates require a new image build and matching Erlang runtime paths.

### Network Exposure

- listen: tcp/5672 127.0.0.1
- listen: tcp/4369 127.0.0.1
- listen: tcp/25672 127.0.0.1
