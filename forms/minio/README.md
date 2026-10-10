# MinIO - Hardened VM

S3 on this machine: [MinIO](https://min.io), for restic, rclone, or an application. The form's manifest is [form.yaml](form.yaml).

## Security Posture

MinIO runs as its own user. There is no shell. Landlock and seccomp hold it to port 9000 and to `/data/svc/minio`. The root is read-only.

- The console is off. The API is the interface, and `mc` is the client.
- Nothing is anonymous until a bucket's policy says so.
- There is no update check, telemetry, replication or notification.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/minio
printf '%s' admin >config/minio/root_user
openssl rand -base64 24 | tr -d '\n' >config/minio/root_password
howl create minio --with minio --config config
```

The API is `http://ADDRESS:9000`. TLS belongs in front, Caddy or the cloud's balancer. Then:

```text
mc alias set store http://ADDRESS:9000 admin "$(cat config/minio/root_password)"
```

Buckets and users are in [MinIO's documentation](https://min.io/docs/minio/linux/index.html).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/minio
printf '%s' admin >config/minio/root_user
openssl rand -base64 24 | tr -d '\n' >config/minio/root_password
howl create minio --with minio --on gcp --allow-from me --config config
```

`--allow-from me` admits your address to port 9000. Put TLS in front before a client sends the root password.

### Migrating data in

This machine starts empty. Once port 9000 answers, mirror the old buckets to it with `mc`. The host cannot write `/data`.

### Known Quirks

- The root user and password files have no newline. They are read into the environment as they are.
- Objects live in `/data/svc/minio`.

### Network Exposure

tcp/9000
