# The demo - Hardened VM

A machine that serves one page about itself and keeps itself patched, with no shell in
the image. The page shows uptime, the last patches, and what a vulnerability scan finds.
The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/demo/index.html).

## Security Posture

- The page is static HTML, rewritten every minute, with no script.
- The scanner may fetch the vulnerability database, and nothing else.
- PostgreSQL is on a UNIX socket. The page reads it. The host cannot.

### Weaknesses

- PostgreSQL compiles costly queries to machine code with LLVM.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create demo --with demo
```

Open `http://ADDRESS`. The first scan follows a download of the vulnerability database.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create demo --with demo --on gcp --allow-from me
```

`--allow-from me` admits your address to port 80. Give the machine a data disk. A scan
does not fit in RAM.

### Importing data

The page keeps its history on `/data`. This form does not import that history. It
collects again after the machine is up.

### Known Quirks

- Times read as "2 hours ago". The moment itself is on hover.
- A finding inside grype is listed under the grype package.

### Network Exposure

- listen: tcp/80 *
