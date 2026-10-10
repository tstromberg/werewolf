# Name - Hardened VM

<<<NOTE on style: prose like Wietse Venema. No more than 75 lines. Pragmatic, easy to read. No unnecessary words or sentences. Assume the reader is familiar with Linux, but not an expert. The form's README does not mention make. A reader may not have this checkout. Only document what is immediately relevant to a user.>>>

One sentence description of what this form is, with a link to the upstream project and the manifest file.

## Security Posture

What makes this hardened image unhackable? No more than 5 concise bullet points.

If any posture weaknesses show up, add a weaknesses section describing why we had to weaken the security model.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

One fenced `sh` block. It is the whole setup, and `make example-NAME` runs it ([docs/design/examples.md](../docs/design/examples.md)). Leave `--on` out: howl picks Lima, bhyve, Firecracker, or QEMU. The machine's name is the form's name. A secret is a command (`openssl rand`). A file the command reads is written in the fence, or lives in `forms/NAME/example/`. A variant is a `text` block.

```sh
howl create NAME --with NAME
```

Describe the post-install configuration required to use the tool. Keep it short. Hand the reader to the official documentation. If it spins up an admin console, publish the URL or how to find it. End with that link.

### Cloud production deployment (aws, gcp, azure, proxmox)

One fenced `sh` block, run by `make examples-gcp`. It passes `--on gcp` and `--allow-from me`. When this form is more often used on Proxmox, or another cloud, say so here and put that command in a `text` block. If the local version doesn't expose network sockets typically used for this service, the production version should to prove it can be done.

```sh
howl create NAME --with NAME --on gcp --allow-from me
```

Don't repeat the local prose. Say what production changes. If it spins up an admin console, publish the URL or how to find it.

### Importing data

How a reader moves an existing server's data onto this machine. The local fence stays a fresh install. This block is separate, and `make example-NAME` does not run it. The form README does not mention make.

When the host can reach the service, the block is a client on the host, reading a dump the reader already has. A stand-in may live in `forms/NAME/example/`. When that client can load the fixture, add `forms/NAME/test/probe` to load it and read one row back.

When the host cannot reach the service, the block is `--import`. It attaches a read-only disk labelled `werewolf-import`, mounted at `/run/werewolf/import`. The form reads it once, while it first makes its data, and streams it into that data. MariaDB and PostgreSQL read `*.sql`. Valkey reads one `dump.rdb`. A cloud cannot attach the disk. A machine that already exists refuses `--import`: delete it, then create. There is no copy into the machine from outside.

```sh
howl create NAME --with NAME --import ./dump
```

### Known Quirks

How Werewolf's image differs from a standard deployment on other Linux distributions, and from the upstream documentation. No more than five bullets: a path, a missing wizard, a password that is a file. Leave the lock-down to Security Posture.

### Network Exposure

Listening sockets or external network connectivity allowances. Omit this section when there are none. Write each as `listens: tcp/PORT` or `listens: udp/PORT`, `connect: tcp/PORT`
