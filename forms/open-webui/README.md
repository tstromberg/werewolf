# Open WebUI

A chat window for models that run on the same machine: [Open WebUI](https://github.com/open-webui/open-webui), with Ollama, PostgreSQL and Caddy. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- Python runs Open WebUI. Named in `form.yaml`. A function an administrator uploads runs as that same user.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create open-webui --with open-webui \
	--base-url https://chat.home.arpa --admin-email you@example.com \
	--webui-admin-password admin-password
```

Open `https://chat.home.arpa` and sign in as `you@example.com`. The password is in `admin-password`. Give the machine 8 GB for a small model. Under Admin Panel, Settings, Models pull `gemma3:4b` and `nomic-embed-text`. Models and documents are in [Open WebUI's documentation](https://docs.openwebui.com/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create open-webui --with open-webui --on gcp --allow-from me \
	--base-url https://chat.example.com --admin-email you@example.com \
	--webui-admin-password admin-password
```

Sign in at `https://chat.example.com`. There is no sign-up. You add users. Change the password in Open WebUI afterwards.

### Migrating data in

PostgreSQL has no TCP port. `--import` attaches a directory of SQL. It is applied once, in the `postgres` database, while the cluster is first made. See [postgresql](../postgresql/README.md). `CREATE DATABASE` is not available there. A cloud cannot attach the disk.

```sh
howl create open-webui --with open-webui --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the service after it is up.

### Known Quirks

- Ollama listens on loopback only. It is not a second service on the network.
- Models are downloaded to `/data/svc/ollama` and stay there.
- Tools and functions are Python that the server runs. Only an administrator can add one.
- There is no GPU. A model runs on the CPU, and a large one will not fit.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Open WebUI and Ollama are on loopback. Ollama may fetch a model you asked for, over HTTPS.
