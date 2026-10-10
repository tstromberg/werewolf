# Open WebUI

A chat window for models that run on the same machine: [Open WebUI](https://github.com/open-webui/open-webui), with Ollama, PostgreSQL and Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create chat --with open-webui --on lima \
	--base-url https://chat.home.arpa --admin-email you@example.com \
	--webui-admin-password admin-password
```

Give the machine 8 GB if you want a small model. Sign in, then under Admin Panel, Settings, Models pull `gemma3:4b` and `nomic-embed-text`. The second is what searches documents you upload.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create chat --with open-webui --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://chat.example.com --admin-email you@example.com \
	--webui-admin-password admin-password
```

Point the name at the machine. There is no sign-up. You add users. The first boot would otherwise give the whole instance to whoever signed up first; here the administrator already exists. Change the password in Open WebUI afterwards.

### Known Quirks

- Ollama listens on loopback only. It is not a second service on the network.
- Models are downloaded to `/data/svc/ollama` and stay there.
- Tools and functions are Python that the server runs. Only an administrator can add one.
- There is no GPU. A model runs on the CPU, and a large one will not fit.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Open WebUI and Ollama are on loopback. Ollama may fetch a model you asked for, over HTTPS.

### Security Weaknesses

- Python runs Open WebUI. Named in `form.yaml`. A function an administrator uploads runs as that same user.
