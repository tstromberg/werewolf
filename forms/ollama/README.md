# Ollama - Hardened VM

Models on this machine: [Ollama](https://ollama.com). The form's manifest is [form.yaml](form.yaml).

## Security Posture

Ollama runs as its own user. There is no shell. Landlock and seccomp hold it to port 11434, to the registry, and to `/data/svc/ollama`. The root is read-only.

- The API has no login. Put oauth2-proxy, Caddy or a tailnet in front before you serve it past this machine.
- A browser on another origin is refused.
- It may run only itself, which is how a model is loaded.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create ollama --with ollama
```

Pull a model against the address howl prints:

```text
curl http://ADDRESS:11434/api/pull -d '{"model":"gemma3:4b"}'
```

Models and the API are in [Ollama's documentation](https://github.com/ollama/ollama/blob/main/docs/api.md).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create ollama --with ollama --on gcp --allow-from me
```

`--allow-from me` admits your address to port 11434. The API still has no login.

### Migrating data in

This machine starts empty. Pull a model with the client against the address howl prints. Models already on disk are in `/data/svc/ollama`, and the host cannot write that directory.

### Known Quirks

- Models run on the CPU. A GPU is a device no form carries yet.
- The leash is 8 GiB. The model decides the rest.

### Network Exposure

tcp/11434
