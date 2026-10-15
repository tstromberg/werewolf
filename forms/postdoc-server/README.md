# postdoc-server - Hardened VM

[postdoc](https://github.com/atomdrift-project/postdoc)'s analysis server, which answers
Scan's `/v1` API behind a Cloudflare Tunnel. Operators reach the machine by security
key. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](../../docs/forms-catalog.md#images-and-downloads).

## Security Posture

postdoc runs as its own user. Landlock and seccomp hold it to `/data/svc/postdoc`, to
loopback port 49999 and to outbound connections. The root is read-only.

- The API listens on loopback only. Callers arrive through the tunnel, which opens no
  port.
- Every route except `/_/health` requires the bearer token. Loopback is not exempt,
  because tunnelled traffic arrives from loopback.
- The token is a file that only postdoc reads. It is never in an environment or an
  argument.
- SSH accepts only security keys, and a login requires touching the key.

### Weaknesses

- `kernel-write-xor-execute`: yara-x compiles the rules to WebAssembly, and wasmtime
  compiles that to machine code.
- `network-no-login`, `programs-no-shell`, `programs-no-downloaders`,
  `programs-no-interpreters`: sshd, and busybox-full for those who log in.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
printf '%s' 'eyJhIjoi...' >tunnel-token
openssl rand -hex 32 >api-token
howl create postdoc-server --with postdoc-server --api-token api-token --tunnel-token tunnel-token
```

The tunnel token is for a remotely managed tunnel, from the Cloudflare dashboard. Point
a public hostname at `http://localhost:49999`. The first start downloads about 600 MB of
rules and model. `/_/health` reports `ok` once they are loaded. Callers send
`Authorization: Bearer` with the contents of `api-token`. The routes are in postdoc's
[SERVER_API.md](https://github.com/atomdrift-project/postdoc/blob/main/docs/SERVER_API.md).

To keep verdicts in hopper as well, add `--hopper https://hopper.example/ --hopper-token
hopper-token`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create postdoc-server --with postdoc-server --on gcp --allow-from me --api-token api-token --tunnel-token tunnel-token
```

`--allow-from me` admits your address to port 22. The API stays behind the tunnel. Give
the machine cores and memory: postdoc sizes its analysis slots and memory ceiling from
the machine.

### Importing data

There is nothing to import. Verdicts live in hopper, and in this machine's own index.

### Known Quirks

- There is no companion idle worker. Run a separate worker to drain hopper's queue.
- No LLM judge: `SCAN_LLM` is unset, so `llm` and `diff_llm` report skipped.
- Rotating the token means replacing `api-token` and restarting the machine. postdoc
  reads the token once.
- The rules and model are kept in `/data/svc/postdoc`. Without a data disk, every boot
  downloads them again.

### Network Exposure

- listen: tcp/22 *
- listen: tcp/49999 127.0.0.1
- listen: tcp/2000 127.0.0.1
- connect: tcp/443 tcp/80 tcp/8081 *
- connect: udp/7844 tcp/7844 *
