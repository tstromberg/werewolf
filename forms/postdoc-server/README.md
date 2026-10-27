# postdoc-server - Hardened VM

[postdoc](https://github.com/atomdrift-project/postdoc)'s analysis server, which
answers Scan's `/v1` API behind a Cloudflare Tunnel. Operators reach the machine by
security key. The image includes rizin, innoextract and upx for analysis and
unpacking. The form's manifest is [form.yaml](form.yaml).

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
- postdoc keeps native Wasmtime JIT compilation for its rules. Its PATH selects
  narrowed rizin, innoextract and upx launchers: each restores
  Memory-Deny-Write-Execute, drops network access and further execution, and limits
  writable files to `/data/svc/postdoc`. This confines the helper processes;
  postdoc itself retains its JIT permission and can still invoke a tool directly.
  See [narrowed programs](../../docs/design/narrow.md).

### Weaknesses

- `kernel-write-xor-execute`: yara-x compiles the rules to WebAssembly, and wasmtime
  compiles that to machine code.
- `network-no-login`, `programs-no-shell`: security-key SSH with mksh for operators.
- `programs-no-downloaders`: wget for local API and tunnel diagnostics.

## Getting Started

### Published deployment (Lima, QEMU)

The command below requires a published `postdoc-server` image for your provider and
architecture. Check with `howl forms --published postdoc-server`. The form is
selected in [the release list](../../release/images.yaml); its image and public
update channel become available after the publication workflow passes integration,
reproducibility and protected image lifecycle gates. A failed build or gate keeps the
previous image.

```sh
printf '%s' 'eyJhIjoi...' >tunnel-token
openssl rand -hex 32 >api-token
howl create postdoc-server --with postdoc-server --api-token api-token --tunnel-token tunnel-token
```

The tunnel token is for a remotely managed tunnel, from the Cloudflare dashboard.
Point a public hostname at `http://localhost:49999`. `--tunnel-token` reads a local
file; the config carries it as `cloudflared/token`, and the service receives it as
`TUNNEL_TOKEN`. Both tokens are boot configuration, outside the signed image;
supplying them does not rebuild the image or change its signing trust or update
channel.

The first start downloads about 600 MB of rules and model. `/_/health` reports `ok`
once they are loaded. Callers send `Authorization: Bearer` with the contents of
`api-token`. The routes are in postdoc's
[SERVER_API.md](https://github.com/atomdrift-project/postdoc/blob/main/docs/SERVER_API.md).

To keep verdicts in hopper as well, add `--hopper https://hopper.example/
--hopper-token hopper-token`.

### Signed A/B updates

`howl create` without `--build` downloads and verifies the published image and
preserves its pinned signer and update channel. Once this form is published, that is
the path for automatic signed A/B updates: the updater verifies a later release,
installs it in the inactive slot and boots it on probation. The slot commits only
after service, data, updater and posture checks pass; a failed trial falls back to
the previous slot. These checks establish service uptime, rather than an end-to-end
API or tunnel health check. See [the updater](../../docs/updater.md) and [independent
updates](../../docs/design/independent-updates.md).

The publication gate exercises this form through signed upgrades, operator rollback,
TPM retirement power cuts and failed-trial recovery on disposable signing keys. It
checks the JIT-backed API and saved verdict after each committed boot; candidate
boots also verify the exact production-signed image with disposable boot
configuration. The test flushes the completed analysis before `howl stop`, which cuts
VM power; the server's local verdict cache does not promise durable writes before a
power loss.

`--build` uses your own signing keys. It does not follow werewolf's public signed
updates. To get automatic A/B updates for a local build, its builder must serve a
dedicated `IPE_UPDATES` channel and publish later releases with the same keys and
increasing `IMAGE_INDEX` values. Without that channel, image changes require a
reinstall. See [secured local
deployment](../../docs/design/secure-local-deployment.md).

### Cloud production deployment

Werewolf currently publishes no protected cloud images. A cloud source build also
needs its own signed update channel; it does not provide public signed A/B updates
out of the box. See [published image support](../../cmd/howl/README.md). Give the
machine cores and memory: postdoc sizes its analysis slots and memory ceiling from
the machine.

### Importing data

There is nothing to import. Verdicts live in hopper, and in this machine's own index.

### Known Quirks

- There is no companion idle worker. Run a separate worker to drain hopper's queue.
- No LLM judge: `SCAN_LLM` is unset, so `llm` and `diff_llm` report skipped.
- Rotating the token means replacing `api-token` and restarting the machine. postdoc
  reads the token once.
- The rules and model are kept in `/data/svc/postdoc`. Without a data disk, every
  boot downloads them again.

### Network Exposure

- listen: tcp/22 *
- listen: tcp/49999 127.0.0.1
- listen: tcp/2000 127.0.0.1
- connect: tcp/443 tcp/80 tcp/8081 *
- connect: udp/7844 tcp/7844 *
