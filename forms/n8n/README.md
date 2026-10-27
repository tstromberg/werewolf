# n8n

[n8n](https://n8n.io/) 2.44.6, including the editor, API, bundled nodes and
JavaScript Code runner, on hardened Node.js 26. See [form.yaml](form.yaml).

## Security Posture

- The signed hardened runtime is required; no Wolfi runtime fallback.
- No shell or package-manager executable in the runtime image.
- The main server and external Code runner have separate users and data directories.
- The main server cannot spawn programs; the runner launcher may start only Node.
- Administrator access is on loopback until exposed through a protected proxy.
- Native Sentry profiling and the development file watcher are omitted. Workflow
  backends, SQLite and expression isolates remain. Hardened Node omits Brotli
  and Zstd; native addons may retain their own codec implementations.

V8 needs JIT permission. SQLite and expression isolates use a native addon allowance
scoped to the main service. Inline entrypoints, writable-source scripts and Node
child-process APIs remain disabled. Provider HTTPS access is limited to public
destinations and resolver DNS.

## Getting Started

See [image availability](../../docs/forms-catalog.md#images-and-downloads).

```sh
mkdir -p config/n8n
openssl rand -hex 32 > config/n8n/task-token
howl create n8n --with n8n --build --config config
```

The editor uses port 5678 at `/`. Complete n8n's owner setup before using workflows.
Put an authenticated TLS proxy in front of the private listener to reach it remotely.
Proxy only the editor/API port.

Set `--editor-url https://automation.example/` and
`--webhook-url https://automation.example/` with `--proxy-hops 1` behind one public
proxy, so OAuth redirects, webhook URLs and client IPs use the public origin.

The broker secret is shared by the two declared services, never embedded in the
image. Missing it parks both services. Credentials and workflows persist beneath
`/data/svc/n8n/.n8n`. Keep a stable data disk: n8n creates its encryption key there.
See [n8n deployment documentation](https://docs.n8n.io/hosting/).

### Known Quirks

- SQLite and the isolated expression engine are rebuilt for Node 26; npm lifecycle
  scripts are not enabled globally.
- The external JavaScript runner has no outbound network or environment/module
  allowances.
- Python Code nodes need a separately declared Python runner.
- Community package installation is disabled. Additional packages or shell commands
  need a new reviewed image.
- This is a single-node SQLite deployment; clustering needs separate database and
  queue forms.

### Network Exposure

- `listen: tcp/5678 127.0.0.1`
- The broker on 5679 and health checks on 5680/5681 stay private.

The native test checks readiness, the editor, the public-only anonymous settings, the
direct Node runtime and its database, owner setup, authenticated workflow creation,
persistence after reboot, expression evaluation and JavaScript Code execution through
the external runner:

```sh
howl test --with n8n
```
