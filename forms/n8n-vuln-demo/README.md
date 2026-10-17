# n8n vulnerable demonstration

[n8n](https://n8n.io/) 1.120.0, including the editor, API, bundled nodes and
JavaScript Code runner, on hardened Node.js 26. See [form.yaml](form.yaml).

## Security Posture

- The signed hardened-packages runtime is required; no Wolfi runtime fallback.
- No shell or package-manager executable in the runtime image.
- The main server and external Code runner have separate users and data directories.
- The main server cannot spawn programs; the runner launcher may start only Node.
- Administrator access is deliberately public.

V8 needs JIT permission. SQLite uses a native addon allowance
scoped to the main service. Inline entrypoints, writable-source scripts and Node
child-process APIs remain disabled. Updates are disabled for this deliberately pinned
vulnerable release.

## Getting Started

See [image availability](../../docs/forms-catalog.md#images-and-downloads).

```sh
mkdir -p config/n8n
openssl rand -hex 32 > config/n8n/task-token
howl create n8n-vuln-demo --with n8n-vuln-demo --build --config config
```

The editor uses port 5678 at `/`. Complete n8n's owner setup before using workflows. Use
`vuln-demo` for request, application and containment event capture. The
expression-injection target requires an authenticated account.

Set `--editor-url https://automation.example/` and
`--webhook-url https://automation.example/` with `--proxy-hops 1` behind one public
proxy, so OAuth redirects, webhook URLs and client IPs use the public origin.

The broker secret is shared by the two declared services, never embedded in the
image. Missing it parks both services. Credentials and workflows persist beneath
`/data/svc/n8n/.n8n`. Keep a stable data disk: n8n creates its encryption key there.
See [n8n deployment documentation](https://docs.n8n.io/hosting/).

### Known Quirks

- Workspace dependencies are pinned to the versions declared by n8n 1.120.0;
  newer semver-compatible packages otherwise create separate configuration and
  dependency-injection registries. Packaging checks real CLI loading, SQLite
  queries, fresh-database migrations and HTTP readiness.
- SQLite is rebuilt for Node 26; npm lifecycle scripts are not enabled globally.
  The original expression engine and vulnerable application remain pinned.
- The external JavaScript runner has no outbound network or environment/module
  allowances.
- Python Code nodes need a separately declared Python runner.
- Community package installation is disabled. Additional packages or shell commands
  need a new reviewed image.
- This is a single-node SQLite deployment; clustering needs separate database and queue
  forms.

### Network Exposure

- `listen: tcp/5678 *`
- The broker on 5679 and health checks on 5680/5681 stay private.

The native test checks owner setup, authenticated workflow creation, persistence
after reboot, expression evaluation and JavaScript Code execution through the
external runner:

```sh
howl test --with n8n-vuln-demo
```
