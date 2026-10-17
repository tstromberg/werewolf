# Langflow

[Langflow](https://www.langflow.org/) 1.12.6, its full editor and ASGI API, hosted
model providers and local CPU ONNX inference on hardened Python 3.15. See
[form.yaml](form.yaml).

## Security Posture

- Python comes from the signed hardened-packages repository.
- No shell or interpreter fetched from an upstream container.
- One service user, private persistent data, bounded memory and no child execution.
- Authentication is required; signup is disabled and the listener is private.
- Hosted providers and model downloads use public HTTPS and resolver DNS.

Native access is scoped to the Langflow service for its numerical dependencies.
Pickle, writable-source and inline-entrypoint allowances remain closed. Application
components execute within Langflow's process and retain its kernel confinement.

## Getting Started

See [image availability](../../docs/forms-catalog.md#images-and-downloads).

```sh
mkdir -p config/langflow
openssl rand -base64 32 > config/langflow/password
howl create langflow --with langflow --build --config config --owner owner
```

The editor is `/` on port 7860; APIs retain `/api/v1/` paths.
Log in with the configured owner and password. Use an authenticated TLS proxy to
reach the private listener remotely. A missing owner or password parks the service.

Flows, SQLite state and models live beneath `/data/svc/langflow`. Keep that data
with its generated secret key. Model files can be provisioned there; local ONNX
inference does not require a hosted provider. The default MiniLM embedding model
and tokenizer are packaged in read-only storage; the demo needs no model download. See
[Langflow documentation](https://docs.langflow.org/).

### Known Quirks

- A direct single-process ASGI launcher avoids the CLI's multiprocessing supervisor.
- The package includes base integrations plus OpenAI and Anthropic providers;
  optional provider extras require a rebuilt image.
- Python upper-bound metadata is ported to 3.15; native dependencies are rebuilt
  where no matching wheel exists. Application endpoint implementations stay pinned.
- The SQLite/local-storage deployment is single-node. Upstream's clustered `prod`
  profile additionally requires PostgreSQL, pgvector and external object storage.
- The ONNX native extension is built from pinned source for Python 3.15.

### Network Exposure

- `listen: tcp/7860 127.0.0.1`
