# OpenTelemetry Collector

A place applications send traces, metrics and logs: the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/), OTLP over TLS, forwarded to the one backend you name.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -hex 24 >otel-token
howl create otel --with otel-collector --on lima \
	--tls-cert otel.crt --tls-key otel.key --token otel-token \
	--export tempo.internal:4317 --export-token backend-token
```

Senders use `https://HOST:4317` (gRPC) or `:4318` (HTTP) and the header `Authorization: Bearer` plus a line from `otel-token`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -hex 24 >otel-token
howl create otel --with otel-collector --on gcp --allow-from 10.128.0.0/20 \
	--tls-cert otel.crt --tls-key otel.key --token otel-token \
	--export tempo.internal:4317 --export-token backend-token
```

`--export` is an OTLP gRPC address on port 4317 or 443. `--token` is one token a line, so a new sender can start before the old token is removed. Run create again to change either; the collector restarts.

In the SDKs: `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20TOKEN`.

### Known Quirks

- A span without a token is refused.
- There is no debug, zpages or pprof extension.
- The check shows that a span is accepted. It does not show that your backend received it.
- Certificates are yours. The form generates none.

### Network Exposure

- tcp/4317 and tcp/4318, TLS, for senders you allow. The export connection leaves for the host you named.
