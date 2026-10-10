# OpenTelemetry Collector

A place applications send traces, metrics and logs: the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/), OTLP over TLS, forwarded to the one backend you name. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -hex 24 >otel-token
openssl rand -hex 24 >backend-token
openssl ecparam -name prime256v1 -genkey -noout -out otel.key
openssl req -new -x509 -key otel.key -out otel.crt -days 30 \
	-subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
howl create otel-collector --with otel-collector \
	--tls-cert otel.crt --tls-key otel.key --token otel-token \
	--export 127.0.0.1:443 --export-token backend-token
```

Nothing answers on `127.0.0.1:443`, so a span stays in the queue until you name a backend. Senders use `https://ADDRESS:4317` (gRPC) or `:4318` (HTTP) and the header `Authorization: Bearer` plus a line from `otel-token`. Receivers and exporters are in the [collector documentation](https://opentelemetry.io/docs/collector/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -hex 24 >otel-token
openssl rand -hex 24 >backend-token
openssl ecparam -name prime256v1 -genkey -noout -out otel.key
openssl req -new -x509 -key otel.key -out otel.crt -days 30 \
	-subj /CN=otel.example.com -addext 'subjectAltName=DNS:otel.example.com'
howl create otel-collector --with otel-collector --on gcp --allow-from me \
	--tls-cert otel.crt --tls-key otel.key --token otel-token \
	--export 127.0.0.1:443 --export-token backend-token
```

`--export` is an OTLP gRPC address on port 4317 or 443. The address above is a local port where nothing answers, so a span waits in the queue; point it at your backend when you have one. `--token` is one token a line. In the SDKs: `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20TOKEN`.

### Migrating data in

This machine starts empty. What it must remember is in the create command or `--config`. There is no database to import.

### Known Quirks

- A span without a token is refused.
- There is no debug, zpages or pprof extension.
- The check shows that a span is accepted. It does not show that your backend received it.
- Certificates are yours. The form generates none.

### Network Exposure

- tcp/4317 and tcp/4318, TLS, for senders you allow. The export connection leaves for the host you named.
