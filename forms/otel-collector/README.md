# OpenTelemetry Collector

The `otel-collector` form takes a company's traces, metrics and logs over
OTLP and passes them on to one backend: the OpenTelemetry Collector 0.162
(contrib), on one leash, TLS and a bearer token on both its ports
([design/corporate.md](../../docs/design/corporate.md)).

## Run your own

```sh
openssl rand -hex 24 >otel-token        # what senders give; keep it
howl create otel --with otel-collector --on gcp --allow-from 10.128.0.0/20 \
	--tls-cert otel.crt --tls-key otel.key --token otel-token \
	--export tempo.internal:4317 --export-token backend-token
```

Applications send OTLP to `https://otel.internal:4317` (gRPC) or
`https://otel.internal:4318` (HTTP), with the header
`Authorization: Bearer TOKEN`: in the SDKs,
`OTEL_EXPORTER_OTLP_ENDPOINT` and
`OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20TOKEN`.

| Flag | |
| --- | --- |
| `--tls-cert FILE`, `--tls-key FILE` | required. A certificate and its key, PEM, for both ports |
| `--token FILE` | required. The tokens senders may give, one a line, so a new one can join before the old leaves |
| `--export HOST:PORT` | required. Where everything goes: an OTLP gRPC endpoint over TLS, on port 4317 or 443 |
| `--export-token FILE` | required. The token the collector gives there, as `Authorization: Bearer` |

To change a running machine's endpoint or tokens, run its create line
again: howl replaces its config and restarts it.

## How it is held

- **One configuration, reviewed in the image.** [config.json](rootfs/etc/otel-collector/config.json)
  is all of it; the endpoint is the one value a setting fills in, as a
  `hostport`, so it holds no `${...}` for the collector to expand.
  `otelcol-contrib validate` checks the result before the collector
  starts; a configuration it refuses parks the service.
- **TLS and a token on both ports.** The bearer-token extension compares
  in constant time; no token, or a wrong one, is 401 over HTTP and
  `Unauthenticated` over gRPC. Plain HTTP gets no further than TLS.
- **TLS out too.** gRPC to the endpoint, checked against the system's
  CAs, with a token of its own; the token is never sent in the clear.
- **Nothing else listening.** No debug exporter, zpages, pprof, health
  check or remote configuration; its own metrics are off, its logs on
  the console.
- **It runs nothing, writes nothing.** Its pledge has no exec or wpath;
  `watch` is the token files', which the extension watches.
- **Its own limits.** 512 MiB under leash, Go's heap held to 360 MiB; the
  memory limiter refuses data above 320 MiB, which senders retry.
- **A queue in memory.** While the endpoint is down, batches wait in the
  exporter's queue and are retried; a restart loses them.

## Drawbacks

- One endpoint, gRPC, verified by public CAs: a backend on an internal
  CA, one taking only OTLP over HTTP (Loki, Prometheus), or several
  backends, is a form of your own on `base: otel-collector`.
- No sampling, filtering or attributes processors: everything sent is
  passed on.
- The binary is 430 MB, the contrib build's every component.

## Checked

`make check-otel-collector` boots it with its test config
([test/config](test/config)): a span sent over HTTPS with the token is
taken, and an export over gRPC; the rendered configuration names the
endpoint and none of debug, zpages, pprof or health check, the collector
listens on :4317 and :4318 alone, and the key and tokens are its user's,
0600. The attack: no token, a wrong one, and the collector's own export
token are each refused, over HTTP and gRPC, and plain HTTP to :4318 is
refused at TLS. Nothing on the machine can stand in for the endpoint:
fence lets the collector reach 4317 and 443 alone, which it holds or
nothing may bind. `make check-shellfree-otel-collector` boots it as it
ships, with no config: the collector parks, saying it has no
certificate, before it renders or binds anything.
