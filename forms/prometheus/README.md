# Prometheus

The `prometheus` form scrapes the targets you name, and itself, every 30
seconds and keeps 15 days of metrics on `/data`: Prometheus 3.12, on one
leash, its web and API taking one user, its admin, lifecycle and
remote-write APIs off, as Prometheus ships
([design/forms-catalog.md](../../docs/design/forms-catalog.md)).

## Run your own

```sh
openssl rand -base64 24 >metrics-password    # its user's; keep it
howl create metrics --with prometheus --on gcp --allow-from 10.128.0.0/20 \
	--targets 10.128.0.5:9100,10.128.0.6:8080 \
	--admin grafana --admin-password metrics-password
```

Prometheus answers on :9090, at `http://ADDRESS:9090`, to `grafana` and
that password alone, in the browser or as Grafana's data source with
basic auth. With `--tls-cert FILE --tls-key FILE` it answers over HTTPS.

| Flag | |
| --- | --- |
| `--targets HOST:PORT,...` | required. Up to 256, by name or IPv4 address, on port 80, 443, 8080, 9090 or 9100, scraped at `/metrics` over HTTP |
| `--admin NAME` | required. The one user its web and API take |
| `--admin-password FILE` | required. That user's password, 12 to 72 bytes |
| `--tls-cert FILE`, `--tls-key FILE` | a certificate and its key, PEM: HTTPS on :9090 |

To change a running machine's targets, run its create line again: howl
replaces its config and restarts it, and the metrics on `/data` stay.

## Ports

fence lets Prometheus reach targets on 80, 443, 8080, 9090 and 9100
alone: applications' `/metrics`, other Prometheus servers, and
node_exporter's port. prometheus-setup refuses a target on any other,
saying so, rather than let fence drop its scrapes. For another port, make
a form of your own on `base: prometheus` whose `prometheus` service
connects to it.

## How it is held

- **prometheus-setup first.** [cmd/prometheus-setup](cmd/prometheus-setup/prometheus-setup.zig)
  runs before Prometheus, on its leash: it writes `prometheus.yml` and
  `web.yml` in `/run/svc/prometheus` from the settings, the password as
  a bcrypt hash, refuses a port fence would drop, and has `promtool`
  check both files before Prometheus starts.
- **One user.** Every page and API call asks for it, `/-/healthy` too.
- **Its APIs off.** No admin API (deleting series, snapshots), no
  lifecycle API (reload, quit), no remote-write or OTLP receiver: nothing
  but scrapes writes metrics in, and nothing over HTTP changes it.
- **It runs nothing.** Its pledge has no exec; `promtool` is
  prometheus-setup's alone.
- **Itself, scraped.** A job `prometheus` scrapes its own `/metrics` with
  its own user, so `up` shows a broken scrape before a dashboard does.
- **Its own limits.** 1 GiB under leash, Go's heap held to 768 MiB.

## Drawbacks

- Scrapes are plain HTTP, without authentication, as most exporters
  serve; keep them on a private network.
- No rules or alerting: Prometheus records, Grafana or Alertmanager
  elsewhere alert.
- 15 days, on the machine's disk; no remote storage.

## Checked

`make check-prometheus` boots it with its test config ([test/config](test/config)):
a stranger gets 401 and its user its health; within a scrape or two
it is up itself and the target nothing answers is down; the admin,
lifecycle and remote-write APIs each refuse its user with their own
message; `web.yml` holds a bcrypt hash and not the password, 0600; the
metrics are on `/data`. `make check-shellfree-prometheus` boots it as it
ships, with no config: Prometheus parks, saying it has no password,
before it writes or binds anything.
