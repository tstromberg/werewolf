# HAProxy

The `haproxy` form balances HTTP over backends you name: HAProxy 3.4 on
:80, and on :443 with a certificate you give it, on one leash, with nothing
to control it by but the configuration its settings write
([design/service-forms.md](../../docs/design/service-forms.md)).

## Run your own

```sh
howl create lb --with haproxy --on gcp --allow-from 0.0.0.0/0 \
	--backends 10.128.0.5:8080,10.128.0.6:8080 --health /health
```

HAProxy sends each request to the next backend that answers its checks,
and adds `X-Forwarded-For`. With a certificate it serves HTTPS on :443
and sends :80 there:

```sh
howl create lb --with haproxy --on gcp --allow-from 0.0.0.0/0 \
	--backends 10.128.0.5:8080 --tls-cert site.crt --tls-key site.key
```

| Flag | |
| --- | --- |
| `--backends HOST:PORT,...` | required. Up to 32, by name or IPv4 address, on port 80, 443 or 8080 |
| `--health PATH` | an HTTP health check, `GET PATH`; without it, a TCP connect |
| `--tls-cert FILE`, `--tls-key FILE` | a certificate and its key, PEM: HTTPS on :443, HSTS, and :80 redirected |

A backend whose name does not resolve yet starts down, not HAProxy's
start. To change a running machine's backends, run its create line
again: howl replaces its config and restarts it.

## Ports

fence lets HAProxy reach backends on 80, 443 and 8080 alone, the ports
werewolf's own application forms and most HTTP services serve on.
haproxy-setup refuses a backend on any other, saying so, rather than let
fence drop its connections. For another port, make a form of your own
on `base: haproxy` whose `haproxy` service connects to it.

## How it is held

- **haproxy-setup first.** [cmd/haproxy-setup](cmd/haproxy-setup/haproxy-setup.zig)
  runs before HAProxy, on its leash: it writes `/run/svc/haproxy/haproxy.cfg`
  from the settings, refuses a port fence would drop, and has HAProxy
  check the file (`haproxy -c`) before it starts.
- **Nothing to control it by.** No stats socket, no Lua, no external
  checks; `-db`, with no master process, so nothing reloads or re-runs
  it. A new configuration is a restart.
- **Timeouts** of 5 s to connect, 30 s to the client and server, 10 s for
  a request's headers (slowloris), and an hour for a tunnel.
- **httpoxy.** A `Proxy` header is dropped, which a CGI backend would
  make `HTTP_PROXY`.
- **Its own limits.** `maxconn 4000`, and `-m 200` under leash's 256 MiB,
  so it refuses connections rather than dying.
- **Its scripts pruned.** HAProxy 3.4 brings `haproxy-reload`,
  `haproxy-dump-certs` and bash for them; the image leaves all three out.
  3.4 is the line Wolfi keeps current: 3.2's last build was 2025-11.
- **Errors logged, not requests**, on the console: `option
  dontlog-normal`, as a serial console cannot carry every request.

## Drawbacks

- HTTP only: no TCP mode, no ports but 80 and 443.
- No ACME: HAProxy 3.4's client is experimental. Give it a certificate,
  from `step-ca` or your own CA, or put Caddy in front.
- HAProxy's watchdog, which kills a thread stuck in a loop, needs a
  CPU-time timer, which werewolf's seal refuses (CVE-2025-38352); a stuck
  HAProxy is restarted only when it exits.

## Checked

`make check-haproxy` boots it with its test config ([test/config](test/config)):
one backend, a listener the check starts on loopback :443 and that
records what reaches it. A request passes through, with
`X-Forwarded-For` added and its `Proxy` header gone; headers sent too
slowly are cut off with a 408 after 10 s; the configuration has no stats
socket, Lua or external checks. `make check-shellfree-haproxy` boots it
as it ships, with no config: its settings are refused for want of
backends, and HAProxy stays down, binding nothing.

TLS is not in `make check`, whose backend holds :443. It was booted by
hand on 2026-10-10, as a form on `base: haproxy` with a certificate:
HTTPS answered with it, :80 sent requests there, and the configuration
loaded the certificate and key from the config.
