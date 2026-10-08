# cloudflared

The `cloudflared` form is `prod` with a Cloudflare Tunnel: a machine that
serves hostnames on the Internet with no port open to it.

| | |
| --- | --- |
| Listens | nothing; metrics on loopback (:2000) |
| Sends | QUIC (udp/7844) and HTTPS to Cloudflare's edge; HTTP and HTTPS to the origins it fronts, on this machine or its network |
| Runs as | `cloudflared` (uid 213), leashed |
| Config | `cloudflared/token`: the tunnel's token, from the Cloudflare dashboard (a remotely managed tunnel), which also holds the hostnames and origins |

```sh
printf '%s' 'eyJhIjoi...' >config/cloudflared/token
build/host/howl pack cloudflared -o config.tar --config config
```

The token is read into the service's environment (`TUNNEL_TOKEN`) by
leash and is nowhere the service can read it as a file. `--no-autoupdate`:
updates come with the image.

## Checked

`make check-cloudflared` gives the machine a token of the right shape and
no way out ([forms/cloudflared/test/config](test/config); the
Makefile's `restrict=on`), and runs
[forms/cloudflared/test/checks](test/checks): nothing listens on
the network, the metrics answer on loopback alone, the tunnel keeps
trying, and the token is root's.
