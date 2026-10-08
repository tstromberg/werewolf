# Gatus

The `gatus` form is `prod` with Gatus 5, watching a service and showing a
status page.

| | |
| --- | --- |
| Listens | tcp/8080, the page and its API, read-only, with no login of its own: `caddy`, `oauth2-proxy` or a tailnet in front to show it beyond the machine |
| Sends | HTTPS, HTTP, DNS and ping to what it watches |
| Runs as | `gatus` (uid 211), leashed |
| Keeps | its history in `/data/svc/gatus/data.db` |
| Settings | `target` (a URL, required): what it watches, 60 s apart, for a 200 within 2 s |

```sh
build/host/werewolf pack gatus -o config.tar --target https://www.example.com/
```

More endpoints, groups and alerting are a form of your own, with its
`etc/gatus/config.yaml` over this one's. The Prometheus endpoint is off,
since it tells anyone what is watched and how it is doing.

## Checked

`make check-gatus` runs [forms/gatus/test/checks](test/checks): the page
and API answer, the target is listed, a write to the API is refused,
`/metrics` is 404, and the history is `gatus`'s on `/data`.
