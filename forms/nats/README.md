# NATS

The `nats` form is `prod` with NATS 2.15, the message bus between an
application's parts, with JetStream for what must be kept.

| | |
| --- | --- |
| Listens | tcp/4222, TLS; monitoring on loopback (:8222) |
| Sends | nothing: no routes, leaf nodes or gateways |
| Runs as | `nats` (a uid of its own, its name's hash), leashed |
| Keeps | JetStream's streams in `/data/svc/nats`, 8 GB at most |
| Config | `nats/tls.crt` and `tls.key`; `nats/users.conf`, an `authorization` block of users with bcrypt passwords or nkeys and what each may publish and subscribe to |

```text
authorization {
  users = [
    { user: app, password: "$2y$10$...", permissions: { publish: ["app.>", "$JS.API.>", "_INBOX.>"], subscribe: ["app.>", "_INBOX.>"] } }
  ]
}
```

`htpasswd -nbB x PASSWORD | cut -d: -f2` makes the hash. Nothing
anonymous, nothing plain; payloads to 1 MB, connections to 1000.

## Checked

`make check-nats` makes a certificate and two users
([forms/nats/test/config](test/config)) and runs
[forms/nats/test/checks](test/checks) with the `nats` client, which the
DEV build carries: a message goes round over TLS; anonymous, a wrong
password and a plain connection are refused; a user cannot use another's
subjects; a stream takes a message and keeps it on `/data`; monitoring
answers on loopback alone.
