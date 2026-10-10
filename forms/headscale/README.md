# headscale

The `headscale` form is `prod` with Headscale 0.29, a coordination
server for Tailscale's clients, behind Caddy, which serves it over HTTPS
at your base URL. Nobody joins unasked, and nothing but the clients'
protocol reaches it.

| | |
| --- | --- |
| Listens | tcp/80 and tcp/443, Caddy's; Headscale on loopback alone; its CLI's socket in `/run/svc/headscale/run` |
| Sends | Tailscale's DERP map over HTTPS, the OpenID provider when one is named, DNS; Caddy's ACME requests |
| Runs as | `_oci-headscale` in Headscale's own image, and `caddy`, each leashed |
| Keeps | its SQLite database and Noise key in `/data/svc/headscale` |
| Config | setting `base-url` (required): Caddy's site and the URL clients use; files `headscale/oidc-issuer`, `oidc-client-id`, `oidc-client-secret`, `oidc-allowed-users`, `oidc-allowed-domains` (optional, lists space-separated) |

## Run your own

You need a domain name you can point at the machine, and for sign-ins,
an OpenID provider with a client for `https://hs.example.com/oidc/callback`.

```sh
mkdir -p config/headscale && cd config/headscale
echo https://accounts.example.com >oidc-issuer
echo headscale >oidc-client-id
printf '%s' 'the client secret' >oidc-client-secret
echo 'me@example.com you@example.com' >oidc-allowed-users
cd ../..
howl create tailnet --with headscale --on gcp --allow-from 0.0.0.0/0 \
	--config config --base-url https://hs.example.com
```

Point `hs.example.com` at the address howl prints. On each device,
`tailscale up --login-server https://hs.example.com` opens a sign-in at
the provider; an allowed user's device joins as that user.

## Defaults

- **No open registration.** A node joins with a pre-auth key, by its
  administrator's approval, or by an OpenID sign-in the config's lists
  allow (Headscale refuses one that is not on them, and one whose email
  is not verified).
- **No admin interface on the network.** Without TLS of its own
  Headscale serves gRPC on its socket alone, and the REST API takes only
  API keys; no metrics or debug listener.
- **Tailscale's relays**, as its clients use them (`derpmap/default`,
  refreshed every 3 hours); no relay of its own, which would need UDP.
- **MagicDNS** names under `tailnet.internal`, without taking over the
  devices' resolvers. No update checks, no logs sent to Tailscale.
- **Headscale's own image**, the 0.29 line, pinned by digest at each
  build ([oci.md](../../docs/design/oci.md)), its program run by leash
  and nothing else in the image.

## Drawbacks

- Open: without an OpenID provider there is no way in yet. Pre-auth
  keys, API keys and approvals come from Headscale's CLI over its
  socket, and the machine has no shell to run it; a setup step that
  makes them from the config needs Headscale running, which `before`
  is not.
- A new Headscale line (0.30) is a new tag in form.yaml; its config
  changes between 0.x releases.

## Checked

`make check-headscale` boots it with its test config
([test/config](test/config)), base URL `https://localhost`, for which
Caddy's own CA signs: Headscale is healthy behind HTTPS and plain HTTP
is redirected; it runs as `_oci-headscale` with no capability; its key,
database and socket are its own; nothing listens on the gRPC or metrics
ports; the API refuses no key and a made-up one; and Tailscale's own
client, with a made-up pre-auth key, is refused and gets no address.
`make check-shellfree-headscale` boots it as it ships, with no config:
Headscale parks, naming the setting; Caddy runs.
