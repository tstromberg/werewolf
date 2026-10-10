# Self-hosting: the top ten uses

Proposed, 2026-10-10. Of the ten uses, five are served today; five
wait on the forms proposed here.

## Summary

The ten things open-source enthusiasts most often run on a VM or a
computer of their own: media, photos, files, passwords, their network's
DNS, their home. Each gets a form, with defaults no visitor can claim.
[forms-catalog.md](forms-catalog.md) is for a machine serving strangers.

## Background

The catalog chose from what Wolfi shipped and left out Nextcloud, Immich
and Matrix as several daemons each; bundles (`with:`), built for
Mastodon, answer that. By our reading of self-hosters' surveys and lists
(r/selfhosted, awesome-selfhosted), the ten below lead, in no order.

A household's machine differs from a server: its data is the most
private there is, its users are on a LAN or a tailnet, and it talks to
devices (TVs, phones, sensors) over UDP, multicast and USB.

## Goals

- Each of the ten has a form or a bundle, `make check`ed, its check
  ending in the attack its defaults refuse.
- No two uses take the same port, so one form of each shares a machine.

## Non-Goals

- Download automation (the *arr suite, torrent clients): popular, but
  scrapers of others' sites; forms outside this tree may add them.
- GPUs: transcoding and machine learning run on the CPU until a form can
  carry a device (forms/ollama says the same).

## Detailed design

| Use | Forms | State |
| --- | --- | --- |
| Media streaming | `jellyfin` | proposed in the catalog |
| Passwords | `vaultwarden` | built |
| Files and sync | `nextcloud`, `syncthing` | proposed |
| Photos | `immich` | proposed |
| Network ad-blocking | `pi-hole`, `adguard-home`, `blocky` | proposed |
| Home automation | `home-assistant` with `mosquitto` | mosquitto built |
| Remote access | `tailscale`, `wireguard`, `headscale` | tailscale built; wireguard in [service-forms.md](service-forms.md) |
| Code | `gitea` | built |
| Monitoring | `gatus`, `prometheus`, `loki`, `grafana` | grafana proposed |
| Local AI | `ollama`, `open-webui` | ollama built |

The forms neither the catalog nor service-forms.md carries:

| Form | Defaults; its check's attack | Waits on |
| --- | --- | --- |
| `nextcloud` on `php`, with `postgresql`, `valkey`, `cron` | admin from the config; `config.php` and apps on `/data`, its own code read-only (web updater off); a web update of Nextcloud | its first-run program (`occ maintenance:install`) |
| `syncthing` | GUI on loopback behind `caddy`, its password from the config; no UPnP or usage reports; the GUI without a password | `listen udp` for QUIC and LAN discovery; TCP 22000 works without |
| `immich` with `postgresql`, `valkey` | the server and machine learning as two users; admin from the config, so no first visitor claims it; models from a public HTTPS host alone; the admin sign-up page | recipes (Node, Python); VectorChord for PostgreSQL |
| `pi-hole` | its web password from the config; DHCP off; answers private ranges alone (no open resolver); the API without a password | `listen udp`; gravity's shell scripts, under busybox `sh` or bash, a weakness declared |
| `adguard-home` | its YAML written from the config, the admin's hash in it, so no setup wizard; DHCP off; private ranges alone; the UI behind `caddy`; the wizard's install endpoint | `listen udp`; a recipe |
| `blocky` | blocklists and DNS-over-TLS upstreams from the config; answers private ranges alone (no open resolver); no API on the network; a query from a public address | `listen udp` |
| `home-assistant` | owner from the config, no onboarding; discovery off; the onboarding page | a recipe and its integrations' packages; multicast; a USB radio, or a network Zigbee coordinator through `mosquitto` |
| `headscale` | no open registration: pre-auth keys from the config; gRPC and metrics on loopback; TLS by `caddy`; a node registering without a key | a recipe |
| `grafana` | admin from the config; sign-up and anonymous access off; Prometheus and Loki provisioned when bundled; the API without a login | `prune` of the bash its package brings |
| `open-webui` with `ollama` | admin from the config, sign-up off; tools and functions an admin's alone, each being Python the server runs; a user's function upload | Python's closure; its first-run program |

The next five: backups (restic's `rest-server --append-only`; its check
deletes a snapshot, and fails), chat (Matrix by `continuwuity`),
documents (Paperless-ngx), file shares (Samba), games (`minecraft`).

**Plugins** (Nextcloud apps, Home Assistant integrations, Grafana
plugins, Open WebUI functions) install at run time into `/data`, as each
application does. One that brings a native program fails, as `/data` is
`noexec` and signed execution will refuse it; if it breaks, it breaks.

**What they teach the base**, beside `listen udp`:

| Improvement | For |
| --- | --- |
| a `multicast` allowance: mDNS and SSDP on the LAN alone | home-assistant, syncthing, jellyfin |
| a device allowance: a USB radio, a GPU, named in form.yaml | home-assistant; jellyfin and immich, later |
| a library disk: media and photos outgrow `/data`; a second disk, read-only to its readers | jellyfin, immich |

## Drawbacks

- These are the heaviest forms: Immich, Home Assistant, Nextcloud and
  Open WebUI each bring a runtime and hundreds of packages, recipes kept
  here until Wolfi takes them.
- Some plugins will not run: a Home Assistant integration whose Python
  package has a compiled module, a Grafana backend plugin.

## Alternatives Considered

**Blocky alone**, the strictest ad-blocker: one file, no admin
interface. People choose Pi-hole and AdGuard Home for their interfaces,
so all three ship. unbound with blocklists needs what Blocky already is.

**Upstream container images** (`image:` in form.yaml,
[adhoc.md](adhoc.md)) run Home Assistant and Immich today, as their
projects ship them, with the userland and shell forms exist to remove.
They stay for ad-hoc machines.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A household's most private data on one machine | each service its own user and `/data/svc` directory; `/data` encrypted ([data.md](../data.md)) |
| A first visitor claims the app (Immich, Open WebUI, Jellyfin, Home Assistant) | owner from the config, made before the port opens ([cpu-and-first-run.md](cpu-and-first-run.md)) |
| A plugin is code | it runs as its application's user, under its leash; native code is refused |
| LAN-only services reached from the internet | served to the LAN or a tailnet; `caddy` or `oauth2-proxy` in front of anything public |

## Reliability Considerations

- Photos and passwords are what people cannot lose: `/data` survives a
  power cut, but backups are theirs ([data.md](../data.md)), hence
  `rest-server` first among the next five.
- Immich's machine learning and Ollama each want gigabytes; as in the
  catalog, nothing yet compares a bundle's limits with the machine's.
- An upstream away degrades, never stops: the ad-blockers serve their
  last lists, Immich runs without its models.
