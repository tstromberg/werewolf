# A catalog of forms: the top 25 uses of a locked-down VM

Proposed, 2026-10-07. Tiers 1 and 2, ten forms in forms/, built
2026-10-08; of tier 3, bundles (`with:`) and `ruby`, and `miniflux`,
`prometheus` and `loki` 2026-10-10.

## Summary

Twenty-five things people stand a Linux VM up for, each a form: one Wolfi
package or melange recipe, leashed, with the most secure defaults that
leave it usable and a check that tries the attack those defaults stop.

## Background

A form is a verified read-only image whose services are leashed
([docs/forms.md](../forms.md)). Most self-hosting serves other people,
where a machine that cannot be taken over matters most. What Wolfi ships
sets the cost: on 2026-10-07 haproxy, unbound, grafana, mattermost and
teleport brought bash (`prune`), mariadb and postfix perl; Mastodon,
Vaultwarden, Miniflux, Immich and Matrix were not in Wolfi; most others
were clean, and nsd, coredns, dnsmasq, zot, meilisearch, clickhouse,
memcached and syslog-ng would fit when asked.

## Goals

- Every form boots under `make check`, shell-free where it can, with
  checks ending in the attack its defaults refuse.
- No form waits for its first visitor to claim it, serves a control
  interface on the network, or starts a program it did not declare.

## Non-Goals

- Machines that run arbitrary code (Kubernetes nodes, CI runners).
- A household's machine: Nextcloud, Immich and the rest of the top ten
  are [self-hosting.md](self-hosting.md)'s.
- Packaging for Wolfi. A recipe stays with its form until Wolfi takes it.

## Detailed design

**Defaults.** Those of [service-forms.md](service-forms.md), such as a
limit under the leash's, and two more. Performance: workers from the
CPUs, pools sized to `memory`, `sendfile` and HTTP/2, since a slow
locked-down machine gets replaced. TLS in front, once: an HTTP form
serves plain HTTP behind `caddy` or a balancer; an edge (`caddy`,
`mosquitto`, `nats`) takes its certificate from the config or `step-ca`.

**Built**: nineteen of these forms, listed in docs/forms.md; their
READMEs, forms/README.md and test/checks hold what tiers 1 and 2 taught.
**Proposed**, besides `mastodon` ([mastodon.md](mastodon.md)):

| Form | Defaults; its check's attack | Waits on |
| --- | --- | --- |
| `minecraft` on `jre` | whitelist, `online-mode`, no RCON or query port; a join off the list | a stand-in jar, as Mojang's cannot ship |
| `mattermost` | no open sign-up, plugins off (a plugin is code); a plugin upload | its first-run program |
| `jellyfin` (.NET) | no DLNA, discovery or remote metadata; the wizard after setup | built 2026-10-10: jellyfin-setup completes the wizard on loopback before Caddy starts; media over ssh (forms/jellyfin) |
| `miniflux` | admin from the config; a feed on loopback (SSRF) | built 2026-10-10 (forms/miniflux) |
| `unbound`, `wireguard`, `chrony` | UDP; chrony an NTS-fed server, `cmdport 0` | `listen udp`; chrony `capability time` |
| `mariadb-local`, `mariadb-tcp` | perl in its closure | `mariadb-init`, as `pg-init` |
| `prometheus`, `loki` | admin API and remote write off; no `node_exporter` in Wolfi | built 2026-10-10: prometheus-setup writes the targets, so no `render ... as list`; Loki behind Caddy, which has its one user |

**What they teach the base.** Built: bundles, `ruby` (4.0), `exec` with
a `run` list (gitea's hooks are Zig), `cpu WEIGHT`, the first-run
pattern ([cpu-and-first-run.md](cpu-and-first-run.md)), and timed jobs,
which a form gets by taking the `cron` form
([forms/cron](../../forms/cron/README.md)). Proposed, in order:

| Improvement | For |
| --- | --- |
| `listen udp`: Landlock cannot bind UDP, so fence's rule is all of it | wireguard, unbound, chrony |
| `capability NAME` beside `CAP_NET_BIND_SERVICE`, also an allowance | chrony, dnsmasq |
| `prune` of a tree (`usr/src/wordpress/.git`, 58 MB); the updater removes files only | wordpress |
| `config NAME PATH oneline`: no trailing newline | openbao, wordpress |

## Drawbacks

- A form can loosen with a new upstream default; only posture and its
  attack check catch that. A recipe's pin is its supply chain.
- Bundles make a form a graph. The build refuses a repeated user or id,
  but only howl's ad-hoc generator refuses two forms on one port.
- The clock is the host's at boot; a pause or migration leaves it behind
  until the next, breaking TOTP and signed requests. The fix, when needed,
  reads the host's PTP clock (`ptp_kvm`, `ptp_vmclock`): no network.

## Alternatives Considered

**Containers on a host form**: each brings the userland, shell and
updater forms exist to remove. **Only infrastructure forms**: the
defaults (sign-ups closed, hooks off) are what people get wrong.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| An application fetches from anywhere | `connect tcp/443` only; fence names ports, not hosts (open) |
| A failed first-run leaves a wizard open | the port opens only after `before` succeeds |
| A recipe's upstream is compromised | sources pinned by sha256; the image is signed |
| A bundle's service reaches another's socket | own users; sharing is a declared group |

## Reliability Considerations

- Open: the build does not compare a bundle's memory limits with the
  machine's; howl prints the sum for an ad-hoc form.
- `/data` survives a power cut (check-persist); worlds and media need the
  same check. A form whose upstream is away should refuse, never crash.
