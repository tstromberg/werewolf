# rules-fetch

## Summary

rules-fetch downloads the Emerging Threats Open ruleset for Suricata 8 into
`/data/svc/rules-fetch` and refreshes that cache daily. Suricata reads the cache. It
does not fetch, and it cannot rewrite the files.

## Background

The engine's package ships protocol rules and no signatures. `suricata-update` is
Python, which this form does not keep. The ruleset changes every day, so the cache is
a download, not a file in the image. The data partition is where that download lives.

## Goals

- Suricata loads Emerging Threats Open, the engine's protocol rules, and the marker.
- A failed download leaves the previous cache, or the protocol rules, and the engine
  still starts.
- The running engine has no network and does not own the cache.

## Non-Goals

- Reloading a running engine. The unix command socket stays off, so a refresh is
  picked up at the next start.
- A pinned checksum. The tarball is replaced in place; pinning it would refuse the
  refresh.

## Detailed design

`rules-fetch` runs as `_rules`. Its directory is mode 0711 and the files are mode
0644, so Suricata can open a path and cannot replace it. Each pass copies
`/usr/share/suricata/rules/*.rules` and merges
`/usr/share/suricata/classification.config` with the feed's classifications, keeping
the image's short name where both define one. It writes `ready` before the download.

The feed is
`https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz`, at most
32 MiB. The tar may contain only regular files under `rules/` whose names do not
climb out of that directory. `rules/*.rules` become `emerging.rules`.
`rules/classification.config` is kept beside the tarball and merged on the next pass.
A link or a `..` name rejects the archive.

`rules-fetch wait` is Suricata's `before`. It returns when `et-ready` appears, or
after 25 seconds, so a slow feed does not hold the engine past that. The engine's
pledge has no `inet`. Fence allows `_rules` TCP 443 to public addresses, and DNS.

## Drawbacks

The first start loads signatures only when the download finishes within those 25
seconds. A later refresh sits on disk until Suricata starts again.

## Alternatives Considered

- `suricata-update`. It is Python, and the form drops Python so the engine's leash
  cannot run it.
- Letting Suricata fetch. The process that sees packets would then be a network
  client, and it would own the files it loads next time.
- Vendoring the rules in the image. They would be stale on the day they were copied.
