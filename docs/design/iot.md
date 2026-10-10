# IoT: one form, its schedule, its sources

Proposed, 2026-10-10. The form, `updates.from` and the policy file are
built. Their package waiting for the window, and a device that asks
only their server, are not.

## Summary

A manufacturer ships one form. Devices poll their server and install in
the window the form names; an exploited bug reboots within 15 minutes.

## Background

A plant flashes one image, phones home to its own server, and installs
in a window, a site at a time. The form, repository and window exist
([manifest.md](manifest.md), [update-policy.md](update-policy.md)).
Today a publish reboots on the next check, and the device also reaches
Wolfi, werewolf, Alpine and a tiers feed on GitHub.

## Goals

- The form is the disk they flash and the package every device takes.
- A publish installs in the window, including a device that was off.
- Update fetches go only to the manufacturer's HTTPS server.

## Non-Goals

- Microcontrollers, USB and GPIO ([lockdown.md](lockdown.md)).
- A device that must not reboot. Urgent has no setting.
- Cohort percentages. A channel is a `from` URL, baked at flash.
- Changing `from`, the signing key, or a static address after flash.

## Detailed design

**One form.** Its directory name is the product ([forms.md](../forms.md)).

```yaml
# gateway/form.yaml
base: app
services:
  gateway:
    exec: /usr/lib/app/gateway
    user: app
    pledge: stdio rpath wpath inet connect
    connect: [tcp/8883 tcp/443 udp/53 tcp/53 public]
updates:
  every: 1d
  from: https://updates.example.com/gateway
  policy: '{"window":"sun 01:00-04:00","high":"24h","medium":"28d","low":"90d","limits":{"high":"24h","medium":"28d","low":"90d"}}'
```

```sh
howl build --with ./gateway --app ./src --arch aarch64
howl create lab --with ./gateway --app ./src
howl apply gateway/form.yaml --name lab --app ./src
```

`build` is the disk the line flashes. `create` enrolls the key. `apply`
publishes `local-NAME` for every device of that form. The binary is in
the image; state is `/data/svc/gateway`. Secrets stay in boot config.

**The window.** `every` (5m to 7d) is the poll. `policy`, in UTC, is the
window and the cap on High, Medium and Low; a site's `--update-policy`
moves them, inside `limits`. Their package is due in that window, as
Low is, so Tuesday's publish installs Sunday. Today it reboots at the
check that sees it. Urgent still reboots within 15 minutes.

**Their server.** `updates.from` is the only repository, kernel and
tiers URL. It holds `local-NAME` (signed with `~/.howl/packages.rsa`)
and the Wolfi, werewolf and Alpine indexes CI copied after a boot,
each checked with that origin's key. Today the image lists those
upstreams, and tiers come from GitHub. A canary is another `from`;
promote by publishing the same package to the production URL.

## Drawbacks

Urgent reboots within 15 minutes of a device seeing the fix. Their
server is the outage domain, and a lost `packages.rsa` means new devices.

## Alternatives Considered

| Alternative | Why not |
| --- | --- |
| Reboot when the package is published | installs land during the day |
| Sign the base with their key | a leak forges Wolfi or werewolf |
| Percentages in the updater | a `from` URL is already a channel |

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Their key leaks | `local-NAME` only; origin keys still check the base |
| Their server withholds a fix | it cannot forge one |
| A site delays a reboot | `limits`; Urgent has none |

## Reliability Considerations

A failed commit boots the previous slot and is not installed again.
Back up `packages.rsa`, `~/.howl/repositories/` and the lab declaration.
