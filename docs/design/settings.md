# Settings

Built, 2026-10-07 (lib/settings.zig, cmd/service-config, leash and howl
pack): the guest's half of [cli.md](cli.md). The bastion has taken none
since 2026-10-08 ([forms/bastion](../../forms/bastion/README.md)).

## Summary

A service file declares its per-machine settings, each of one of ten types,
and a format to render them in: `env`, `json` or `conf`. One program,
`service-config`, renders any service's settings from the config tar,
unprivileged, in its leash; `howl pack` checks them with the same code.
The syntax, types and formats are in [forms.md](../forms.md#settings).

## Background

The config tar ([cloud.md](../cloud.md)) holds what is particular to one
machine. Secrets are files that leash copies to a service. *Settings* are
the rest: values that differ per machine but are not secret, such as a
router's routes. [service-forms.md](service-forms.md) first had each daemon
include a fragment from `/run/config/NAME`, which makes the tar's writer
an author of the daemon's configuration: a fragment can say
`PermitOpen any` as easily as a destination. The first `service-config`
had a case per service instead: a parser of untrusted input in every image.

## Goals

- `service-config` names no service; a setting is one line, with no Zig.
- Host and guest validate with one function per type, in `lib/`.
- A setting cannot add a directive, key or variable the image did not
  declare, so the image's review still describes the machine.

## Non-Goals

- Secrets, which stay files; a template language; a path into a list;
  every daemon's syntax (a format is added when a form needs one).
- Changing settings on a running machine: the tar changes with a reboot.

## Detailed design

The image declares names and types; the tar gives only values. Defaults
stay in the daemon's configuration in the image, where the reviewer reads
them, so an absent setting is absent from the output. `cidr` refuses `/0`
(an exit node is another form), and `url` a user or password, so a secret
does not ride in a setting by habit.

Nothing is quoted: the build refuses a type that could hold its format's
delimiter, and Zig's serializer writes `json`. `json from` replaces only
the declared keys of the image's file, so its policy (Tailscale's
`locked`) passes through untouched.

At each start leash runs `service-config` as the service, before any
`before` line, with the image's declarations on its stdin
([cmd/service-config](../../cmd/service-config/README.md)). A refusal
parks the service with one line naming the setting and reason, never the
value, which `howl pack` already showed its user.

Ten forms use settings, `json from` in tailscale, openbao and step-ca.
Open: `conf` has had no user since the bastion left. Waiting: unbound's
forward zones and clustered OpenBao's `retry_join`, which need a list of
objects that no type or format holds.

## Drawbacks

- A schema for service files, and more code in leash, which every service
  passes through.
- A `conf` include in the wrong place lets the image's default win
  silently; only the form's boot check sees it.
- Renaming a setting refuses old tars. On an A/B update the new slot fails
  and slot-keep boots the old ([updater.md](../updater.md)), so forms add
  settings and never rename them.

## Alternatives Considered

- **Fragments the daemon includes**: the tar's writer authors the service.
- **A renderer per service**: a parser per service, in every image and howl.
- **Templates**: an interpreter, which [shell-free.md](shell-free.md)
  removes, and escaping that varies per daemon.
- **leash renders as root**: root parses the tar's JSON, which privilege
  separation forbids ([programs.md](../programs.md)).
- **A JSON path language** (`retry_join[].leader_api_addr`): grows into jq.
- **YAML, TOML or properties**: no form needs them; Java reads `env`.
- **Defaults in the service file**: two places, and include order decides.

## Security Considerations

- Declarations come from the verified image, values from the tar. Policy
  is not a setting, so settings cannot widen it.
- Parsed as the service's user, in its Landlock rules, under a seccomp
  filter of ten calls, with at most 32 KiB of input. `PATH`, `LD_*`, and a
  key shadowing an `env` or `secret` line are refused.
- Rendered again at every start from root's copy, so a service taken over
  cannot keep a change to its rendered file past a restart.

## Reliability Considerations

- No state: rendered at every start, into a tmpfs.
- Fail closed and say why; service-config also logs the names it set.
- Tested by `lib/settings.zig`'s tests and by forms booting from their
  `test/config`. Open: the fuzz test of each type's parser, as planned.
