# Form variants

**Status:** Pending as of 2026-10-27

Forms declare combinable variants in `form.yaml`; every form implicitly offers `ssh`.

## Background

MariaDB and Valkey have separate local and TCP forms; Open WebUI and Immich both add
pgvector to PostgreSQL. Variants let authors express these differences in one form.
Protected updates install [complete signed
images](../implemented/independent-updates.md), so each published combination needs
an update channel that preserves its selected features.

## Goals

- Define workload variants inline and supply SSH through shared code.
- Combine compatible variants independently of selection order.
- Preserve selected features through automatic updates and rollback.

## Non-Goals

- Publishing every possible combination or installing extensions at runtime.
- Switching update channels, database major upgrades or arbitrary service patches.

## Detailed design

A variant adds packages or changes service declarations in an existing form.
For example, PostgreSQL's `form.yaml` can include:

```yaml
variants:
  vector:
    description: Vector search with pgvector
    packages: [pgvector-18]
```

`howl run --with postgresql --variant vector --ssh` selects `[ssh, vector]`.
`--variant` accepts repeated or comma-separated names; `--ssh` adds `ssh`.
Sort and deduplicate names; reject unknown names. Names follow form grammar.
Reserve `ssh` for shared code. Each form exposes its own variants and descriptions.
Variant definitions cannot change `base`, declare `users`, or contain `variants`.

Apply selected variants after composing the base form and its dependencies.
Packages accumulate; a service replacement supplies the entire declaration.
Two variants may add packages. Different replacements of the same service conflict,
including replacements brought in through dependencies. Other conflicting settings
also fail the build; argument order never resolves a conflict. Validate the resulting
accounts, ports and policies, adding variant weaknesses to the form's declarations.

**SSH.** Shared code supplies operator login using `sshd` and `ssh-su`.
Bastion uses that service with controlled SSH egress, not a separate listener.
Remote root login is refused on bastion; administrators log in as themselves.
Destination restrictions cover SSH forwards and connections from user processes.
`admin: true` adds a person to `wheel`; only those people may use SSH-backed `su`.
Enforce membership beyond the wrapper, retaining fresh authentication with root keys.
Reuse existing login policies; `--ssh` grants no `admin` and disables no protections.
`--dev=ssh` stays separate. Existing bastion deployments need explicit migration.

**Updates.** Store the form and sorted variants separately in signed metadata,
machine records, locks, caches and release evidence. Verify downloads against both.
Keep existing channels for forms without selected variants. Other channels use paths
such as `boot/v1/postgresql/variants/ssh,vector/qemu/ARCH/latest.json`.
The channel identity includes the path through the provider (`qemu` here).
Existing channel-digest, TPM collision and release-index checks still apply.
Updates follow the selected channel and never substitute the base image.
Older metadata without a variant list describes a form without selected variants.
Refuse variant changes on an enrolled machine: they require a different channel.

**Publication.** Release configuration lists supported workload combinations.
Automatically build and test each with and without SSH. Every form supports local
SSH builds; vendor updates require published channels for the full form catalog.
`howl forms --published` reports available combinations. Unavailable downloads fail;
a local build requires an explicit request. Build, pack, test and run/create use the
same variant selection rules. Existing named forms and their channels remain valid.

## Drawbacks

SSH roughly doubles image builds. Service replacements repeat declarations;
variants cannot remove inherited permissions.

## Alternatives Considered

- Separate forms repeat definitions; `postgresql+ssh` mixes form and variant names.
- SSH in every image reduces builds but installs shell software even when unselected.
- Signed extensions require new verification, composition and atomic rollback rules.
- Applying variants in argument order makes service policy depend on that order.

## Security Considerations

A valid signature for another variant or the base image cannot satisfy a request.
SSH must preserve workload confinement, restricted listeners and authentication.
Check the final image's security posture, including its added shell and login access.

## Reliability Considerations

Each combination needs ongoing releases; abandoning one strands its machines.
More builds can delay security fixes, so one failed target must not block the others.
Failed publication retains the last good release and reports its age. Broken SSH can
leave a healthy workload inaccessible; release health must include working login.
