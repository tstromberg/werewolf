# Form variants

A variant adds packages or changes services in an existing form. Select compatible
variants together; argument order does not affect the result.

```sh
howl run --with postgresql --variant vector --ssh
howl create database --with postgresql --variant ssh,vector
```

Both commands select PostgreSQL with pgvector and operator SSH. Repeat `--variant`
or use commas. Duplicate names are ignored; unknown or conflicting variants fail.
Build, pack and test accept the same selection.

Run a combination's integration checks with `howl test --with postgresql --variant
ssh,vector`, or `make check-postgresql VARIANTS=ssh,vector` from the checkout.
Each selection keeps separate build, lock and test output paths.

## Definitions

Declare workload variants inside the form's existing `form.yaml`:

```yaml
variants:
  vector:
    description: Vector search with pgvector
    packages: [pgvector-18]
```

Only selected variants affect the image. Packages accumulate; services replace
whole declarations. Two variants replacing one service differently conflict.
A variant cannot change `base`, declare instance `users`, or nest `variants`.
A form exposes its own definitions; dependency variants are not inherited.
Descriptions are optional single lines. `howl forms postgresql` shows them beside
variant names; `--published` reads descriptions from the signed catalog. JSON output
includes a `variant_descriptions` object. SSH is always described as "SSH access".
Search also matches variant names and descriptions: `howl forms pgvector`.

## SSH

Every form offers `ssh` through shared code; forms cannot redefine it.
`--ssh` is shorthand for `--variant ssh`. Forms with operator SSH reuse it.
Bastion uses the same listener with a destination allowlist and refuses remote root
login. Administrators log in as themselves before using local SSH-backed `su`.
`--dev=ssh` remains a separate development facility.

SSH adds no administrator grant. Declare `users.NAME.admin: true` for a person
who may use SSH-backed `su`. This manages membership in `wheel`; fresh root-key
authentication remains required. Automatically added login accounts are not admins.

## Updates

A published combination has its own signed channel. Automatic updates preserve
its selected variants; a missing release never substitutes the base image.
`howl forms --published` reports available combinations. Source builds support
compatible combinations, but need a publisher and channel for automatic updates.

Changing variants on an enrolled machine requires a new deployment. Repeated
run/create refuses that change before replacing the machine or its configuration.
Existing deployments without variants keep their original channels.
