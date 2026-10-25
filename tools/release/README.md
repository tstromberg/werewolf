# release

## Summary

`build/host/release VERB ARG...` builds, tests, signs and publishes werewolf's images
(`make build/host/release`). Each verb is one of the release scripts it replaced, with
their arguments, refusals and output bytes.

## Background

[form-images.yml](../../.github/workflows/form-images.yml) builds every published form
twice per architecture and provider, in the secure-boot and legacy-boot profiles, gates
the exact bundles and publishes the passing ones ([releases](../../docs/releases.md),
[form images](../../docs/form-images.md)). Its jobs run these verbs.

## Goals

- One host program; the data a person edits, [images.yaml](../../release/images.yaml).
- Records that are signed or published keep the bytes the scripts wrote them with.
- Every refusal is tested beside its code, with no network, gh, aws or howl.

## Non-Goals

- Building forms or booting machines: howl and the checks under test/ do that.

## Detailed design

| Verb | Job |
| --- | --- |
| `form-images matrix\|gates` | the build and lifecycle-gate matrices, as JSON |
| `form-images resolve ARCH SHARD SHARDS OUT` | a shard's locks, inputs and plan |
| `form-images build\|check\|gate ...` | the two copies, their comparison and tests, gates |
| `form-images export\|publish ...` | signed release assets; R2 objects and catalog |
| `legacy-images build\|check ...` | the legacy-boot profile from the same plan |
| `build-protected`, `authorize-protected` | one bundle; its withheld descriptor signature |
| `prepare-`, `export-`, `publish-protected` | admit, export and upload one bundle |
| `check-protected-download` | the public mirror serves exactly what was published |
| `protected-inputs`, `github-protected` | a package snapshot; the draft GitHub release |
| `create-protected-trust`, `with-boot-key`, `with-protected-keys` | key custody |
| `report-publishing-health` | one issue per failing main-branch workflow |

Run it with no verb for the usage. A verb exits 0, 1 when a target failed or a
refusal stopped it, or the child's status for the key wrappers.

[images.yaml](../../release/images.yaml) holds the published forms, boot profiles,
architectures with their build runners and providers, the forms each provider's
lifecycle gates test, the gate runners, shards, checks and the focused recovery
target. lib/form.zig parses it, refusing unknown keys and names.

`json.zig` writes what Python's json module wrote: sorted keys and no spaces for
records, its default style for the workflows' outputs, ensure_ascii escapes and float
repr. `catalog.zig` is the signed catalog and its pages, `notes.zig` inventories and
release notes, `boot.zig` howl's native admission and lib/boot-download.zig's floor,
`prepare.zig`, `exporter.zig` and `publish.zig` one protected bundle, `plan.zig`,
`candidates.zig` and `publication.zig` the form-images jobs, `legacy.zig` the
legacy-boot profile, `keys.zig` key custody. `sys.zig` is the host: programs, files,
HTTPS; `fixture.zig` gives tests a fake for programs and downloads.

## Security Considerations

A key is checked against its committed certificate before any child runs, written
0600 in a 0700 directory, and removed on every exit; SIGTERM, SIGINT and SIGHUP go to
the child first, which has ten seconds before SIGKILL. Diagnostics never echo a
secret. Nothing is signed before native admission and lifecycle evidence for that
exact bundle, provider and architecture; immutable objects precede heads.

## Reliability Considerations

Every failure names its program and target, and one target's failure never stops the
others. A store interrupted mid-publication is recovered by its signed receipt and
never loses its floor; a retry reuses the bytes an earlier attempt signed.
`make _test/tools/release/release.zig` runs the tests, real openssl, zstd and qemu-img
included.
