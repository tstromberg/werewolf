# Published package consumption

## Summary

Forms consume published, signed APKs by package name. Package sources and build
provenance belong to the publisher; image locks bind the installed package set.

## Background

The packages repository builds applications and hardened Wolfi replacements on
both native architectures and publishes signed feeds. Werewolf composes those
packages into forms and tests their behavior in images.

## Goals

- Build every built-in form without a sibling packages checkout.
- Resolve third-party dependencies from authenticated package feeds.
- Preserve exact package versions and checksums in image locks.
- Keep package production and form integration tests in their respective repos.

## Non-Goals

- Removing form-local recipes for Werewolf software and private development.
- Changing Wolfi or OCI update policies, package signing or feed verification.

## Detailed design

Built-in forms name dependencies in `packages`. The `minimal` form supplies the
application and hardened package feeds and the existing trust configuration.
Plex selects `musl-werewolf`, `plexmediaserver` and `caddy`; Pi-hole selects
`pihole-curl` and takes Caddy through its existing form dependency.

Howl constrains covered package names to the authenticated feeds before resolving
dependencies. Image locks record exact versions for the selected architecture,
and installation verifies the packages against the lock and signing keys.
Release input snapshots keep both native builds bound to their resolved inputs.
Missing packages fail resolution; there is no fallback to sibling source builds.

CI checks out only Werewolf. It neither pins the packages source repository nor
promotes a repository-wide recipe snapshot. Package updates are tested through
the existing form build, native integration and image publication gates.

Form-local `melange/` recipes retain their existing source and build environment
snapshots for Werewolf software and private development. Their context identity
checks remain independent of any external package repository.

## Drawbacks

A new dependency must reach its signed feed before a consuming form can build.
Developers testing unpublished package changes must publish to a test feed or use
an explicit private development form.

## Alternatives Considered

A shared recipe commit couples unrelated applications and requires consumers to
check out sources they do not build. Source provenance remains useful in the
publisher's records without becoming an additional consumer lock.

## Security Considerations

Existing signature, checksum and authenticated feed checks remain mandatory.
Removing source checkout does not change the trusted keys or allow unsigned APKs.
Signing and publication credentials stay with their existing release workflows.

## Reliability Considerations

Image locks keep a build's resolved package set stable. Publication and form test
failures leave previous published images available. Regression tests require
built-in recipes to stay within their own forms and verify that Plex and Pi-hole
declare the packages their executables need.
