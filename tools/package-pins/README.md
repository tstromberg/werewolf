# package-pins

## Summary

Promote a clean packages checkout into Werewolf's source lock after verifying
signed publication records for both native architectures. Uses the Go standard library.

## Background

Source updates and package publication finish separately. A consumer pin must wait
for every locked context, including subpackages, to reach the signed feed.

## Goals

Verify publication, then update the application source commit and content digest.
Leave the previous lock intact if any context is not ready.

## Non-Goals

Build packages, refresh upstream versions, hold signing keys or merge PRs.

## Detailed design

From the Werewolf root, with Go 1.27 or newer:

```sh
go -C tools/package-pins test ./...
go -C tools/package-pins run . --root ../.. --packages ../../../packages
go -C tools/package-pins run . --root ../.. --packages ../../../packages --write
```

The default package path is relative to the program's working directory. Supply
an absolute `--packages` path when the checkout is elsewhere. `--root` names the
trusted Werewolf checkout, including its publication key and source lock.

Every signed `contexts/NAME/current.json` must match the candidate's build input
hash and contain every APK and index for aarch64 and x86_64. Only then can `--write`
atomically replace the lock. Unchanged context content produces no update.
The hardened-packages entry stays fixed.

## Drawbacks

One failed native build delays the complete snapshot.

## Alternatives Considered

Staged publication records precede feed updates and cannot prove readiness.

## Security Considerations

The trust key is reviewed in Werewolf. Candidate files are never executed.
The tool needs no GitHub, R2 or signing credentials.

## Reliability Considerations

Unit tests cover signatures, partial publication, subpackages, transactional
failure and digest compatibility. See the
[design](../../docs/design/package-promotion.md) for workflow setup and merge gates.
