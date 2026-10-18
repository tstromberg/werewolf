# Published package source promotion

## Summary

Promote immutable application source pins only after signed native packages are
published. Test each proposed pin with Werewolf's existing form checks before merging.

## Background

The packages repository tracks stable upstream releases and publishes signed APKs
to R2. Werewolf pins source commits and context hashes separately. A source change
alone does not prove that both architectures are ready for consumers.

## Goals

- Move the WordPress SQLite plugin from vendored source to a tracked package.
- Verify all locked application contexts against signed publication records.
- Update one immutable commit and context digest through a tested PR.
- Keep the old pins when publication or form checks fail.

## Non-Goals

- Changing Wolfi, OCI or hardened runtime update policies.
- Rebuilding or signing packages from the consumer's update job.

## Detailed design

The hourly `package-pins.yml` workflow checks out packages main at one commit.
`tools/package-pins` is a Go program with no third-party dependencies. It refuses a
dirty candidate and hashes each locked context, including file modes. It also
computes the publisher's input hash, which includes the shared builder and tool lock.
Tests compare both encodings with the existing Python implementations.

For each context, the tool verifies `contexts/NAME/current.json` with Werewolf's
reviewed `release/application-packages.pub` key. The candidate's input hash must
match. Both architectures must list every APK, including subpackages, and an index.
The publisher advances this signed record only after both feed indexes are updated;
staged build records alone cannot authorize promotion. An unchanged context may
reuse an earlier release whose inputs match exactly.

Only after every context passes does the tool atomically replace the application
source's commit and digest in `release/package-sources.json`. Other source entries
stay fixed. Commits with identical context content do not create update churn.

A separate job receives only the generated lock, then mints a repository-scoped
GitHub App token and opens `auto/package-pins`. There is at most one open update PR;
the scheduler leaves an existing PR and its CI results alone. The ordinary check
workflow merges only after unit tests, all x86_64 form boots and any configured
arm64 checks pass. It requires the PR to change only the source lock and merges
with `--match-head-commit` so a newer untested head cannot slip through.
Other CI workflows must also pass before the merge job requests an App token.

The App token lets the PR trigger ordinary CI and its merge trigger publication
workflows. Install a GitHub App on Werewolf with Contents and Pull requests write
permissions. Configure `PACKAGE_UPDATE_APP_ID` as a repository variable and
`PACKAGE_UPDATE_APP_PRIVATE_KEY` as a repository secret. Without the variable,
verification still runs but the workflow cannot propose or merge updates.

## Drawbacks

One unpublished context holds the whole snapshot back. The failed context appears
in the workflow log; its build must be repaired before promotion resumes. A failed
consumer PR stays open for diagnosis. Close it to request a fresh candidate.

## Alternatives Considered

Mutable branch pins cannot reproduce a reviewed build. Updating pins directly on
main skips consumer testing. A second publication service duplicates the existing
signed readiness records. Reimplementing native package builds in Werewolf would
also duplicate their release gates.

## Security Considerations

Candidate sources are read as data and never executed by the promotion tool. The
trust key comes from Werewolf, not the candidate. HTTPS, bounded downloads and RSA
signatures protect readiness records. Signing and R2 keys stay with the publisher;
the PR credential is available only after verification, in a separate job.

## Reliability Considerations

No lock bytes change on partial publication, bad signatures or missing inputs.
The normal CI tests the exact proposed pin. A merge race refuses the update;
published immutable APKs and the previous lock remain available.
