# Security

werewolf exists to be attacked and hold, so we want to hear about every way it doesn't.

## Reporting a vulnerability

Report it privately through GitHub: on the repository's **Security** tab, choose **Report a vulnerability**. Please don't open a public issue or pull request for it.

Include what you can: the form and release (or commit), what you did, and what happened. A proof of concept helps.

We aim to acknowledge a report within three days, and to agree with you on a fix and a disclosure date. We credit reporters who want credit.

## Scope

In scope:

- werewolf images: every form in `forms/`, its programs (`cmd/`), and the boot chain.
- Releases and updates: signing, manifests, the updater.
- `howl`, and `bite`.

Out of scope: bugs in upstream packages (Wolfi, Alpine's kernel) that werewolf doesn't make worse; report those upstream. If werewolf's hardening fails to contain one, that part is in scope.

## After a fix

Fixes to werewolf's own code are published as advisories in [release/advisories](release/advisories), which machines read to decide how soon to update ([docs/design/update-policy.md](docs/design/update-policy.md)). The design behind werewolf's defenses is in [docs/security.md](docs/security.md).
