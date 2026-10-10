# A university's machines: the top ten uses

Built, 2026-10-10. Nine of the ten uses have a form. Notebooks
(`jupyterhub`) are not built: they wait on a seat count, and on
`instances` for a service.

## Summary

The ten things a university stands a VM up for, on a network full of
people who are not its administrator. Each gets a form whose defaults
a first visitor cannot claim.

## Background

[startup.md](startup.md) is a few engineers; [self-hosting.md](self-hosting.md)
a household; [corporate.md](corporate.md) a company behind its firewall.
A campus is all three at once, and its users arrive already able to
read the internal network. The breaches are a Moodle the first visitor
installed, a wiki the world can edit, and a notebook server that runs
student code as the hub.

A form need not wait for Wolfi. melange builds from a pinned source,
and `image:` runs a project's OCI image ([oci.md](oci.md)).

## Goals

- Each use has a form or a bundle passing `make check-NAME` and
  `check-shellfree-NAME`, its check ending in the attack its defaults
  refuse.
- The administrator comes from the config, before the port opens.

## Non-Goals

- Research clusters, GPUs and batch schedulers.
- Bulk mail to applicants. `mox` is the department's own mail.
- Student code as root. Notebooks, when built, are fixed unprivileged
  seats, not a process the hub starts.

## Detailed design

| Use | Forms | State |
| --- | --- | --- |
| Courses | `moodle` | built |
| Lab notes | `mediawiki` | built |
| Surveys and research data | `limesurvey` | built |
| Papers | `overleaf` | built; x86_64 only |
| Lectures | `galene` | built |
| Sign-on, including SAML | `keycloak` | built |
| Notebooks | `jupyterhub` | not built |
| The department's mail | `mox` | built |
| Files | `nextcloud` | built; [self-hosting.md](self-hosting.md) |
| Code | `gitea` | built |

**Notebooks.** Seats would be services laid down at build, `seat-1` to
`seat-N`, each its own user and Landlock domain. The hub, unprivileged,
only routes. N wants `instances` on a service, or a generated
`form.yaml`; forty seats was the suggestion. Neither is decided, so
the form is not here. Native extensions fail: `/data` is `noexec`.

| Form | Defaults; its check's attack |
| --- | --- |
| `moodle` | no sign-up, no guest, no plugin from the web; a plugin install |
| `mediawiki` | strangers cannot read, edit or sign up; an anonymous edit |
| `limesurvey` | plugins from the image alone; a plugin ZIP upload |
| `overleaf` | admin from the config; TeX `shell_escape` restricted; `\write18` |
| `galene` | rooms from the config, passwords hashed; a join with a wrong one |
| `keycloak` | admin from the config, sign-up off; a token with a wrong password |

## Drawbacks

- Moodle, Keycloak and Overleaf are heavy first boots: hundreds of
  tables, or a 3 GB image copied twice for the compiler.
- Overleaf's compiles share one user, as upstream's Community Edition
  does. Sandboxed compiles are the paid edition.

## Alternatives Considered

**Jitsi** for lectures: several services and a TURN of its own. Galène
is one program, and UDP 10000 is the only extra port.
**Shibboleth** for federation: Java plus a container of scripts.
Keycloak speaks the SAML a federation wants, and is one service.
**JupyterHub on the host:** the hub would start processes as root.
Fixed seats do not.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A first visitor claims the site | admin from the config, before the port opens |
| A plugin or a TeX document is code | plugins off, or from the image; `\write18` restricted, compiler apart |
| A wiki is the world's | strangers cannot read or edit until a setting says so |
| A forged Host sends a reset link elsewhere | Keycloak's issuer is the configured URL alone |

## Reliability Considerations

- LimeSurvey refuses tables newer than the image, so a rolled-back
  slot cannot damage them. MediaWiki runs `update.php` only when the
  code changes.
- Overleaf publishes no Arm image, so the form is `archs: [x86_64]`.
