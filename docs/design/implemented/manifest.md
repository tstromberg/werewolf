# One manifest: a machine from one YAML file

**Status:** Implemented
[2026-10-10](https://github.com/werewolf-linux/werewolf/commit/90d03718)

Designed 2026-10-09; phases 1–5 implemented 2026-10-10. Built on [adhoc](adhoc.md),
[custom-updates](custom-updates.md) and [howl-build](howl-build.md).
## Summary
A manifest is `form.yaml`; a named form is one others take by name. A lock pins
resolutions; packages update without changing policy.
## Background
Policy sat in five files and only `prod` updated; `lib/compose.zig` now serves both.
## Goals
- One reference alone runs that form unchanged; `-n` prints a manifest `-f` reads
  back.
- A matching input lock reuses package versions, form serials and OCI digests.
- Published forms follow releases, extra packages Wolfi, and `local-NAME` `howl
  apply`.
## Non-Goals

Inline files, timers, conditionals, doas, sudo, su, OS Login, changing disk or
address.
## Detailed design

**Keys and flags.** `--KEY VALUE` sets a scalar or appends to a list; `--updates off`
takes its value, and boolean flags such as `--users.NAME.admin` none. `-f FILE` reads
a manifest that flags layer over; a scalar set twice is refused. Host and updater
share one renderer for services, fence policy and accounts; people and secrets ride
in boot config.

| Key | Meaning |
| --- | --- |
| `base`, `with` | Form chain; every form's `with` counts; ad-hoc creation defaults to `prod` |
| `packages` | Additional Wolfi packages; form dependencies retain their own constraints |
| `services` | Named leash directives, replaced whole by name; `image` pins OCI, `link` reaches another service; listeners and connections derive fence policy |
| `users` | Named UNIX accounts with optional security keys; `admin` requires keys; boot config only, never the image |
| `updates` | `every`, `from`, `policy`, or `off`, which removes the updater and records the `updates-enabled` posture weakness; last declaration wins. `policy` is quoted JSON using [update-policy.md](update-policy.md) |
| `machine` | Top manifest only: hostname, ip, gw, dns, data-key, on, arch, size, allow-from, metadata-users; forwarded at creation, immutable on apply |
| `app` | Destination in the image; `--app DIR` supplies its source tree |
| `sshd`, `allow`, `prune`, `paths`, `programs`, `bastion`, `weaknesses`, `check` | Existing form policy; service setting and file flags supply boot config |

```yaml
# shop.yaml: howl create shop -f shop.yaml; howl apply shop.yaml --to ssh://deploy@host/srv/apk/shop
with: [sshd]
packages: [curl]
users:
  tom:
    keys: [sk-ssh-ed25519@openssh.com AAAAGnNr... tom@yubikey]
updates:
  every: 1h
  from: https://packages.example.com/shop
```

**The lock.** `build/lock/NAME[-dev][-published].lock.json` is apko JSON plus a
`werewolf` record: packages for both arches, form serials, image digests, app hash
and an input hash over local manifests, form chains, rootfs and app bytes, modes and
symlink targets, not mtimes or generated comments. Published forms are resolution
outputs, local fallback forms inputs. Matching inputs reuse exact versions, changed
inputs resolve again, and a failed resolution keeps the old lock. Kernel and
boot-loader locks are separate; `make clean` keeps locks and `make relock FORM=...`
refreshes them.

**Publishing.** Enroll by setting `updates.from` before creation. Howl packages
caller-owned forms and the staged app as `local-NAME`, signs the index with
`packages.rsa` in `$XDG_DATA_HOME/howl` and gives the machine its public key;
published forms stay dependencies, people and secrets stay out. Apply's package is
named for the file stem (`--name` overrides), `--app DIR` replaces the remembered app
source, and `-n` prepares without uploading; run it once after creation to seed the
repository. Uploads use HTTPS PUT or SSH (`--to`); machines fetch HTTPS without
credentials. One URL and one publisher per declaration: packages upload before the
signed index, an index holding versions absent locally is refused, and a revision
advances only when inputs change. History lives under `repositories/` there,
file-locked and kept across clean builds; back it up with the signing key and
`build/machines/NAME/declaration.json`.

**Updating and rollback.** A changed operator package is due at the next successful
package check, with no CVE-feed delay: the updater composes it into the other slot,
boots it once and keeps it only after commit, and a failed resolution keeps the
current image and fails `update-held`. An older declaration is never republished:
apply requests `slot-update try HASH`, which needs the parked slot to hold those
exact inputs, through `howl ssh` (QEMU, Firecracker, Lima) or
`/usr/lib/werewolf/slot-update try HASH` as root; without a hash, `try` boots
whatever is parked. Data and config stay as they are.

**Config transports.** GCP and Azure publish metadata live: people and root keys
change within the minute poll, other config at boot. AWS stops and starts to replace
user data; QEMU, Firecracker, Lima, bhyve and Proxmox swap the config disk on
restart, keeping image and data disks, and an image-only apply does not restart the
VM. A new machine map, address, platform, signing key or repository means a new
machine. Package and config publication are separate; retry a partial failure with
the same declaration. `machine.metadata-users: true` opts into GCP instance and
project `ssh-keys`; `block-project-ssh-keys: TRUE` excludes project keys. Expired or
malformed `google-ssh` keys are ignored, declared people take precedence, and
metadata grants neither admin nor root ([key
format](https://docs.cloud.google.com/compute/docs/connect/add-ssh-keys),
[project-key-control](https://docs.cloud.google.com/compute/docs/connect/restrict-ssh-keys)).

**Release and verification.** This is package format 4: publish its programs and
forms together before enrolling; format-2 machines need reinstalling. Tests cover
content invalidation, two-arch packages, signed indexes, stable revisions, config
merging and GCP expiry and precedence, `make check-gcp-metadata` the live GCP key
handling, and the lock fixture and QEMU SSH boots pass; other clouds and
apply/rollback await live tests.
## Drawbacks

The operator keeps a signing key and repository history; a lost key means a new
machine.
## Alternatives Considered

Without `updates.from`, local files are copied forward. Signed packages allow
intentional changes; forwarded agents would expose credentials.
## Security Considerations

Trusted keys authorize images; root can replace slots. Admin touch is proven at
login. Metadata supplies config, never images.

## Reliability Considerations

Commit proves services are up, not that the application is right. Data and config
outlive rollback.
