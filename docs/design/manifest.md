# One manifest: a machine from one YAML file

Designed 2026-10-09; phases 1–5 implemented 2026-10-10. Live apply verification remains before release.
Built on [adhoc.md](adhoc.md), [custom-updates.md](custom-updates.md) and [howl-build.md](howl-build.md).

## Summary

A manifest is `form.yaml`; a named form is one others take by name. A lock pins resolutions; packages update without changing policy.

## Background

Previously policy was split over five files and only `prod` updated. Host and updater now share `lib/compose.zig`.

## Goals

- One reference alone runs that form unchanged; `-n` prints a manifest `-f` reads back.
- A matching input lock reuses package versions, form serials and OCI digests.
- Published forms follow releases, extra packages follow Wolfi, and `local-NAME` moves by `howl apply`.

## Non-Goals

Inline files, timers, conditionals, doas, sudo, su, OS Login, changing a disk or address in place.

## Detailed design

**Keys and flags.** `--KEY VALUE` sets a scalar or appends to a list by `lib/form.zig`'s schema.
`--updates off` takes its value; boolean flags such as `--users.NAME.admin` take none.
`-f FILE` reads a manifest and flags layer over it; setting a scalar twice on the line is refused.

| Key | Meaning |
| --- | --- |
| `base`, `with` | Form chain; every form's `with` counts; ad-hoc creation defaults to `prod` |
| `packages` | Additional Wolfi packages; form dependencies retain their own constraints |
| `services` | Named leash directives, replaced whole by name; `image` pins OCI, `link` reaches another service; listeners and connections derive fence policy |
| `users` | Named people with security keys, optional `admin` or bastion destinations; boot config only, never the image; needs sshd or bastion |
| `updates` | `every`, `from`, `policy`, or `off`; last declaration wins. `policy` is quoted JSON using [update-policy.md](update-policy.md) |
| `machine` | Top manifest only: hostname, ip, gw, dns, data-key, on, arch, size, allow-from, metadata-users; forwarded at creation, immutable on apply |
| `app` | Destination in the image; `--app DIR` supplies its source tree |
| `sshd`, `allow`, `modules`, `prune`, `paths`, `programs`, `dev`, `bastion`, `weaknesses`, `check` | Existing form policy; service setting and file flags supply boot config |

```yaml
# shop.yaml
with: [sshd]
packages: [curl]
users:
  tom:
    keys: [sk-ssh-ed25519@openssh.com AAAAGnNr... tom@yubikey]
updates:
  every: 1h
  from: https://packages.example.com/shop
```
```sh
howl create shop -f shop.yaml
howl apply shop.yaml -n
howl apply shop.yaml --to ssh://deploy@host/srv/apk/shop
```

**Composition.** Host and updater use the same renderer for services, fence policy and accounts.
People and secrets travel in boot config. `updates: off` removes the updater and records the `updates-enabled` posture weakness.

**The lock.** `build/lock/NAME[-dev][-published].lock.json` is apko JSON with a `werewolf` record:
packages for both arches, form serials, image digests, app hash and an input hash. Inputs cover
local manifests and form chains, rootfs and app bytes, modes and symlink targets; mtimes do not count.
Published forms are resolution outputs; local fallback forms remain inputs. Generated invocation
comments do not count. Matching inputs reuse exact versions; changed inputs resolve again, and a
failed resolution preserves the old lock. Kernel and boot-loader locks remain separate.
`make clean` keeps locks; `make relock FORM=...` refreshes them. Reproduction needs the same tools and artifacts; `FREEZE=1` is obsolete.

**Publishing.** Set `updates.from` before creation to enroll. Howl packages caller-owned forms
and the staged app as `local-NAME`, signs the index with `~/.howl/packages.rsa`, and gives the
machine its public key. Published forms stay separate dependencies. People and boot secrets stay out.
Apply defaults NAME to the file stem; `--name` overrides it and `--app DIR` replaces the remembered
app source. `-n` prepares locally without uploading. Run apply once after creation to seed the repository.
Uploads use HTTPS PUT, or SSH with `--to`; machines always fetch HTTPS without publishing credentials.
Use a dedicated repository URL and one publisher per declaration. Packages upload before the signed
index. A remote index containing versions absent locally is refused rather than overwritten.
Identical inputs reuse a revision; changed inputs advance monotonically. History lives under
`~/.howl/repositories/`, protected by a file lock and retained across clean builds. Back it up with
the signing key and `build/machines/NAME/declaration.json`, which identifies the enrolled machine.

**Updating and rollback.** A changed operator package is due immediately at the next successful
package check, without a CVE-feed delay. The updater composes it into the other slot, boots it once,
and keeps it only after commit. Failed resolution retains the current image and fails `update-held`.
An older declaration is never republished as a new version: apply requests `slot-update try HASH`,
which requires the parked slot to hold those exact image inputs. Automatic requests use `howl ssh`
(QEMU, Firecracker, Lima); elsewhere run `/usr/lib/werewolf/slot-update try HASH` through root access.
`slot-update try` without a hash explicitly tries whatever is parked. Neither rolls back data or config.

**Config transports.** GCP and Azure publish metadata live. People and root keys change within the
minute poll; other config takes effect at boot. AWS stops and starts to replace user data. QEMU,
Firecracker, Lima, bhyve and Proxmox replace their config disk through their existing restart path,
retaining image and data disks. Image-only applies do not restart the VM. A changed machine map,
address, platform, signing key or repository needs a new machine. Package and config publication
are separate operations; retry partial failures with the same declaration.

**Cloud people.** `machine.metadata-users: true` opts into GCP instance and project `ssh-keys`.
`block-project-ssh-keys: TRUE` excludes project keys. Expired or malformed `google-ssh` keys are ignored;
declared people take precedence, and metadata grants neither admin nor root. See Google's
[key format](https://docs.cloud.google.com/compute/docs/connect/add-ssh-keys) and [project-key control](https://docs.cloud.google.com/compute/docs/connect/restrict-ssh-keys).

**Release and verification.** This is package format 3: publish its programs and forms together
before enrolling; format-2 machines need reinstalling. Tests cover content invalidation, two-arch
packages, signed indexes, stable revisions, config merging and GCP expiry/precedence. The lock command
fixture and QEMU SSH boots pass. Cloud publishing and the full apply/rollback cycle need live verification.

## Drawbacks

The operator keeps a signing key and repository history; losing the key requires a new machine.

## Alternatives Considered

Without `updates.from`, local files are copied forward. Signed packages allow intentional changes; forwarded agents would expose credentials.

## Security Considerations

Trusted keys authorize images; root can replace slots. Admin touch is proven at login. Metadata supplies config, never images.

## Reliability Considerations

Commit proves services are up, not that the application is right. Data and config outlive rollback.
