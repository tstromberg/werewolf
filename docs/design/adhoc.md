# Ad-hoc machines

Proposed, 2026-10-08. Built the same day (cmd/howl/adhoc.zig, oci.zig,
cmd/init/oci.zig, leash `root`), but for the open items below.

## Summary

A werewolf machine from a command line alone: forms, Wolfi packages and
OCI images, mixed freely. The flags write a form directory
([docs/forms.md](../forms.md#forms-from-the-command-line)) that the build
builds and `howl form -o` keeps, so a one-shot machine and a kept one are
the same files. Only the operator writes policy.

## Background

A form is several files before the first boot: right for a fleet, wrong
for trying something, and people arriving from Docker have a list of
images, not a form. [oci.md](oci.md) proposed pulling images at boot.

## Goals

- One command boots any mix, `-n` shows the form, and `form -o DIR` keeps
  it; DIR builds the same. Machines that use none of it do not change.
- Nothing an image, registry or package index says becomes policy, and
  every refusal comes on the host, before apko, with the fix to paste.

## Non-Goals

A compose file, a DSL or prompts; a package running by itself; port
remapping, namespaces or a container runtime; pulling at boot (oci.md's
path, kept open); shell entrypoints.

## Detailed design

**Flags write lines; files hold structure**
([the grammar](../forms.md#forms-from-the-command-line)). An image's
flag is a line of its service file as written there, so one grammar
covers every leash directive; anything nested is the file's. howl knows
no form, and the build says which keys exist.

**Images are baked at build.** Nothing runs from a tmpfs, no policy is
fixed after boot, and boot costs nothing; a new image is a new build, as
`--app` is. `crane export` flattens the layers onto a pipe, and `howl
_unpack` lays them out holding no network, environment or credentials.
`ExposedPorts` and `Volumes` grant nothing until the operator says so.

**Accounts.** Each image runs as `_oci-NAME`, shared with no one: a
service user no form declares, whose uid is its name's hash
(`compose.defaultId`), so an image keeps its owner.

**The form says `image`.** The generated form.yaml holds each image as a
service: `services: NAME: {image: REF@sha256:..., listen: ..., write:
...}`, the operator's lines as keys and `--link A:B` as `link: [B]`. What
the registry said is a record beside the tree,
`rootfs/usr/share/werewolf/images/NAME.json` (lib/form.zig's `ImageRecord`):
the pinned image, the command checked against the tree, its environment
and working directory. compose renders the service file from the two, on
the host and on the machine alike, so a kept form carries no service
file and the machine needs no registry.

**leash `root`.** leash enters the image with `chroot`, as root, before
any rule, so every path resolves inside it
([cmd/leash](../../cmd/leash/README.md)). Before fence forbids mounting,
init binds the service's own `/tmp`, `/run` and `/data` into the root,
and each `write PATH` from `/data/svc/NAME/PATH`, all `noexec`
([cmd/init](../../cmd/init/README.md)). fence lets `/oci` execute.

**`loopback` on a listen.** fence served every `listen` from outside,
so a listener was public or impossible. `listen tcp/5432 loopback`
grants the bind and serves nothing, the twin of `connect ... public`;
`--link A:B` is A's `connect` to it. Open: a link to a form's UNIX
socket, binding `/run/svc/SVC` into the image so the listener knows its
peer and no password exists (the image's user must share its group).

## Drawbacks

The first build needs the network; the kept form's lock makes it
hermetic. Stock images meet two refusals: a script entrypoint and
ungranted volumes. A redeploy is a rebuild; `crane` is one more host
dependency. Loopback TCP cannot name its peer.

## Alternatives Considered

**A service inferred from a package**: guessing. **Pull at boot**:
oci.md, right for a fleet. **`EXPOSE` and `VOLUME` as policy**: the
image's author would author the binds, and a printed service is no
consent when `run` builds at once. **A hash as the name**: a cache key in
the UI. **A flag per concern**: six grammars for seven directives. **Our
own puller**: `crane` and a pipe replace oci.md's three processes.

## Security Considerations

| Risk | Control |
| --- | --- |
| An image grants itself ports or writable paths | its config grants nothing; the operator's line does |
| A tag moves to other bytes | resolved once; the digest is kept and signed with the image |
| A hostile tar escapes the tree | `_unpack` refuses `..`, links out and whiteouts; no devices, no setuid |
| A shell entrypoint | refused: the entrypoint must be ELF |
| A service writes a program and runs it | every bind is `noexec`; posture's `processes-image-roots` checks |

## Reliability Considerations

- howl refuses before apko what the build or the boot would: two forms
  or images on one port, a key the build refuses, an unknown directive.
  A failed build is a line on the host, never a parked service.
- `make check-adhoc` boots Chainguard's nginx from flags alone. Open:
  packages, bundles and links in `make check`; `--package` names checked
  against the APKINDEX; the memory sum checked against the machine's.
