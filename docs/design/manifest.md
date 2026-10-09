# One manifest: a machine from one YAML file

Proposed, 2026-10-09; revised after review. On [adhoc.md](adhoc.md), [custom-updates.md](custom-updates.md) and [howl-build.md](howl-build.md).

## Summary

A werewolf machine is one YAML file, a manifest; a form is a manifest in
`forms/` others take by name. It is the machine's whole policy; a lock pins
what the network resolved; the machine updates itself, never its declaration.

## Background

Policy is split over five files; the machine has no lock; only `prod` updates.

## Goals

- One reference alone is that form, byte for byte; `howl create FLAGS -n`
  prints a manifest `-f` rebuilds; a lock whose inputs match rebuilds exactly.
- Everything a form says, a manifest says inline, and the reverse.
- Three tiers, by apk alone: forms follow their latest release and its pins,
  `packages:` follow Wolfi, `local-NAME` moves only by `howl apply`.

## Non-Goals

Inline files, timers, conditionals, doas, sudo, su, OS Login, a new disk or
address in place, compatibility.

## Detailed design

**The manifest** is `form.yaml`, every key optional. A *form* key merges
along the chain; a *machine* key is the top manifest's alone. *Image* keys
change by `apply`, *config* by the boot config, *machine* by a new machine.

| Key | Is | Merge |
| --- | --- | --- |
| `base`, `with` | the form it is built on, `prod` if none, on every host alike; forms taken beside it. Any form's `with` counts | chain |
| `packages` | Wolfi packages by name; a form's pins own a package both name | added to |
| `services` | one a name: leash's directives as keys (a scalar is one line, a list one each), `image: REF` (an OCI tree at `/oci/NAME`, run as `_oci-NAME`), `group` (another service's, as php shares nginx's socket). `listen` and `connect` take `tcp/`, `udp/`, `icmp`, `public`, `loopback`: leash takes the TCP, fence the rest. No `net` key | whole, last by name |
| `users`, `secrets` | people, one an account: `keys` (security keys), on a bastion `destinations`, `admin: true` (the keys are root's too: a root session takes the key's touch, as sshd proves, attributed by fingerprint). Needs `with: [sshd]` or the bastion, said. Users and secret files are packed into the boot config, never the image, with the cloud's users where `machine.metadata-users` says; made as init makes Lima's user: home `/data/home/NAME`, the chain's shell or none, uid the name's hash in 1000 to 60000. cloud-metadata refetches the config and GCP's `ssh-keys` every minute and init redoes accounts and keys: a new user is a login away, never a boot | config |
| `updates` | on everywhere: every image boots from a slot, `minimal` included; `every`, `policy`, `from` (where `apply` publishes); `off` is a weakness the build excuses | last |
| `machine`, `app`, `settings` | howl's flags today, `hostname`, `ip`, `dns`, `data`, `data-key`, `on`, `arch`, `size`, `allow-from`, and `metadata-users`, off unless said: a new machine. The application directory, laid where the chain's `app-dir` says, and settings, baked at `/etc/werewolf/settings`: image | machine |
| `ssh`, `allow`, `modules`, `prune`, `paths`, `app-dir`, `programs`, `dev`, `bastion`, `weaknesses`, `check` | as today; `ssh` is `sshd:`'s keywords | as today |

```yaml
# forms/valkey/form.yaml: Valkey on a UNIX socket, for the app beside it
base: prod
packages: [valkey-9.1, valkey-9.1-cli]
services:
  valkey:
    exec: /usr/bin/valkey-server /etc/valkey/valkey.conf
    user: valkey
    pledge: stdio rpath wpath unix listen proc
```
```yaml
# shop.yaml
with: [chrony]
users:
  tom:
    keys: [sk-ssh-ed25519@openssh.com AAAAGnNr... tom@yubikey]
updates:
  every: 1h
services:
  web:
    image: ghcr.io/acme/web:1.4
    listen: [tcp/8080]
```
```sh
howl create shop --with chrony --updates.every 1h \
  --users.tom.keys 'sk-ssh-ed25519@openssh.com AAAAGnNr... tom@yubikey' \
  --services.web.image ghcr.io/acme/web:1.4 --services.web.listen tcp/8080
```

**The flags are the keys.** `--KEY VALUE` sets a scalar or appends to a list,
by the schema in `lib/form.zig`; `off` and booleans take no value. `-f FILE`
reads a manifest, flags layer over it; `-n` prints it, with no side effects.

**compose** renders each service's directory, the keys, fence's policy and
the accounts, on host and machine from one function, checked by leash's
parser. A service's user is its name's hash; renamed, it is new. Excuses are
the chain's, each with its form, and the build's; one that passes fails.

**The lock** is apko's widened: packages on both arches, form serials, image
digests, the app's hash, and `inputs`, the sha256 of manifest, `rootfs/` and
app: matching, it builds exactly; else it is resolved again. The image's is
apk's database, composed per slot, never read.

**apply.** What the manifest derives is a package, `local-NAME`, versioned by
the build, signed by howl's key (`~/.howl`; public half in `/etc/apk/keys`).
`howl apply shop.yaml` publishes the config half as the boot config, metadata
or the config disk, and the image half to `updates.from`, HTTPS or ssh; the
updater takes it as any newer package, due at once: the other slot, one boot,
kept if it commits. A downgrade is a boot of the other slot, never a build:
an older manifest it holds, or `slot-update try`, arms it; any other is
refused. An unsolvable pin holds the last image, logged, `update-held` failing.

**Refused on the host:** an unknown key, a machine key in a form, a package
not in the APKINDEX, two forms on one port, an image with ports and no grant.

**Phases.** 1: one format, byte-identical. 2: services inline, `net` derived,
users, updates in `minimal`. 3: howl's schema, `-f`. 4: the lock. 5: `apply`.

## Drawbacks

Forty forms change shape at once; a lost `~/.howl` key means a new machine.

## Alternatives Considered

**Services in files only**: a form cannot be written inline. **`net` beside
services**: two authorities for one port. **doas**: nothing setuid runs here.
**Touch per command**, by a forwarded agent: a compromised machine holds it.

## Security Considerations

The machine cannot change what it runs: only a package signed by a key in
`/etc/apk/keys` can. A metadata user is trusted as the boot config is; an
admin's touch is proven at login, not per command. Root can replace a slot.

## Reliability Considerations

Commit proves services up, not an application right; data outlives a rollback.
