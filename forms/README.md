# forms

To choose a VM, browse the [available forms and setup
guides](../docs/forms-catalog.md). For prebuilt disks, see [image availability and
download instructions](../docs/forms-catalog.md#images-and-downloads). This page is
the reference for defining a form.

Each directory here is a form ([docs/forms.md](../docs/forms.md)), and holds its
service policy and configuration: a new form is a new directory. Third-party package
recipes, patches and build sources live in the sibling `../packages` checkout,
organized under `CATEGORY/NAME/`, including hardened runtimes.

```text
forms/NAME/
  form.yaml       the form: what apko installs, and what apko cannot say (below)
  rootfs/         files laid over the packages: path here, path in the image
  cmd/PROGRAM/    a program only this form needs, PROGRAM.zig, built and laid
                  at /usr/lib/werewolf/PROGRAM (docs/programs.md)
  melange/        distro-specific package recipes beside their source (docs/forms.md)
  test/tests.yaml its native tests: YAML probes and Zig drivers (docs/testing-native.md)
  test/config     writes its config for make check: config DIR
  test/console    console lines its as-shipped boot must show
  README.md       what it is, how to use it, what it refuses, and how data comes in (TEMPLATE.md)
```

A form has the parts of every form in its chain, base first and its own last, so its
files win; `make list-forms` shows each chain. CI publishes each form but those with
melange recipes as NAME-form ([docs/releases.md](../docs/releases.md#packages)), and
howl takes a form by name from there, so the machine updates it; `--build` takes this
tree's. These are APK packages, not bootable qcow2 images; disk publication has
separate gates.

## form.yaml

| Key | Is | Along the chain |
| --- | --- | --- |
| `base` | the form it is built on, a name in forms/ | |
| `with` | forms it takes beside its base, as a Mastodon takes `[postgresql, valkey, nginx]`: their dependencies are included recursively, once each, before its own parts; cycles are refused | added to |
| `packages` | the Wolfi packages apko installs, by name | added to |
| `recipes` | Melange recipe paths relative to this form; checkout builds keep these inside the forms tree. Their directories supply the complete build context. Without this key, `melange/*.yaml` beside the form is discovered for local packages | added to, base first, once per resolved path |
| `accounts`, `paths` | what apko installs beyond packages: `accounts` its `groups` and `users`, with ids optional, for an account something depends on by number or shell (a login account, a program's fixed uid); a service's user needs none, its id being its name's hash. `paths` its permissions. `repositories`, `keyring` and `archs` are minimal's alone | added to; `archs` the last form's |
| `programs` | programs from cmd/ its machines run beyond every form's: prod's `dhcp-client`, postgresql's `sh-shim` | added to |
| `allow` | what it takes back of werewolf's defaults ([lib/allow.zig](../lib/allow.zig)): `kvm`, `nested-kvm`, `netadmin`, `packet`, `pty` (ssh logins), `jit` (a runtime that compiles code as it runs), `sh` (every leashed service may run the sh shim); and `PACKAGE:NAME`, what a hardened package gives back (`php:exec`, `java:deserialize`; docs/design/hardened-interpreters.md). General grants live in `/etc/werewolf/allow`; package grants in `/etc/runtime-hardening/allow/all/PACKAGE/NAME` | added to |
| `app` | where `howl --app DIR` lays an application: `/usr/lib/app`, nginx's `/usr/share/nginx/html` | the last form's |
| `services` | its leashed services, one a name: leash's directives as keys ([cmd/leash](../cmd/leash/leash.zig) lists them), a value one line, a list one line each, which the build writes as `etc/sv/NAME/service` with `run` and `finish` on leash. `listen` and `connect` take a net line's words (`tcp/PORT`, `udp/PORT`, `icmp`, `public`, `loopback`, `lan`): leash holds the TCP, fence the rest, so a service's network is said once. `lookup: NAME` or `lookup: "*"` grants DNS names through unwound; DNS servers with `dns-direct: true`, their own user and DNS listener may use declared upstream connections on port 53 or 853 ([DNS allowances](../docs/design/unwound-policy.md)). `image: REF` runs it in that image's tree, baked at `/oci/NAME` as `_oci-NAME` with the image's own command and environment, or `exec`'s; a tag is followed, the build baking its digest of the day ([docs/design/oci.md](../docs/design/oci.md)); `run DIR/` runs what is beneath DIR in it; `link: [NAME...]` reaches those services' ports on loopback | whole, last by name |
| `users` | the machine's people, the top manifest's alone (a form others take may name none): each a name with `keys:` (lines of a `.pub`, security keys' unless `sshd:` takes key files) and `admin: true`, whose keys are root's too. Never in the image: `howl` packs them into the boot config, and init makes each an account (uid its name's hash in 1000-60000, home `/data/home/NAME`, mksh where the shell package provides it) and its keys file; `howl --users.NAME.keys LINE`, `--users.NAME.admin` | the top form's |
| `updates` | how the machine keeps itself current (docs/updater.md): `every: 1h` (5m to 7d) between checks, or `off`, which leaves the autoupdate service out of the image; `howl --updates off`, `--updates.every 1h` | the last form's |
| `imports` | supported data import modes: `[init]` (the default), `[init, sync]`, or `[]` to refuse imports. The form must implement each declared mode; `sync` preserves destination-only files. Signed into the deployment definition; see [data import](../docs/design/data-import.md) | the last declaration's |
| `net` | the network of what is no service, as the updater's fetcher (`connect _update tcp/443`, `lookup _update packages.wolfi.dev`) or root's: `listen tcp/PORT... [loopback|lan]`, `listen USER udp/PORT... [lan]` (a kernel's socket is root's), `connect USER\|:all\|:people tcp/PORT udp/PORT icmp [public]` (UDP also accepts `lan` for connected subnets and discovery multicast, for a USER), `metadata USER`, `lookup USER\|:people NAME [TYPE...]`; `:all` is every user, and `:people` every person, Lima's NoCloud login included, by the uid ranges init gives them alone (an account the image declares there fails the build); no account name begins with `:`. A line for a service's user is refused ([docs/design/fence.md](../docs/design/fence.md)); `build/host/form listens FORM` lists the ports it serves | added to |
| `prune` | files its packages bring that nothing runs, as each is in the image: `usr/bin/bash` | added to |
| `weaknesses` | the posture checks it fails, each with its excuse: why this image has the weakness, not what the check tests. `?ID` may fail or not, as the host decides. None named, none excused: any posture failure fails `make check` | its own |
| `sshd` | sshd_config settings, each named in lowercase with dashes, from a closed list ([lib/sshd.zig](../lib/sshd.zig)): `pubkey-accepted-algorithms: ssh-ed25519,sk-ssh-ed25519@openssh.com` lets key files in beside security keys; werewolf's own `verify-required-keys`, none or security key types, puts `verify-required` before each such key of `users:`. The image holds them in `/etc/ssh/sshd_config.d/form.conf`, which sshd reads before werewolf's policy. Only where the chain has the `sshd` form or the `bastion`; a setting posture checks wants its weakness named. howl's `--sshd.KEYWORD=VALUE` writes the same | a later form's value in place of its base's |
| `bastion` | the bastion's users: `users:`, each a name with `keys:` (lines of a `.pub`, security keys' unless `sshd:` takes key files) and `destinations:` (literal `ADDRESS:PORT`s). The image holds them in `/etc/ssh/bastion`, each key held to its user's destinations ([bastion](bastion/README.md)) | added to |
| `check` | how `make check` boots it: `memory` (MiB, a number), `offline: true`, `skip` (the shared platform checks its boot rules out, such as `http-answering`), `native: false` (not checked under systemd-nspawn, as every other form is; say why). `offline` and `native` are `true` or `false`; anything else fails the build | its own |

A service's `allow: [java:native]` grants a hardened runtime capability to that
service's cgroup alone. The builder generates its read-only marker under
`/etc/runtime-hardening/allow/NAME/java/native`; no rootfs file is needed.
The CLI equivalent is `--services.NAME.allow java:native` (repeat for more grants).
Both parts of `PACKAGE:NAME` must be nonempty and use only `a-z`, `0-9` and `-`.
Packages define their own names; forms validate the shape without a package or
capability list. Unrecognized names have no effect in the package. General allowances
such as `jit` require top-level `allow` for image-wide grants.
Service grants require the machine's root (no `image` or `root`), and `all` is
reserved. Replacing a service replaces its grants too.

A service may declare `listen: tcp/0 loopback` for a kernel-assigned temporary
port. This grants that service's bind request only: no port is published or
forwarded, and `link` grants no connection to an unknown port. Fixed ports
and outbound connections still need their own declarations.

What a form's chain gives it, it cannot take away, only add to. Its own
keys are its own because they describe the machine as built: a form on
`python` that ships no interpreter would fail no check, so it does not
inherit `python`'s excuse. `make check` fails a machine on any posture
failure its form does not excuse, and on any excused one that passes;
[test/posture-known](../test/posture-known) holds what every form
fails (a boot-chain gap, an architecture's). The image
carries both, with their excuses, in `/usr/share/werewolf/weaknesses`, so
every machine knows which failures are expected: posture marks each
excused one in its JSON and warns on the console of any other, wherever
it boots.

```yaml
# forms/python/form.yaml
base: app

net:
  - listen tcp/8080

weaknesses:
  programs-no-interpreters: python3 runs the application, which is what this form is for
```

Both files are YAML in the small part of it they are written in: block
maps and lists indented with spaces, plain or quoted scalars, `[a, b]`,
and `#` comments. Plain values may wrap onto adjacent, more-indented lines;
each line break becomes a space. Quoted values stay on one line. A key
this page does not list, or YAML apko might read some other way (anchors,
tags, block scalars, inline maps, blank lines within values), fails
the build with its file and line.

## What apko installs

A form's `packages`, `accounts` and `paths` (and minimal's `repositories`,
`keyring` and `archs`) are an apko config in form.yaml's own keys:
werewolf merges the chain's into one, base first, by the rules apko's
deprecated `include:` used (lists joined, maps merged by key, everything
else the last form's), and apko builds that. `build/host/form apko NAME`
prints it.

`accounts` are added again on a machine's update, which installs with
apk, not apko (lib/compose.zig): a user's `homedir` is `/var/empty` (or
`/dev/null`), since nothing on the machine would make another, and a
service writes where its service file's `write` says.

A service's `user` needs no account there: one no form names gets its
own, uid and gid a hash of its name in 1073741824-2147483647, home
`/var/empty`, shell `/sbin/nologin`, the same on every build. Name the
account to override its shell or ids. An account with no `uid` gets the
same defaults, including its own group; a declared group's omitted `gid`
is its name's hash. A same-named declared group supplies the default user's
primary gid. Explicit ids remain available when software requires them.
Each service runs as a user of its own: two
that share one, or a hash that lands on an id taken, fail the build.

For example, this overrides only a user's shell:

```yaml
accounts:
  users:
    - username: supercronic
      shell: /usr/lib/werewolf/sh-shim
```

To share another service's files, name its user in the service's `group`
directive. The user's primary group and both ids keep their defaults.
Removing a numeric override can change the id. Migrate existing `/data`
file ownership before updating a machine that used the old id.

## A new form

1. `forms/NAME/form.yaml`: `base: prod`, or a runtime form; its
   `packages`; and its `net`.
2. its `services`: how leash starts each, as whom, on which ports
   ([cmd/leash](../cmd/leash/leash.zig) lists the directives).
3. `forms/NAME/test/tests.yaml`: at least five distinct integration cases proving
   what works and what is refused ([coverage
   policy](../docs/testing.md#form-integration-coverage)).
4. `make check-NAME`, then name each posture failure in `weaknesses`
   with its excuse, or fix it.

A form outside this tree builds the same way: `make FORM=../myapp`, a
form named after its directory, built on forms here. howl takes one by its
path (`--with ./myapp`), built on the published forms, and the machine
never updates it.
