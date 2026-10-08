# forms

Each directory here is a form: what a werewolf machine is for
([docs/forms.md](../docs/forms.md)). Everything about a form is in its
directory, so a new form is a new directory and nothing else.

```text
forms/NAME/
  apko.yaml       the Wolfi packages, accounts and paths apko installs
  form.yaml       what apko cannot say (below); optional
  rootfs/         files laid over the packages: path here, path in the image
  cmd/PROGRAM/    a program only this form needs, PROGRAM.zig, built and laid
                  at /usr/lib/werewolf/PROGRAM (docs/programs.md)
  melange/        recipes for packages Wolfi does not ship (melange.mk)
  test/checks     make check's checks for it, beside test/checks
  test/config     writes its config for make check: config DIR
  test/console    console lines its as-shipped boot must show
  README.md       what it is, how to use it, what it refuses
```

A form has the parts of every form in its chain, base first and its own
last, so its files win: `make list-forms` shows each chain, and
build/host/form (tools/form.zig) reads them for the build.

## form.yaml

| Key | Is | Along the chain |
| --- | --- | --- |
| `base` | the form it is built on, a name in forms/ | |
| `with` | forms it takes beside its base, as a Mastodon takes `[postgresql, valkey, nginx]`: their parts come before its own | added to |
| `programs` | programs from cmd/ its machines run beyond every form's: prod's `dhcp-client`, postgresql's `popen-shim.so` (a library) | added to |
| `net` | its network policy: `listen tcp/PORT`, `connect USER\|all tcp/PORT udp/PORT icmp [public]`, `metadata USER` ([docs/design/fence.md](../docs/design/fence.md)) | added to |
| `prune` | files its packages bring that nothing runs, as each is in the image: `usr/bin/bash` | added to |
| `dev` | packages for DEV=1 builds alone: a daemon's client, for its checks | added to |
| `modules` | kernel modules it loads: `ARCH: MODULE...` for one arch, `@TAG: MODULE` for a machine stage0 tags (quote a line with a colon) | added to |
| `weaknesses` | the posture checks it fails, each with its excuse: why this image has the weakness, not what the check tests. `?ID` may fail or not, as the host decides. None named, none excused: any posture failure fails `make check` | its own |
| `check` | how `make check` boots it: `memory` (MiB), `offline: true`, `web` (a port test/boot drives from the host), `skip` (checks of test/checks it skips), `native: false` (not checked under systemd-nspawn, as every other form is; say why) | its own |

What a form's chain gives it, it cannot take away, only add to. Its own
keys are its own because they describe the machine as built: a form on
`python` that ships no interpreter would fail no check, so it does not
inherit `python`'s excuse. `make check` fails a machine on any posture
failure its form does not excuse, and on any excused one that passes;
[test/posture-known](../test/posture-known) holds what every form of a
kind fails (a DEV=1 build's shell, an architecture's gap).

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
and `#` comments. A key this page does not list, or YAML apko might read
some other way (anchors, tags, multi-line scalars, inline maps), fails
the build with its file and line.

## apko.yaml

An apko config, as apko documents it, without `include:`: werewolf
merges the chain's configs into one, base first, by the rules apko's
deprecated include used (lists joined, maps merged by key, everything
else the last form's), and apko builds that. `build/host/form apko NAME`
prints it.

## A new form

1. `forms/NAME/apko.yaml`: its packages, and an account for each service.
2. `forms/NAME/form.yaml`: `base: prod`, or a runtime form, and its `net`.
3. `forms/NAME/rootfs/etc/sv/SERVICE/service`: how leash starts it
   ([cmd/leash](../cmd/leash/leash.zig) lists the directives).
4. `forms/NAME/test/checks`: what proves it works, and what it refuses.
5. `make check-NAME`, then name each posture failure in `weaknesses`
   with its excuse, or fix it.

A form outside this tree builds the same way: `make FORM=../myapp`, a
form named after its directory, built on forms here.
