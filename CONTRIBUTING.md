# Contributing to werewolf

Thanks for helping. This page gets you from a clone to a tested change.

## Set up

werewolf builds on macOS and Linux (and, experimentally, FreeBSD and NetBSD, where
you run gmake).

```sh
make install-deps   # apko, Zig 0.17.0, QEMU, erofs-utils and the rest; asks first
make test           # every unit test, in seconds, no VM
make check-sshd     # build one form, boot it under QEMU and attack it
make hooks          # run test, lint and check-sshd before each commit
```

Zig is pinned to the version in the Makefile's `ZIG_VERSION`. Zig changes between
releases; when it moves, `make fix` (tools/zigfix.zig) rewrites most of what changed.

## Package dependencies

Forms consume third-party applications, hardened runtimes and libraries by package
name from the signed feeds declared by `minimal`. Image locks record exact package
versions and checksums for each architecture. Building and testing forms needs no
sibling package checkout or package repository commit pin.

The separate packages repository owns recipes, source pins, patches, native package
tests and publication. Publish a dependency there before adding it to a form's
`packages` list. Form integration tests verify the resulting installed packages.
An unavailable package fails the build; forms do not rebuild it from source.

Werewolf's own software and private development packages may keep recipes beside
their source in a form's `melange/` directory. This is separate from consumption of
published third-party packages. See [the
design](docs/design/implemented/package-promotion.md).

## Find your way around

| Path | What lives there |
|---|---|
| `cmd/NAME/` | one program per job, written in Zig; guest commands have mdoc manual pages |
| `cmd/howl/` | `howl`, the command users build and run machines with |
| `lib/` | code the programs share: sandboxing, seccomp promises, verity, forms |
| `../packages/CATEGORY/NAME/` | recipes or Wolfi derivations, maintenance metadata, patches, locks and tests |
| `forms/NAME/` | a form: `form.yaml` (its packages, and what werewolf adds), `rootfs/`, `test/` ([forms/README.md](forms/README.md)) |
| `test/` | the checks `make check` boots and attacks machines with; `test/host/` is what they share |
| `tools/` | build-host programs, never in an image; `tools/release/` builds, signs and publishes releases |
| `release/` | release keys, `images.yaml` (what is published) and a release's shell steps |
| `docs/` | user docs; `docs/design/` holds design docs |

The image has no shell, so everything that runs on a machine is a small Zig program.
Programs on the build host are Zig too, sharing `lib/` and `test/host/`, with tables
people edit in YAML. A POSIX shell script is fine for a step that only runs other
commands. Python and Go appear only where a form runs them.

## Make a change

1. Run the narrowest test while you work:
   - `make _test/lib/seal.zig` runs one file's unit tests.
   - `make check-FORM` boots one form, such as `make check-prod`.
   - `make check-one FORM=prod REPEAT=5` boots it again and again, to chase a flake.
2. Before you push, run `make test`, `make lint` (`make fix` repairs most of it) and
   `make check`. CI runs `make check` on x86_64 and arm64;
   [docs/testing.md](docs/testing.md) explains each check.
3. A guest command gets a [Markdown manual](docs/manuals.md) beside its source, named
   `NAME.1.md` for user commands or `NAME.8.md` for administration and boot helpers.
   Describe its invocation, options, files and operational limits; `make man-lint`
   compiles it to NetBSD-style mdoc and checks the result. The build installs manuals
   with their programs in `/usr/share/man`, including in APKs. Host tools keep
   READMEs. Put unit tests beside the code (`test "..." {}`).
4. A larger change starts as a design doc in `docs/design/pending/`, on the same
   template. Update its status and directory as the design is implemented or retired.
5. Service and application forms need at least five distinct integration cases
   covering useful behavior and refusals. Run `make form-coverage` to inspect
   coverage; [the testing guide](docs/testing.md#form-integration-coverage)
   explains the foundation and runtime exceptions.

## Style

Three people set the bar:

- **Code, as Theo de Raadt would write it:** simple, reliable, efficient
  and secure, with privileges separated. A program does one job, gives up
  what it doesn't need before it touches untrusted input, and fails closed.
- **Comments, as Rob Pike would write them:** concise, and only where the
  code can't say why. Don't restate the code. If an explanation runs past
  a few lines, it belongs in the program's manual or a design document.
- **Documentation, as Wietse Venema would write it:** clear, concise and readable. No
  unnecessary words or sentences. Manuals compile to mdoc semantic macros and
  conventional sections (NAME, SYNOPSIS, DESCRIPTION, FILES, SEE ALSO), with one
  sentence per source line where practical. READMEs and design docs use [the
  template](docs/design/TEMPLATE.md)'s headings; a README stays within 100 lines, a
  design doc within 120, any other doc in docs/ within 175, and every line within 85
  columns (`make fix` rewraps prose).

And in practice:

- Go's and Zig's own style: [Effective Go](https://go.dev/doc/effective_go) applies
  in spirit, and the [Zig style
  guide](https://ziglang.org/documentation/master/#Style-Guide) to the letter; `make
  lint` enforces it.
- Names say what a thing does: `dhcp-client`, not `dhcp`; `slot-keep`, not `commit`.
- Every log line starts with the program's name.
- Deny by default. A new capability, syscall or port is declared where a reviewer
  will see it (a promise, `form.yaml`'s `allow` or `net`), never opened silently.

## Commits and pull requests

- Commit subjects are `area: what changed`, in the imperative: `howl: verify the
  downloaded release before booting`. The body says why.
- One logical change per pull request. CI must pass.
- Pull requests are merged with merge commits.

## Good first contributions

- A new form for a service you run: copy a small one, such as `forms/valkey/`.
- A posture check for a hardening control that isn't checked yet (`cmd/posture/`).
- A docs fix: anything here that confused you is a bug.

## Security

Please don't open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
