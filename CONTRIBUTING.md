# Contributing to werewolf

Thanks for helping. This page gets you from a clone to a tested change.

## Set up

werewolf builds on macOS and Linux (and, experimentally, FreeBSD and NetBSD, where you run gmake).

```sh
make install-deps   # apko, Zig 0.17.0, QEMU, erofs-utils and the rest; asks first
make test           # every unit test, in seconds, no VM
make check-sshd     # build one form, boot it under QEMU and attack it
make hooks          # run test, lint and check-sshd before each commit
```

Zig is pinned to the version in the Makefile's `ZIG_VERSION`. Zig changes between releases; when it moves, `make fix` (tools/zigfix.zig) rewrites most of what changed.

## Find your way around

| Path | What lives there |
|---|---|
| `cmd/NAME/` | one program per job, written in Zig, each with a README on how it works |
| `cmd/howl/` | `howl`, the command users build and run machines with |
| `lib/` | code the programs share: sandboxing, seccomp promises, verity, forms |
| `forms/NAME/` | a form: `apko.yaml` (packages), `form.yaml` (what werewolf adds), `rootfs/`, `test/` ([forms/README.md](forms/README.md)) |
| `test/` | the scripts `make check` boots and attacks machines with |
| `release/` | building, signing and publishing releases |
| `docs/` | user docs; `docs/design/` holds design docs |
| `bite` | takes over an existing VM |

The image has no shell, so everything that runs on a machine is a small Zig program. Tools that run on the build host or on a distro being taken over (`bite`, `release/*`, `test/*`) are POSIX shell, on purpose: that is where a shell already is.

## Make a change

1. Run the narrowest test while you work:
   - `make _test/lib/seal.zig` runs one file's unit tests.
   - `make check-FORM` boots one form, such as `make check-prod`.
   - `make check-one FORM=prod REPEAT=5` boots it again and again, to chase a flake.
2. Before you push, run `make test`, `make lint` (`make fix` repairs most of it) and `make check`. CI runs `make check` on x86_64 and arm64; [docs/testing.md](docs/testing.md) explains each check.
3. A new program gets a README on the [design doc template](docs/design/TEMPLATE.md) (100 lines at most), and unit tests beside its code (`test "..." {}`).
4. A larger change starts as a design doc in `docs/design/`, on the same template.

## Style

Three people set the bar:

- **Code, as Theo de Raadt would write it:** simple, reliable, efficient
  and secure, with privileges separated. A program does one job, gives up
  what it doesn't need before it touches untrusted input, and fails closed.
- **Comments, as Rob Pike would write them:** concise, and only where the
  code can't say why. Don't restate the code. If an explanation runs past
  a few lines, it belongs in the program's README.
- **Documentation, as Wietse Venema would write it:** clear, concise and
  readable. No unnecessary words or sentences. READMEs and design docs use
  [the template](docs/design/TEMPLATE.md)'s headings; a README stays within
  100 lines, a design doc within 120.

And in practice:

- Go's and Zig's own style: [Effective Go](https://go.dev/doc/effective_go) applies in spirit, and the [Zig style guide](https://ziglang.org/documentation/master/#Style-Guide) to the letter; `make lint` enforces it.
- Names say what a thing does: `dhcp-client`, not `dhcp`; `slot-keep`, not `commit`.
- Every log line starts with the program's name.
- Deny by default. A new capability, syscall or port is declared where a reviewer will see it (a promise, `form.yaml`'s `allow` or `net`), never opened silently.

## Commits and pull requests

- Commit subjects are `area: what changed`, in the imperative: `bite: download the latest release when given no slot`. The body says why.
- One logical change per pull request. CI must pass.
- Pull requests are merged with merge commits.

## Good first contributions

- A new form for a service you run: copy a small one, such as `forms/valkey/`.
- A posture check for a hardening control that isn't checked yet (`cmd/posture/`).
- A docs fix: anything here that confused you is a bug.

## Security

Please don't open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
