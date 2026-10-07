# werewolf

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

werewolf is a Linux for virtual machines that gives malware nothing to run
with. Production images have no shell and no interpreter. The root
filesystem is read-only. The kernel is locked at boot, and not even root
can unlock it.

It is [Wolfi](https://wolfi.dev/)'s userland on
[Alpine](https://www.alpinelinux.org/)'s kernel, built the way OpenBSD would
build it.

## How it stays locked

- **[No shell.](docs/design/shell-free.md)** Production forms carry no shell
  or interpreter, and `posture` checks that they do not. A service is a
  ten-line declaration, which `leash` starts as its own user under Landlock.
  A shell is a build option, never a dependency.
- **Nothing written runs.** The root is a read-only erofs image. `/data`,
  `/tmp`, `/run`, `/dev/shm` and memfds are `noexec`, and user namespaces are
  off. werewolf's `mount` can add restrictions but never remove them.
- **[Locked at boot.](docs/design/lockdown.md)** Before the first service
  starts, init closes the module loader, raises kernel lockdown, turns off
  ptrace, and seals PID 1 with seccomp. Every process inherits the seal, so
  even root has no eBPF, perf, kexec, io_uring or `/dev/mem`.
- **[Network policy fixed at build.](docs/design/fence.md)** `fence` allows
  only the ports a form serves and the destinations each user may reach.
  There is no firewall to configure.
- **[Privilege separation.](docs/programs.md)** werewolf's own programs are
  small static Zig in the OpenBSD style. The half that reads untrusted input
  runs as its own user, chrooted, with no capabilities, under seccomp.
- **[Auditable updates.](docs/updater.md)** Packages and kernel come straight
  from Wolfi and Alpine, with no build server between. Each update logs the
  CVEs it fixes. A new image boots once and stays only if it stays healthy.
- **Small.** `minimal` is 9 packages and 3 MB, listens on nothing, and boots
  in 0.17 s. There is no systemd, no PAM, and no setuid file.
- **[Tested.](docs/testing.md)** Every push boots every form on two
  architectures, tries the attacks, and fails if one gets through.

What is not yet closed, and how to check a machine by hand, is in
[docs/security.md](docs/security.md). Where it is going, Linux IPE and
machines that run only code we signed, is in
[docs/design/verified-boot.md](docs/design/verified-boot.md).

## Try it

```sh
brew install apko lima qemu zstd erofs-utils zig    # macOS; Zig 0.17
make lima                                           # build, boot and ssh in

# or with QEMU alone
make run                   # the sshd form, with a root shell on the console
make run FORM=prod         # the production base: no shell, nothing listening
make run FORM=prod DEV=1   # the same, with a shell added for debugging
make run-ssh               # from another terminal
make webshell-demo         # a deliberately vulnerable web app on :8080; try to escape it
```

`posture` runs at every boot and prints what passed and what did not. It is
a static binary that assumes nothing about werewolf, so copy it to any Linux
machine and compare. See [docs/posture.md](docs/posture.md).

## Configure it

Secrets travel in a config tar. Put `authorized_keys`, `hostname` and
`data.key`, which puts `/data` in LUKS2, in `config/`, which is gitignored, and run
`make config-tar`. init finds the tar raw on any block device or in the
cloud's user data, and leaves it in `/run/config`, readable by root alone.
See [docs/cloud.md](docs/cloud.md).

## Forms

A form is an apko config in `forms/<name>.yaml`, with optional files, kernel
modules and network policy beside it. Forms build on each other, and every
one includes `minimal`. `make list-forms` shows the include chains.

| Form | What it is |
|---|---|
| `minimal` | the base: 9 packages, nothing listening |
| `prod` | DHCP, the cloud's metadata, updates itself, `/data` on a disk (in LUKS2 with `data.key`); no shell, nothing listening. Build yours on this. |
| `prod-ssh` | `prod` plus sshd |
| `nginx`, `php`, `node`, `python`, `jre` | `prod` and one runtime, leashed: bake your site or application into a form on one ([docs/forms.md](docs/forms.md)) |
| `postgresql`, `demo` | leashed services |
| `webshell-example` | a deliberately vulnerable web app, to show the sandbox holds (`make webshell-demo`) |

CI publishes `minimal`, `prod` and `prod-ssh` as signed, reproducible releases. See
[docs/releases.md](docs/releases.md).

## Take over an existing VM

When a provider will not boot a custom image, run `make bite-me` on a
Debian, Ubuntu, Fedora or Rocky VM. It installs werewolf beside the distro,
opens a shell in it, and offers to reboot. werewolf becomes the default only
after a healthy minute. See [docs/bite.md](docs/bite.md).

## Documentation

- [docs/forms.md](docs/forms.md): the forms, and building your application into one
- [docs/programs.md](docs/programs.md): the programs in `cmd/` and what confines them in `lib/`
- [docs/data.md](docs/data.md): `/data`, disks and encryption
- [docs/postgresql.md](docs/postgresql.md) and [docs/demo.md](docs/demo.md): running a leashed service
- [docs/roadmap.md](docs/roadmap.md): what comes next
