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

- **[No shell.](docs/design/shell-free.md)** Services do not need one, so
  production forms carry no `sh`, `busybox`, `awk` or any interpreter, and
  `posture` checks that they do not. A shell is a build option, for the
  `sshd` form and for `DEV=1`, never a dependency. A service is a ten-line
  declaration, not a script. `leash` starts it as its own user under
  Landlock, confined to the paths, programs and ports it names.
- **Nothing written runs.** The root is an erofs image mounted read-only.
  `/data`, `/tmp`, `/run`, `/dev/shm` and memfds are `noexec`. User
  namespaces are off. werewolf's own `mount` can add `ro`, `nosuid`, `nodev`
  and `noexec` but can never remove them.
- **[Locked at boot.](docs/design/lockdown.md)** Before the first service
  starts, init closes the module loader, raises kernel lockdown, turns off
  ptrace, and seals PID 1 with a seccomp filter and a reduced capability set.
  Every process inherits both. Root has no eBPF, perf, kexec, io_uring,
  `/dev/mem` or raw I/O.
- **[Network policy fixed at build.](docs/design/fence.md)** `fence` reads
  the form's `.net` file and allows only the ports it serves and the
  destinations each user may reach. The cloud metadata server is reachable
  only by the user it is meant for. There is no firewall to configure, no
  BPF and no netfilter.
- **[Privilege separation.](docs/programs.md)** init, DHCP, metadata fetch,
  mount, the updater and the rest are small static Zig programs in the
  OpenBSD style. The half that reads untrusted input runs as its own user,
  chrooted, with no capabilities, under a seccomp allowlist. The privileged
  half keeps one capability and checks every message again.
- **[Auditable updates.](docs/updater.md)** Packages and kernel come straight
  from Wolfi and Alpine, verified against keys in the image. There is no
  build server and no signing key of ours. Each update logs the CVEs it fixes
  and writes a report an auditor can reproduce. A new image boots once into
  the other slot and is kept only if it stays healthy.
- **Small.** `minimal` is 10 packages and 3 MB. It listens on nothing and
  boots to runit in 0.17 s. There is no systemd, no PAM, and no setuid or
  setgid file.
- **[Tested.](docs/testing.md)** Every push boots every form on x86_64 and
  arm64, tries the attacks, and fails if one gets through.

What is not yet closed, and how to check a machine by hand, is in
[docs/security.md](docs/security.md). Where it is going, Linux IPE and
machines that run only code we signed, is in
[docs/design/verified-boot.md](docs/design/verified-boot.md).

## Try it

```sh
brew install apko lima qemu zstd erofs-utils zig    # macOS; Zig 0.17
make lima                                           # build, boot and ssh in
```

Or with QEMU alone:

```sh
make run                   # the sshd form, with a root shell on the console
make run FORM=prod         # the production base: no shell, nothing listening
make run FORM=prod DEV=1   # the same, with a shell added for debugging
make run-ssh               # from another terminal
```

`posture` runs at every boot and prints what passed and what did not. It is
a static binary that assumes nothing about werewolf, so copy it to any Linux
machine and compare. See [docs/posture.md](docs/posture.md).

## Configure it

Secrets travel in a config tar. Put `authorized_keys`, `hostname` and
crypt's `data.key` in `config/`, which is gitignored, and run
`make config-tar`. init finds the tar raw on any block device or in the
cloud's user data, and leaves it in `/run/config`, readable by root alone.
See [docs/cloud.md](docs/cloud.md).

## Forms

A form is an apko config in `forms/<name>.yaml`, with optional files, kernel
modules and network policy beside it. Forms build on each other, and every
one includes `minimal`. `make list-forms` shows the include chains.

| Form | What it is |
|---|---|
| `minimal` | the base: 10 packages, nothing listening |
| `prod` | DHCP and autoupdate, no shell, nothing listening. Build yours on this. |
| `prod-ssh` | `prod` plus sshd |
| `crypt` | `/data` in LUKS2 |
| `postgresql`, `demo` | leashed services |

CI publishes `minimal` and `prod-ssh` as signed, reproducible releases. See
[docs/releases.md](docs/releases.md).

## Take over an existing VM

When a provider will not boot a custom image, `bite` turns a running Debian,
Ubuntu, Fedora or Rocky VM into werewolf without repartitioning. Build a
slot with `make FORM=prod slot`, copy the slot and `bite` over, and run
`sudo ./bite --reboot DIR`. The new system boots once and becomes the
default only after its services have stayed up for a minute. See
[docs/bite.md](docs/bite.md).

## Documentation

- [docs/programs.md](docs/programs.md): the programs in `cmd/` and what confines them in `lib/`
- [docs/data.md](docs/data.md): `/data`, disks and encryption
- [docs/postgresql.md](docs/postgresql.md) and [docs/demo.md](docs/demo.md): running a leashed service
- [docs/roadmap.md](docs/roadmap.md): what comes next
