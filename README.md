# werewolf

<img src="media/logo-small.png" alt="werewolf logo" width="160" align="right">

A Linux for virtual machines with nothing to run malware with: no shell,
no interpreter, a read-only root, and a kernel locked at boot so that not
even root can unlock it. [Wolfi](https://wolfi.dev/)'s userland on
[Alpine](https://www.alpinelinux.org/)'s kernel, built the way OpenBSD
would build it.

## What is different

- **No shell.** Production forms carry no `sh`, `busybox`, `awk` or any
  interpreter; `posture` checks that they do not. Services are declared in a
  ten-line file, not scripted, and started by [`leash`](leash/leash.zig) as
  their own user under Landlock: the paths, programs and ports it names, and
  nothing else ([design/shell-free.md](design/shell-free.md)).
- **Nothing written runs.** The root is an erofs image mounted read-only;
  `/data`, `/tmp`, `/run` and `/dev/shm` are `noexec`; memfds are `noexec`;
  user namespaces are off. werewolf's own [`mount`](mount/mount.zig) can add
  `ro`, `nosuid`, `nodev` and `noexec` but never lift them.
- **Locked at boot, for good.** Before the first service starts, init closes
  the module loader, raises kernel lockdown, turns ptrace off, and seals
  PID 1 with a seccomp filter and a reduced capability bounding set that
  every process inherits: no eBPF, perf, kexec, io_uring, `/dev/mem` or
  raw I/O, for root too ([design/lockdown.md](design/lockdown.md)).
- **Network policy fixed at build.** [`fence`](fence/fence.zig) reads the
  form's `.net` file and allows only the ports it serves and the
  destinations each user may reach; the cloud metadata server only for whom
  it is meant. No firewall to configure, no BPF, no netfilter
  ([design/fence.md](design/fence.md)).
- **Privilege-separated programs.** init, DHCP, metadata fetch, mount, the
  updater and the rest are small static Zig programs in the OpenBSD style:
  the half that reads untrusted input runs as its own user, chrooted, with
  no capabilities, under a seccomp allowlist; the privileged half keeps one
  capability and checks every message again ([docs/programs.md](docs/programs.md)).
- **Updates you can audit.** Packages and kernel come from Wolfi and Alpine
  directly, verified against keys in the image; there is no build server
  and no signing key of ours. Every update logs the CVEs it fixes and writes
  a report an auditor can reproduce. A new image boots once into the other
  slot and is kept only if it stays healthy ([docs/updater.md](docs/updater.md)).
- **Small.** `minimal` is 10 packages, 3 MB, listens on nothing, and boots
  to runit in 0.17 s. No systemd, no PAM, no setuid or setgid files.
- **Tested.** `make check` boots every form on every push, on x86_64 and
  arm64, tries the attacks, and fails if one gets through
  ([docs/testing.md](docs/testing.md)).

What is not yet closed, and how to check a machine by hand:
[docs/security.md](docs/security.md). Where it is going, Linux IPE and
machines that run only code we signed:
[design/verified-boot.md](design/verified-boot.md).

## Quick start

```sh
brew install apko lima qemu zstd erofs-utils zig    # macOS; Zig 0.17
make lima                  # build, boot and ssh into a VM under Lima
```

Or with QEMU alone:

```sh
make run                   # the sshd form, with a root shell on the console
make run FORM=prod         # the production base: no shell, nothing listening
make run FORM=prod DEV=1   # the same, with a shell added for debugging
make ssh                   # from another terminal
```

Then measure it: `posture` runs on every boot and prints what passed and
what did not. It is a static binary that assumes nothing of werewolf, so
copy it to any Linux machine to compare ([docs/posture.md](docs/posture.md)).

Secrets travel in a config tar: put `authorized_keys`, `hostname` and
crypt's `data.key` in `config/` (gitignored) and `make config` packs it.
init finds it raw on any block device, or in a cloud's user data
([docs/cloud.md](docs/cloud.md)), and leaves it in `/run/config`, root's alone.

## Forms

A form is `forms/<name>.yaml`, an apko config, with optional files, kernel
modules and network policy beside it. Forms build on each other; every one
includes `minimal`. `make forms` lists them with their include chains.
The ones to know: `minimal`, `prod` (DHCP, autoupdate, no shell, nothing
listening: build yours on this), `prod-ssh`, `crypt` (`/data` in LUKS2),
`postgresql` and `demo`. CI publishes `minimal` and `prod-ssh` as signed,
reproducible releases ([docs/releases.md](docs/releases.md)).

## Taking over an existing VM

Where a provider will not boot a custom image, `bite` turns a running
Debian, Ubuntu, Fedora or Rocky VM into werewolf without repartitioning:
`make FORM=prod slot`, copy the slot and `bite` over, then
`sudo ./bite --reboot DIR`. It boots once and becomes the default only after
its services have stayed up for a minute ([docs/bite.md](docs/bite.md)).

## More

- [docs/data.md](docs/data.md): `/data`, disks and encryption
- [docs/postgresql.md](docs/postgresql.md), [docs/demo.md](docs/demo.md): leashed services
- [docs/roadmap.md](docs/roadmap.md): what comes next
