# Werewolf Linux — Secure-by-default VMs [EXPERIMENTAL]

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

**What if we actually just used the security features the Linux kernel provides -- by
default?**

Werewolf Linux is an experiment with a simple goal: creating the most secure VM
environment ever built.

Inspired by NixOS, ChromeOS, OpenBSD, and NanoVMs it takes the idea of a declarative,
immutable distro to the extreme.

Out of the box, Werewolf ships with modern Linux security controls enabled, such as
[Landlock](https://docs.kernel.org/userspace-api/landlock.html),
[Seccomp-BPF](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html),
[dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html),
[IPE](https://docs.kernel.org/admin-guide/LSM/ipe.html),
[EROFS](https://docs.kernel.org/filesystems/erofs.html),
[MDWE](https://man7.org/linux/man-pages/man2/pr_set_mdwe.2const.html),
[KASLR](https://docs.kernel.org/security/self-protection.html#kernel-address-space-layout-randomization-kaslr),
[YAMA](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html), and [A/B
system updates](https://source.android.com/docs/core/ota/ab), where the provider
supports them. It aims to keep the operating system and native code immutable even
after a service compromise; application data remains writable. To frustrate would-be
attackers, we've hardened dependencies like glibc, runtimes like PHP and Python, and
reduced our attack surface so much that our production images generally don't include
a shell.

In a survey of [CISA known-exploited Linux
vulnerabilities](docs/cve-mitigation-survey.md), dated 2026-10-07, Werewolf's
controls were assessed to block 48 of 49 exploits in scope. This was a source-based
assessment; the exploits were not run.

## The ten craziest things we did

1. **Root isn't omnipotent.** Before any service starts, the machine is sealed with
   seccomp and Landlock rules that fix each service's system calls, files and ports,
   and nobody, root included, can loosen them.
2. **New code can't run.** The root filesystem is read-only and verified block by
   block, and the kernel's IPE executes native code only from that signed image.
3. **There's no shell to pop.** Most production images ship without one, so a
   hijacked web server can't `sh -c`, pipe `curl` into `bash`, or chain tools
   together.
4. **Kernel attack surface is deleted, not disabled.** Our kernel is built without a
   module loader, eBPF, io_uring, user namespaces, kexec or IPv6; 19 of the 31
   exploited kernel bugs on CISA's list live in code it never compiles.
5. **glibc, neutered.** Our glibc ignores `LD_PRELOAD`, `GLIBC_TUNABLES` and loader
   audit hooks and loads no external NSS or iconv modules, closing the doors used by
   Looney Tunables, PwnKit and the xz backdoor.
6. **Hardened interpreters.** Our Python, Java, PHP and Node.js refuse to run as
   root, and each gates its favorite exploit tricks (`eval`, scripts on writable
   disk, native code, deserialization) behind root-held allowances.
7. **DNS on a leash.** Each service resolves only domains its form declares, with
   filtering against newly registered domains, OOB domains, and tunnel shapes by
   default.
8. **A firewall per service.** Each service's listeners and outbound connections
   follow its form's network policy, and raw-socket capabilities are removed.
9. **Kernel settings stay set.** Root can't write `/proc/sys`, ptrace a process or
   read kernel memory, and an oops reboots the machine rather than run a damaged
   kernel.
10. **Signed updates recover automatically.** Enrolled machines normally check
    hourly. After detecting an urgent fix, the updater targets a reboot within 15
    minutes, subject to reboot spacing. A failed trial returns to the retained good
    slot.

The [security guide](docs/security.md) covers every control and its limits.

## Try it

This will run a Werewolf "playground" image under a local VM:

```sh
git clone https://github.com/werewolf-linux/werewolf && cd werewolf
make install
howl run
```

To build and deploy the Python example on GCP, first complete the
[cloud setup](examples/README.md#prepare-gcp-once), then run:

```sh
howl create python --with python-example --on gcp --build --allow-from me
```

Providers include AWS, GCP, Azure, Firecracker, Lima, QEMU, bhyve and Proxmox.
Protection support varies: x86_64 bhyve supports Secure Boot, TPM, IPE and A/B
updates; ARM64 bhyve remains experimental. Firecracker defaults to host-pinned boot
files with IPE and dm-verity, lacks Secure Boot and TPM protection, and requires host
rebuilds for image updates. See [provider
details](cmd/howl/README.md#detailed-design).

## Forms

As locking down complex services isn't for the faint of heart, we have a catalog of
[hardened forms](docs/forms-catalog.md) that Werewolf can take: for example:

- [Caddy](forms/caddy/README.md)
- [PostgreSQL](forms/postgresql/README.md)
- [Plex](forms/plex/README.md)

We also have general-purpose runtime forms to quickly deploy a hardened app in your
preferred language:

- [ASP.NET Core](examples/aspnet/README.md)
- [Go](examples/go/README.md)
- [Node.js](examples/nodejs/README.md)
- [Python](examples/python/README.md)
- [PHP](examples/php/README.md)
- [Rust](examples/rust/README.md)

## Get involved

Questions, fixes and reports from new hosts are welcome in [GitHub
issues](https://github.com/werewolf-linux/werewolf/issues); no Zig required. See the
[contribution guide](CONTRIBUTING.md). Think you've broken it? Tell us privately
through the [security policy](SECURITY.md); that's the whole point.

Licensed under [Apache 2.0](LICENSE). Sponsored by [isotope13](http://isotope13.io/).
