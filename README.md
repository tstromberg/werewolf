# Werewolf Linux — Secure-by-default VMs [EXPERIMENTAL]

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

**What if we actually just used the security features the Linux kernel provides -- by default?**

Werewolf Linux is an experiment with a simple goal: creating the most secure VM environment ever built.

Inspired by NixOS, ChromeOS, OpenBSD, and NanoVMs it takes the idea of a declarative, immutable distro to the extreme. 

Out of the-box, Werewolf ships with all manner of modern Linux security controls enabled, such as [Landlock](https://docs.kernel.org/userspace-api/landlock.html), [Seccomp-BPF](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html), [dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html), [IPE](https://docs.kernel.org/admin-guide/LSM/ipe.html), [EROFS](https://docs.kernel.org/filesystems/erofs.html), [MDWE](https://man7.org/linux/man-pages/man2/pr_set_mdwe.2const.html), [KASLR](https://man7.org/linux/man-pages/man2/pr_set_mdwe.2const.html), [YAMA](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html), and [A/B system updates](https://source.android.com/docs/core/ota/ab). It aims to make it impossible to drop a persistent backdoor - even as root. To further frustrate would-be attackers, we've hardened dependencies like glibc, runtimes like PHP and Python, and reduced our attack surface so much that our production images generally don't include a shell. 

In a survey of [CISA known-exploited Linux vulnerabilities](docs/cve-mitigation-survey.md), Werewolf would have prevented 48 of 49 exploits.

## The ten craziest things we did

1. **Root isn't omnipotent.** Before any service starts, the machine is sealed with
   seccomp and Landlock rules that fix each service's system calls, files and ports, and
   nobody, root included, can loosen them.
2. **New code can't run.** The root filesystem is read-only and verified block by block,
   and the kernel's IPE executes native code only from that signed image.
3. **There's no shell to pop.** Production images ship without one, so a hijacked web
   server can't `sh -c`, pipe `curl` into `bash`, or chain tools together.
4. **Kernel attack surface is deleted, not disabled.** Our kernel is built without a
   module loader, eBPF, io_uring, user namespaces, kexec or IPv6; 19 of the 31 exploited
   kernel bugs on CISA's list live in code it never compiles.
5. **glibc, neutered.** Our glibc ignores `LD_PRELOAD`, `GLIBC_TUNABLES` and loader
   audit hooks and loads no external NSS or iconv modules, closing the doors used by
   Looney Tunables, PwnKit and the xz backdoor.
6. **Hardened interpreters.** Our Python, Java, PHP and Node.js refuse to run as
   root, and each gates its favorite exploit tricks (`eval`, scripts on writable disk,
   native code, deserialization) behind root-held allowances.
7. **DNS on a leash.** Each service resolves only domains its form declares, with
   filtering against newly registered domains, OOB domains, and tunnel shapes by default.
9. **A firewall per service.** Every packet a form doesn't declare is dropped in both
   directions, and the raw-socket capabilities to get around that are gone.
10. **Kernel settings stay set.** Root can't write `/proc/sys`, ptrace a process or read
   kernel memory, and an oops reboots the machine rather than run a damaged kernel.
11. **Exploited bugs get 15 minutes.** Machines check for updates hourly and boot a fix for anything
    on CISA's exploited list within 15 minutes, into a signed spare slot that rolls back
    on its own if it fails.

The [security guide](docs/security.md) covers every control and its limits.

## Try it

This will run a Werewolf "playground" image under a local VM:

```sh
git clone https://github.com/werewolf-linux/werewolf && cd werewolf
make install
howl run
```

Want to deploy a production Python app to GCP instead?

```sh
howl run --with prod-ssh --on gcp
```

Supported providers include: AWS, GCP, Azure, Firecracker, Lima, QEMU, bhyve

## Forms

As locking down complex services isn't for the faint of heart, we have a catalog of
[hardened forms](docs/forms-catalog.md) that Werewolf can take: for example:

- [Caddy](forms/caddy/README.md)
- [PostgreSQL](forms/postgresql/README.md)
- [Plex](forms/plex/README.md)

We also have general-purpose runtime forms to quickly deploy a hardened app in your preferred language:

- [ASP.NET Core](examples/aspnet/README.md)
- [Go](examples/go/README.md)
- [Node.js](examples/nodejs/README.md)
- [Python](examples/python/README.md)
- [PHP](examples/php/README.md)
- [Rust](examples/rust/README.md)

## Get involved

Questions, fixes and reports from new hosts are welcome in [GitHub
issues](https://github.com/werewolf-linux/werewolf/issues); no Zig required. See the
[contribution guide](CONTRIBUTING.md). Think you've broken it? Tell us privately through
the [security policy](SECURITY.md); that's the whole point.

Licensed under [Apache 2.0](LICENSE). Sponsored by [isotope13](http://isotope13.io/).
