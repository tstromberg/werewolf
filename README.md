# Werewolf Linux — Secure-by-default VMs

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

Most Linux hardening assumes the attacker never gets root. Werewolf assumes they already
have it, and makes sure it doesn't help them.

Werewolf Linux is an experiment with a blunt goal: the most unhackable Linux or UNIX
system ever shipped. It's a declarative, immutable VM distro where every service is
presumed compromised, and root holds none of the keys that matter. We checked every
Linux vulnerability CISA lists as [exploited in the
wild](docs/cve-mitigation-survey.md) since its catalog began in 2021. Of those 49, none
would have worked against Werewolf; 48 are blocked outright, and one is only partly
mitigated, by choice.

## The ten craziest things we did

1. **Root isn't in charge.** Before any service starts, the machine is sealed with
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
6. **Interpreters that say no.** Our Python, Java, PHP and Node.js refuse to run as
   root, and each gates its favorite exploit tricks (`eval`, scripts on writable disk,
   native code, deserialization) behind root-held allowances.
7. **DNS on a leash.** Each service resolves only the names its form declares, the
   kernel says who asked, and wildcard grants refuse tunnel-shaped names, with domains
   younger than 30 days next on the list.
8. **A firewall per service.** Every packet a form doesn't declare is dropped in both
   directions, and the raw-socket capabilities to get around that are gone.
9. **Kernel settings stay set.** Root can't write `/proc/sys`, ptrace a process or read
   kernel memory, and an oops reboots the machine rather than run a damaged kernel.
10. **Exploited bugs get 15 minutes.** Machines check hourly and boot a fix for anything
    on CISA's exploited list within 15 minutes, into a signed spare slot that rolls back
    on its own if it fails.

The fine print: you must trust the hypervisor, your application's bugs are still yours,
and every host but QEMU, Lima and, with `--build`, GCP, AWS and Azure currently needs
`--disable=secureboot,tpm,ipe`. The [security guide](docs/security.md) covers every
control and its limits.

## Try it

```sh
git clone https://github.com/werewolf-linux/werewolf && cd werewolf
make install
howl run
```

`howl run` boots a signed playground image under QEMU or an arm64 Mac's Lima; `--build`
builds from source with your own keys. `howl` also deploys to FreeBSD, NetBSD, Proxmox,
AWS, GCP and Azure ([Secure Boot status](docs/cloud.md#signed-boot)).

A **form** declares a VM's software and permissions. Browse the
[catalog](docs/forms-catalog.md) (`howl forms`), start with
[Caddy](forms/caddy/README.md) or [PostgreSQL](forms/postgresql/README.md), [build your
own](docs/forms.md), or follow a tutorial: [Python](examples/python/README.md),
[PHP](examples/php/README.md), [Node.js](examples/nodejs/README.md),
[Go](examples/go/README.md), [Rust](examples/rust/README.md), [ASP.NET
Core](examples/aspnet/README.md).

## Get involved

Questions, fixes and reports from new hosts are welcome in [GitHub
issues](https://github.com/werewolf-linux/werewolf/issues); no Zig required. See the
[contribution guide](CONTRIBUTING.md). Think you've broken it? Tell us privately through
the [security policy](SECURITY.md); that's the whole point.

Licensed under [Apache 2.0](LICENSE). Sponsored by [isotope13](http://isotope13.io/).
