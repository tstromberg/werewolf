# Werewolf Linux - Battle hardened, Secure-by-default VMs

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

Werewolf Linux is an experimental, secure-by-default distro for virtual machines. Our goal is to find a way to serve
popular applications in a form that's effectively unhackable, even in the face of undocumented application or Linux 
vulnerabilities. Our mitigations prevent 48 of 49 Linux exploits in CISA's Known Exploited Vulnerabilities catalog ([survey](docs/cve-mitigation-survey.md)):

- Verified execution: Binaries can only be executed from a cryptographically verified, read-only image.
- Minimal, privilege-separated OS: Minimal surface area - most images don't even ship with a shell.
- Automatic remediation: Automatic CVE/KEV driven updates by default, with rollback on failure
- Declarative runtime confinement: Explicit syscall, filesystem, and network permissions constrain compromised components.
- Kernel lockdown: Irreversible restrictions block dangerous kernel interfaces, such as io_uring, eBPF, module loading

Werewolf is like if ChromeOS and OpenBSD had a baby: locked down, minimal, privilege seperated, with automatic updates enabled by default. It predominantly uses packages from Wolfi and Alpine, and uses Zig as it's implementation language.

## Try it

`howl` is werewolf's friendly end-user interface, it builds and boots werewolf VMs, locally or in a cloud.

```sh
git clone https://github.com/werewolf-linux/werewolf && cd werewolf
make install
howl run
```

Build your application into an immutable VM, here or in a cloud (`--on gcp`, `aws`, `azure`, `proxmox`):

```sh
howl create web --with python-app --app ./myapp
```

Tutorials: [PHP](examples/php/README.md), [Python](examples/python/README.md), [Node.js](examples/nodejs/README.md), [Go](examples/go/README.md), [Rust](examples/rust/README.md), [ASP.NET Core](examples/aspnet/README.md).

Even an application with a remote code execution bug stays contained. Don't believe us? Try to break out of this web shell:

```sh
howl run --with webshell-example
```

Prebuilt images for any cloud or hypervisor are on the [releases](https://github.com/werewolf-linux/werewolf/releases) page.

## Take over an existing VM

If your provider won't boot a custom image, `bite` installs the latest release beside Debian, Ubuntu, Fedora or Rocky and boots into it ([docs/bite.md](docs/bite.md)):

```sh
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/werewolf-linux/werewolf/main/bite)" bite -i
```

## Forms

A form is werewolf tuned to do one thing well. A few of them:

| Form | What it is |
|---|---|
| `minimal` | the smallest bootable image; no sshd |
| `prod` | DHCP, a persistent `/data` disk and automatic updates; no shell |
| `prod-ssh` | `prod` plus sshd, by security key |
| `app` | `prod` plus an unprivileged application user |
| [`bastion`](forms/bastion/README.md) | a forwarding-only SSH bastion |
| [`caddy`](forms/caddy/README.md) | a web server |
| [`cloudflared`](forms/cloudflared/README.md) | a zero-trust tunnel |
| [`tailscale`](forms/tailscale/README.md) | an unprivileged, userspace subnet router |
| [`postgresql`](forms/postgresql/README.md) | a database |
| `webshell-example` | a deliberately vulnerable web app, to show the sandbox holds |

All of them are in [forms/](forms/README.md).

## Learn more

- [docs/forms.md](docs/forms.md): forms, and building your application into one
- [docs/security.md](docs/security.md): what werewolf defends against, and how
- [docs/programs.md](docs/programs.md): the programs in `cmd/` and how each is confined
- [docs/releases.md](docs/releases.md) and [docs/updater.md](docs/updater.md): releases and updates
- [docs/data.md](docs/data.md): `/data`, disks and encryption
- [docs/roadmap.md](docs/roadmap.md): what comes next

## Contributing

Contributions are welcome; [CONTRIBUTING.md](CONTRIBUTING.md) gets you from a clone to a passing test. Report security issues privately, as [SECURITY.md](SECURITY.md) describes.

## License

[Apache 2.0](LICENSE).
