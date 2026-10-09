# Werewolf Linux
So secure that you can just give out the root password.

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

Werewolf Linux is an experimental, secure-by-default distro for virtual machines:

* **Locked down**: a read-only, verified root (ChromeOS's dm-verity) and every program confined by promises (OpenBSD's pledge).
* **Declarative**: a VM is a form plus a few flags, built from Wolfi packages (apko), like NixOS but as a one-liner.
* **Minimal**: production images carry no shell (Chainguard).
* **Self-updating**: on by default, into A/B slots that roll back on failure (ChromeOS).

None of the 49 Linux exploits in CISA's Known Exploited Vulnerabilities catalog would have worked against werewolf as it ships: 36 because the component isn't there, 12 because hardening stops them, and 1 we accept by choice ([survey](docs/cve-mitigation-survey.md)).

## Try it

`howl` is werewolf's command: it builds and boots werewolf VMs, locally or in a cloud.

```sh
git clone https://github.com/werewolf-linux/werewolf && cd werewolf
make install   # installs howl, and the tools it needs
howl run       # builds and boots a werewolf VM here
```

Build your application into an immutable VM, here or in a cloud (`--on gcp`, `aws`, `azure`, `proxmox`):

```sh
howl create web --with python --app ./myapp
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
