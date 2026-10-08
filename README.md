# Werewolf Linux
So secure, that you can just give out the root password.

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

Werewolf Linux is an experimental, secure-by-default, high-performance distro for Virtual Machines. It combines an assortment of wacky ideas that make it appropriate for heavily locked down 

* Secure-by-default: heavily influenced by OpenBSD (pledge) and ChromeOS (dm-verity)
* Declarative: influenced by Wolfi (apko) and NixOS; except you can just declare an entire VM as a CLI one-liner.
* Minimalist: inspired by Chainguard - our minimal image doesn't even include a shell
* Auto-update: inspired by Microsoft (on by default) and ChromeOS (A/B partitions)

In a recent review, we found that our [Werewolf Linux prevents 48 of 49 Linux CISA KEV exploits](docs/cve-mitigation-survey.md) - even if still shippde the vulnerable component.

## Try it

The easiest way to get started is via `howl`, our CLI tool that builds and deploys Werewolf VMs in local or remote providers. To install it, run:

```sh
make install
```

This builds and boots a local VM running Werewolf:

```sh
howl run
```

You can also just browse our [releases](https://github.com/werewolf-linux/werewolf/releases) page for pre-built images
that can be used by any Cloud or VM provider. That's just the beginning though; where things get wild is how you are able to declaratively define an immutable VM that securely runs your favorite application:

```sh
howl create web --with python --app ./myapp
```

For more info on application-based VMs, see [PHP](examples/php/README.md), [Python](examples/python/README.md),
[Node.js](examples/nodejs/README.md), [Go](examples/go/README.md),
[Rust](examples/rust/README.md) or [ASP.NET Core](examples/aspnet/README.md).

Even if your application had an RCE, it would fail. Don't believe me, try to hack into this webshell demo:

```sh
howl run --with webshell-example
```

## Forms

Forms are pre-baked secure spinoffs of Werewolf Linux, tuned to do one thing and do it well:

| Form | What it is |
|---|---|
| `minimal` | the basic bootable image, no sshd |
| `prod` | Includes a DHCP client, persistent `/data` disk, and automatic updates. No shell though. |
| `app` | `prod` plus an unprivileged application user and group; no runtime |
| `prod-ssh` | `prod` plus sshd, by security key |
| `bastion` | forwarding-only SSH bastion, its users, keys and destinations in your form ([docs](forms/bastion/README.md)) |
| `cloudflared` | zero-trust tunnel ([docs](examples/cloudflared/README.md)) |
| `tailscale` | unprivileged, userspace subnet router ([docs](examples/tailscale/README.md)) |
| `caddy` | webserver ([docs](examples/tailscale/README.md)) |
TODO(fill in)
| `webshell-example` | a deliberately vulnerable web app, to show the sandbox holds (`make webshell-demo`) |

## Take over an existing VM

Does your favorite VM provider not allow custom boots? Werewolf Linux can take over an existing installation in a single-line (see [docs/bite.md](docs/bite.md)):

```
curl -L https://raw.githubusercontent.com/werewolf-linux/werewolf/refs/heads/main/bite | sudo bash -
```

## Documentation

- [examples/](examples/README.md): shared build tools and QEMU/GCP setup for the application tutorials
- [docs/forms.md](docs/forms.md): the forms, and building your application into one
- [docs/programs.md](docs/programs.md): the programs in `cmd/` and what confines them in `lib/`
- [docs/data.md](docs/data.md): `/data`, disks and encryption
- [docs/roadmap.md](docs/roadmap.md): what comes next
