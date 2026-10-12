# Werewolf Linux — Secure-by-default VMs

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

Werewolf Linux is an ambitious experiment to create unhackable (yet useful) Linux VMs.

Our goal is to keep application compromises contained; even in the face of vulnerabilities:
even a webshell running as root shouldn't be vulnerable to most zero-day kernel exploits.
In our review against the CISA KEV catalog of exploited Linux vulnerabilities - Werewolf
prevents 49 out of 50 of them by virtue of it's protections.

Think ChromeOS meets OpenBSD: verified, read-only system images, automatic updates,
a minimal OS and privilege separation. Services get explicit system-call, filesystem
and network permissions that gaining root cannot remove. Werewolf uses packages
from Wolfi and Alpine; its own programs are written in Zig.

## Try it

`howl` builds and starts VMs on Linux and macOS, with experimental FreeBSD and
NetBSD support (`gmake` instead of `make`). This creates a local playground based
on the best available local VM manager (lima, qemu, firecracker, etc):

```sh
git clone https://github.com/werewolf-linux/werewolf && cd werewolf
make install
howl run
```

To deploy a locked-down Python app on GCP, try something like this:

```sh
howl create web --on gcp --with python-app --app ./myapp
```

Tutorials: [Python](examples/python/README.md), [PHP](examples/php/README.md),
[Node.js](examples/nodejs/README.md), [Go](examples/go/README.md),
[Rust](examples/rust/README.md), [ASP.NET Core](examples/aspnet/README.md).
Prebuilt images are on the [releases page](https://github.com/werewolf-linux/werewolf/releases).

## Choose a form and host

A **form** declares packages, services and permissions. Choose [Caddy](forms/caddy/README.md),
[PostgreSQL](forms/postgresql/README.md), an [SSH bastion](forms/bastion/README.md),
or [build your own](docs/forms.md). The [catalog](forms/README.md) includes production
bases and a deliberately vulnerable `webshell-example` for testing confinement.

## Secure Boot

Secure Boot authenticates the kernel, early boot code and root filesystem hash.

| Provider | Werewolf Secure Boot | Caveats |
|---|---|---|
| QEMU | Verified, x86_64 and arm64 | Enrolled firmware; x86 needs SMM, arm64 uses immutable variables |
| AWS EC2 | Verified, arm64 | Custom UEFI enrollment; NitroTPM alone does not protect rollback |
| Google Compute Engine | Verified, arm64 | Custom Shielded VM keys; vTPM alone does not protect rollback |
| Azure Trusted Launch | Deployment blocked | Custom enrollment inconsistently leaves firmware in setup mode; boot refuses |
| Lima QEMU | Verified, arm64 Mac | Explicit debug firmware arguments; normal `howl --on lima` uses VZ |
| Lima VZ / Firecracker | Unsupported | No usable enrollment; Secure Boot-required images refuse to boot |
| bhyve | Manual enrollment verified, x86_64 | Bilbo firmware test; `howl` enrollment and arm64 backend remain unfinished |
| Proxmox VE | Unverified | `howl` enrollment unfinished; no test node available |
| Existing VMs converted with `bite` | Unverified | Existing bootloader authentication is unfinished |

A/B updates must retain the previous good slot after commit. Protected rollback
prevention remains unfinished, even with a TPM. See
[provider recovery tests](docs/testing.md#provider-ab-upgrades-and-rollbacks),
[cloud setup](docs/cloud.md#signed-boot) and [boot tests](docs/testing.md#secure-boot).
[`bite`](docs/bite.md) can replace an existing distro and deletes it after a successful
migration. Verifying the existing bootloader's authenticity remains unfinished.

## Security and updates

Before starting services, Werewolf disables kernel module loading and prevents
services from changing kernel security settings, even as root. Development images
can relax some restrictions. Posture checks test the running machine's protections;
the [security guide](docs/security.md) explains the controls and trusted helpers.
Our [CVE survey](docs/cve-mitigation-survey.md) checks whether known exploits have
the conditions they need to work; it does not report tests of those exploits.

The [updater](docs/updater.md) prioritizes known exploited vulnerabilities and keeps
two system images so a failed update can return to the previous one. Signed images
need updates signed by a key the machine trusts. Protection against booting older
signed images remains unfinished. You must update your application code and
the dependencies bundled with it.

## Get involved

Questions, documentation fixes and reports from different hosts are welcome in
[GitHub issues](https://github.com/werewolf-linux/werewolf/issues); no Zig knowledge
is needed. The [contribution guide](CONTRIBUTING.md) covers setup, tests and first
contributions. Discuss larger changes early. Report vulnerabilities privately
through the [security policy](SECURITY.md).

Licensed under [Apache 2.0](LICENSE).
