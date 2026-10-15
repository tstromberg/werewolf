# Werewolf Linux — Secure-by-default VMs

<img src="docs/media/logo-small.png" alt="werewolf logo" width="160" align="right">

Werewolf Linux is an ambitious experiment to create unhackable (yet useful) Linux VMs.

It's a declarative, immutable Linux distro that takes a "deny-by-default" stance that
makes it impossible to run undeclared malware and (most) kernel exploits. In our review
against the [CISA KEV catalog of exploited Linux
vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=linux&field_date_added_wrapper=all&field_cve=&sort_by=field_date_added&items_per_page=20&url=),
Werewolf's protections prevent 49 of 50 from executing.

Think ChromeOS meets OpenBSD: verified, read-only system images, automatic updates,
a minimal OS and privilege separation. Services get explicit system-call, filesystem
and network permissions (pledge) that not even root can remove. It's also designed to
be auditor friendly, tracking which CVEs were resolved, and which weaknesses remain.

Werewolf uses Wolfi packages, with it's own kernel and glibc build. It's
own programs are written in Zig.

## Try it

`howl` builds and deploys VMs on macOS, Linux, FreeBSD, NetBSD, Azure, Proxmox, GCP, and
AWS. This creates a local playground based on Lima's protected QEMU backend on an arm64
Mac, or QEMU on Linux:

```sh
git clone https://github.com/werewolf-linux/werewolf && cd werewolf
make install
howl run
```

Secure mode is the default for every deployer. Plain `howl run` authenticates a
published protected image with embedded production certificates; an unpublished target
fails closed. Production downloads currently cover playground on x86_64 QEMU and arm64
Lima. `howl run --build` uses local signing credentials and cached source builds.
Existing locally signed VMs retain their trust and use `--build`; use a new machine name
for production trust. Cloud deployment currently requires an explicit opt-out:

```sh
howl create web --on gcp --with python-app --app ./myapp
```

Tutorials: [Python](examples/python/README.md), [PHP](examples/php/README.md),
[Node.js](examples/nodejs/README.md), [Go](examples/go/README.md),
[Rust](examples/rust/README.md), [ASP.NET Core](examples/aspnet/README.md).
See [image availability and downloads](docs/forms-catalog.md#images-and-downloads)
for published forms, verification and deployment instructions.

## Choose a form and host

A **form** declares the software and permissions of a VM. Browse the
[available forms](docs/forms-catalog.md) for an alphabetical list and setup guides:
web servers, databases, self-hosted applications, language runtimes and examples.
Start with [Caddy](forms/caddy/README.md), [PostgreSQL](forms/postgresql/README.md),
an [SSH bastion](forms/bastion/README.md), or [build your own](docs/forms.md).

Browse, inspect and test from the checkout:

```sh
howl forms
howl forms database
howl forms caddy
howl run --build --with caddy
howl test --with caddy
```

`howl forms --published` checks the signed image catalog for current qcow2
downloads. `howl forms NAME` links to the setup guide and configuration flags;
many services need credentials before they can start.

## Secure Boot

Secure Boot authenticates the kernel, early boot code and root filesystem hash.

| Provider | Werewolf Secure Boot | Caveats |
|---|---|---|
| QEMU | Verified, x86_64 and arm64 | Linux default includes host custody and persistent TPM; x86 needs SMM |
| AWS EC2 | Firmware verified, arm64 | Protected default blocked pending TPM custody; NitroTPM alone is insufficient |
| Google Compute Engine | Firmware verified, arm64 | Protected default blocked pending TPM custody; vTPM alone is insufficient |
| Azure Trusted Launch | Deployment blocked | Custom enrollment inconsistently leaves firmware in setup mode; boot refuses |
| Lima QEMU | Verified, arm64 Mac | Default requires signed protected downloads; local `--build` retains caller signing |
| Lima VZ / Firecracker | Unsupported | No usable enrollment; Secure Boot-required images refuse to boot |
| bhyve | Manual enrollment verified, x86_64 | Bilbo firmware test; `howl` enrollment and arm64 backend remain unfinished |
| Proxmox VE | Unverified | `howl` enrollment unfinished; no test node available |

A/B updates retain the previous good slot after commit. The secured local profile uses
TPM authorization for exactly two releases and refuses retired images. Cloud TPM
enrollment remains unfinished; enabling a vTPM alone is insufficient. See [provider
recovery tests](docs/testing-secure-boot.md#provider-ab-upgrades-and-rollbacks), [cloud
setup](docs/cloud.md#signed-boot) and [boot
tests](docs/testing-secure-boot.md#secure-boot).

## Security and updates

Before starting services, Werewolf disables kernel module loading and prevents
services from changing kernel security settings, even as root. Development images
can relax some restrictions. Posture checks test the running machine's protections;
the [security guide](docs/security.md) explains the controls and trusted helpers.
Our [CVE survey](docs/cve-mitigation-survey.md) checks whether known exploits have
the conditions they need to work; it does not report tests of those exploits.

The [updater](docs/updater.md) prioritizes known exploited vulnerabilities and keeps two
system images so a failed update can return to the previous one. Signed images need
updates signed by a key the machine trusts. The secured local profile also refuses
retired signed images while retaining A/B recovery. You must update your application
code and the dependencies bundled with it.

## Get involved

Questions, documentation fixes and reports from different hosts are welcome in
[GitHub issues](https://github.com/werewolf-linux/werewolf/issues); no Zig knowledge
is needed. The [contribution guide](CONTRIBUTING.md) covers setup, tests and first
contributions. Discuss larger changes early. Report vulnerabilities privately
through the [security policy](SECURITY.md).

Licensed under [Apache 2.0](LICENSE).

Development sponsored by [isotope13](http://isotope13.io/).
