# Playground

The default `howl run` environment provides an interactive SSH shell and accepts
ordinary SSH key files. Its software and permissions are in [form.yaml](form.yaml).
It includes our hardened Python 3.15 and BusyBox tools; mksh supplies `/bin/sh`.
Chard is available to root and ordinary users as `/usr/bin/chard` for hardening
inspection (`chard elf /usr/bin/chard`).
Guest command manuals are installed in `/usr/share/man`. Use `man posture`,
`man seal`, `man slot-update` or `man su` in the machine to read them.
[SSH-backed su](../ssh-su/README.md) accepts software keys for the local VM.
The root key must be available through a forwarded agent. Root and
people may look up any name through unwound, audited, and connect to TCP 22, 80,
443, 8000 and 8080 anywhere; everything else stays closed.

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/playground/index.html).

## Getting started

Follow the [installation steps](../../README.md#try-it), then run:

```sh
howl run
```

Howl downloads a protected image for x86_64 QEMU on Linux or arm64 Lima on macOS,
authenticates it, and enrolls the VM with Secure Boot and a TPM its first boot takes.
Use `howl ssh` to connect, `howl stop` to stop it, and `howl run` to resume it.
`howl run --build` builds from the checkout with local signing credentials.

## Image downloads and updates

The x86_64 QEMU qcow2 is available on [GitHub
Releases](https://github.com/werewolf-linux/werewolf/releases). Follow the [download
and verification instructions](../../docs/form-images.md#downloading-images) before
using a standalone disk. Other forms and hosts have different [image
availability](../../docs/forms-catalog.md#images-and-downloads).

The machine fetches signed vendor updates from werewolf's public channel itself and
stages A/B slots according to its [update policy](../../docs/updater.md); no host
service takes part. Keep the machine's firmware variables and TPM state. Importing
the qcow2 alone does not enroll them or provide the complete protected deployment.
