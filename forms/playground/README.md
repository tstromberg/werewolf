# Playground

The default `howl run` environment provides an interactive SSH shell and accepts
ordinary SSH key files. Its software and permissions are in [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/playground/index.html).

## Getting started

Follow the [installation steps](../../README.md#try-it), then run:

```sh
howl run
```

Howl downloads a protected image for x86_64 QEMU on Linux or arm64 Lima on macOS,
authenticates it, and enrolls the VM with Secure Boot and a persistent TPM.
Use `howl ssh` to connect, `howl stop` to stop it, and `howl run` to resume it.
`howl run --build` builds from the checkout with local signing credentials.

## Image downloads and updates

The x86_64 QEMU qcow2 is available on [GitHub
Releases](https://github.com/werewolf-linux/werewolf/releases). Follow the [download and
verification instructions](../../docs/form-images.md#downloading-a-protected-qcow2)
before using a standalone disk. Other forms and hosts have different [image
availability](../../docs/forms-catalog.md#images-and-downloads).

Howl keeps vendor code signatures separate from the machine's owner keys.
Its host service fetches authenticated vendor updates; the guest stages signed
A/B slots according to its [update policy](../../docs/updater.md).
Keep the host service and the machine's enrollment and TPM state. Importing the
qcow2 alone does not create them or provide the complete protected deployment.
