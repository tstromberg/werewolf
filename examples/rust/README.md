# Rust on werewolf

Build a small Rust HTTP server and run it as the unprivileged `app` user.
The VM needs no Rust compiler.

Install the [build tools](../README.md#build-host), then run these commands
from the repository root.

`ARCH` defaults to your host architecture. Keep it the same for QEMU and GCP.

## Declare the app

The [form](../../forms/example-rust/apko.yaml) inherits `app.yaml`, which adds an
application user to `prod`. It declares the service and port 8080.
[main.rs](main.rs) is compiled into a static Linux executable installed at
`/usr/lib/app/server`.
This example uses no third-party crates; use an HTTP framework as your app grows.

A form declares the machine's packages, users, services and network permissions.
Keep it with your code in version control. Building changes into a read-only
image gives each replacement VM the same starting configuration.

## Build and run

```sh
make -C examples/rust image
make -C examples/rust deploy-qemu

# In another terminal:
curl -f http://127.0.0.1:8080/
curl -f http://127.0.0.1:8080/health
```

You should see `Hello from Rust on werewolf!` and `ok`.
Quit QEMU with `Ctrl-a x`. Relaunching preserves the VM's data and updates;
to try rebuilt code, choose a [fresh QEMU disk](../README.md#what-the-makefiles-do).

Install rustup and the Linux musl targets listed in the
[build prerequisites](../README.md#build-host). The Makefile selects the target
and uses Rust's bundled linker.

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once) to set
`GCP_PROJECT`, `GCP_BUCKET` and `GCP_SOURCE_RANGES`, then:

```sh
make -C examples/rust deploy-gcp
```

Open the printed URL, then visit `/health`. To read the boot log:

```sh
make -C examples/rust serial-gcp
```

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

Wolfi packages and the kernel update automatically. Rust's standard library,
musl and any linked crates stay inside the compiled app; updating them or
your code requires rebuilding the image with the updated toolchain and dependencies.
After changing only the toolchain, use `make -B -C examples/rust image` to
force a full rebuild.

For application changes, rebuild, test with a fresh QEMU disk, then deploy
under a new name:

```sh
make -C examples/rust deploy-gcp GCP_NAME=werewolf-rust-v2
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove)
for package refreshes and rollback details.

## Clean up

These commands remove the example VMs, their disks and data, and deployment
resources. The shared bucket stays.

```sh
make -C examples/rust delete-gcp
# If you deployed v2:
make -C examples/rust delete-gcp GCP_NAME=werewolf-rust-v2
```

Use the same settings as deployment. [Cleanup details](../README.md#change-update-and-remove).
