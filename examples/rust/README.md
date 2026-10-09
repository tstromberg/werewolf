# Rust on werewolf

Build a small Rust HTTP server and run it as the unprivileged `app` user.
The VM needs no Rust compiler.

Install the [build tools](../README.md#build-host), then run these commands
from the repository root.

## Declare the app

The [form](../../forms/rust-example/apko.yaml) inherits `app.yaml`, which adds an
application user to `prod`. It declares the service and port 8080.
[main.rs](main.rs) is compiled into a static Linux executable installed at
`/usr/lib/app/server`.
This example uses no third-party crates; use an HTTP framework as your app grows.

A form declares the machine's packages, users, services and network permissions.
Keep it with your code in version control. Building changes into a read-only
image gives each replacement VM the same starting configuration.

## Build and run

```sh
build/host/howl run --with rust-example
curl -f http://ADDRESS/          # ADDRESS as run printed it
curl -f http://ADDRESS/health
build/host/howl stop
```

You should see `Hello from Rust on werewolf!` and `ok`. On a Mac `run` boots
the machine under Lima, at its own address, port 8080; elsewhere, or with
`--on qemu`, under QEMU, on a loopback port forwarded to it. Each `run`
replaces the last machine, so it boots what you last built, with an empty
`/data` ([the tutorials' guide](../README.md#with-werewolf)).

Install rustup and the Linux musl targets listed in the
[build prerequisites](../README.md#build-host). The build selects the target
and uses Rust's bundled linker.

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once), then:

```sh
build/host/howl create rust --with rust-example --on gcp --allow-from me
build/host/howl console rust --on gcp     # the boot log
```

Open `http://ADDRESS:8080/`, at the address create printed, then visit `/health`.

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

Wolfi packages and the kernel update automatically. Rust's standard library,
musl and any linked crates stay inside the compiled app; updating them or
your code requires rebuilding the image with the updated toolchain and dependencies.
After changing only the toolchain, remove `build/*/rust-example*/application`
so the next build compiles the app again.

For application changes, rebuild, try it here, then create a machine under a
new name:

```sh
build/host/howl create rust-v2 --with rust-example --on gcp --allow-from me
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove)
for package refreshes and rollback details.

## Clean up

These commands delete the machines, their disks and data, and their
firewall rules. The image stays ([details](../README.md#change-update-and-remove)).

```sh
build/host/howl delete rust --on gcp
build/host/howl delete rust-v2 --on gcp   # if you made it
```
