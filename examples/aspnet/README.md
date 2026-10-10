# ASP.NET Core on werewolf

Run a small C# HTTP service as the unprivileged `app` user.

Install the [build tools](../README.md#build-host) and the
[.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), then run
these commands from the repository root.

## Declare the app

The [form](../../forms/aspnet-example/form.yaml) inherits `app.yaml` and adds
Wolfi's ASP.NET Core 10 runtime. Its [service](../../forms/aspnet-example/rootfs/etc/sv/app/service)
runs [Program.cs](Program.cs), published as `/usr/lib/app/App.dll`, on port 8080.
The SDK stays on the build host.

The service disables file watching and diagnostic sockets. Its JIT uses
writable/executable anonymous memory; executable memfds stay blocked.

A form declares packages, users, services and network permissions. Keep it
with your code in version control. Build changes into a read-only image so
each replacement VM starts with the same configuration.

## Build and run

```sh
build/host/howl run --with aspnet-example
curl -f http://ADDRESS/          # ADDRESS as run printed it
curl -f http://ADDRESS/health
build/host/howl stop
```

You should see `Hello from ASP.NET Core on werewolf!` and `ok`. On a Mac `run` boots
the machine under Lima, at its own address, port 8080; elsewhere, or with
`--on qemu`, under QEMU, on a loopback port forwarded to it. Each `run`
replaces the last machine, so it boots what you last built, with an empty
`/data` ([the tutorials' guide](../README.md#with-werewolf)).

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once), then:

```sh
build/host/howl create aspnet --with aspnet-example --on gcp --allow-from me
build/host/howl console aspnet --on gcp     # the boot log
```

Open `http://ADDRESS:8080/`, at the address create printed, then visit `/health`.

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

This is a [framework-dependent application](https://learn.microsoft.com/en-us/dotnet/core/deploying/#publish-as-framework-dependent):
Wolfi's .NET 10 runtime packages and the kernel update automatically. Your
code and any NuGet dependencies stay as built. Changes to those need a new
image, as does a .NET major-version upgrade.
After changing only the SDK, remove `build/*/aspnet-example*/application.stamp`
so the next build publishes the app again.

For application changes, rebuild, try it here, then create a machine under a
new name:

```sh
build/host/howl create aspnet-v2 --with aspnet-example --on gcp --allow-from me
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove).

## Clean up

These commands delete the machines, their disks and data, and their
firewall rules. The image stays ([details](../README.md#change-update-and-remove)).

```sh
build/host/howl delete aspnet --on gcp
build/host/howl delete aspnet-v2 --on gcp   # if you made it
```
