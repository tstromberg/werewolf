# ASP.NET Core on werewolf

Run a small C# HTTP service as the unprivileged `app` user.

Install the [build tools](../README.md#build-host) and the
[.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), then run
these commands from the repository root. `ARCH` defaults to your host
architecture; keep it the same for QEMU and GCP.

## Declare the app

The [form](../../forms/example-aspnet.yaml) inherits `app.yaml` and adds
Wolfi's ASP.NET Core 10 runtime. Its [service](../../forms/example-aspnet/etc/sv/app/service)
runs [Program.cs](Program.cs), published as `/usr/lib/app/App.dll`, on port 8080.
The SDK stays on the build host.

The service disables file watching and diagnostic sockets. Its JIT uses
writable/executable anonymous memory; executable memfds stay blocked.

A form declares packages, users, services and network permissions. Keep it
with your code in version control. Build changes into a read-only image so
each replacement VM starts with the same configuration.

## Build and run

```sh
make -C examples/aspnet image
make -C examples/aspnet deploy-qemu

# In another terminal:
curl -f http://127.0.0.1:8080/
curl -f http://127.0.0.1:8080/health
```

You should see `Hello from ASP.NET Core on werewolf!` and `ok`.
Quit QEMU with `Ctrl-a x`. Relaunching preserves data and updates; to try
rebuilt code, choose a [fresh disk](../README.md#what-the-makefiles-do).

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once), then:

```sh
make -C examples/aspnet deploy-gcp
make -C examples/aspnet serial-gcp
```

Open the printed URL, then visit `/health`.

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

This is a [framework-dependent application](https://learn.microsoft.com/en-us/dotnet/core/deploying/#publish-as-framework-dependent):
Wolfi's .NET 10 runtime packages and the kernel update automatically. Your
code and any NuGet dependencies stay as built. Changes to those need a new
image, as does a .NET major-version upgrade.
After changing only the SDK, use `make -B -C examples/aspnet image` to force
a full rebuild.

Rebuild and test changes with a fresh QEMU disk, then deploy under a new name:

```sh
make -C examples/aspnet deploy-gcp GCP_NAME=werewolf-aspnet-v2
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove).

## Clean up

These commands remove the VMs, their disks and data, and deployment resources.
The shared bucket stays.

```sh
make -C examples/aspnet delete-gcp
# If you deployed v2:
make -C examples/aspnet delete-gcp GCP_NAME=werewolf-aspnet-v2
```

Use the same settings as deployment. [Cleanup details](../README.md#change-update-and-remove).
