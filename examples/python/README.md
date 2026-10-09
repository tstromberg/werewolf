# Python on werewolf

Run a small Python HTTP server as the unprivileged `app` user.

Install the [build tools](../README.md#build-host), then run these commands
from the repository root.

## Declare the app

The [form](../../forms/python-example/form.yaml) builds on
[python-app](../../forms/python-app/form.yaml), which supplies Python, a
service that starts `/usr/lib/app/main.py`, and its network settings, and
ships no application. The example brings
[main.py](../../forms/python-example/rootfs/usr/lib/app/main.py), and its
own [service](../../forms/python-example/rootfs/etc/sv/app/service), which
adds a setting. The service's `app` user gets its account from the build.
Your own application is `--with python-app --app ./myapp`, with
`./myapp/main.py`.
For a production application, see the [Flask and gunicorn example](../../docs/forms.md#a-python-web-server).

A form declares the machine's packages, users, services and network permissions.
Keep it with your code in version control. Building changes into a read-only
image gives each replacement VM the same starting configuration.

## Build and run

```sh
build/host/howl run --with python-example
curl -f http://ADDRESS/          # ADDRESS as run printed it
curl -f http://ADDRESS/health
build/host/howl stop
```

You should see `Hello from Python on werewolf!` and `ok`. On a Mac `run` boots
the machine under Lima, at its own address, port 8080; elsewhere, or with
`--on qemu`, under QEMU, on a loopback port forwarded to it. Each `run`
replaces the last machine, so it boots what you last built, with an empty
`/data` ([the tutorials' guide](../README.md#with-werewolf)).

The greeting is a setting the form declares (`etc/sv/app/service`): howl
checks it, the machine hands it to the application as `GREETING`, and a
second `create` with a new one changes it without a rebuild:

```sh
build/host/howl create web --with python-example --greeting "Hello from a setting"
build/host/howl create web --with python-example --greeting "Hello again"
build/host/howl delete web
```

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once), then:

```sh
build/host/howl create python --with python-example --on gcp --allow-from me
build/host/howl console python --on gcp     # the boot log
```

Open `http://ADDRESS:8080/`, at the address create printed, then visit `/health`.

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

Python, Wolfi-packaged dependencies and the kernel update automatically.
Your source code and vendored pip dependencies stay as built; changes to
those need a new image.

For application changes, rebuild, try it here, then create a machine under a
new name:

```sh
build/host/howl create python-v2 --with python-example --on gcp --allow-from me
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove)
for package refreshes and rollback details.

## Clean up

These commands delete the machines, their disks and data, and their
firewall rules. The image stays ([details](../README.md#change-update-and-remove)).

```sh
build/host/howl delete python --on gcp
build/host/howl delete python-v2 --on gcp   # if you made it
```
