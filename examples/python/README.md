# Python on werewolf

Run a small Python HTTP server as the unprivileged `app` user.

Install the [build tools](../README.md#build-host), then run these commands
from the repository root.

`ARCH` defaults to your host architecture. Keep it the same for QEMU and GCP.

## Declare the app

The [form](../../forms/example-python/apko.yaml) inherits `python.yaml` and replaces
[main.py](../../forms/example-python/rootfs/usr/lib/app/main.py). The parent supplies
Python, the service and network settings, and inherits its user from `app`.
For a production application, see the [Flask and gunicorn example](../../docs/forms.md#a-python-web-server).

A form declares the machine's packages, users, services and network permissions.
Keep it with your code in version control. Building changes into a read-only
image gives each replacement VM the same starting configuration.

## Run it with werewolf

```sh
make howl
build/host/howl create example-python web --greeting "Hello from a setting"
curl -f http://ADDRESS:8080/          # the address create printed
build/host/howl delete web
```

The greeting is a setting the form declares (`etc/sv/app/service`):
`werewolf` checks it, the machine hands it to the application as
`GREETING`, and another `create` with a new `--greeting` changes it
without a rebuild. Without one, the page says `Hello from Python on
werewolf!`.

## Build and run with make

```sh
make -C examples/python image
make -C examples/python deploy-qemu

# In another terminal:
curl -f http://127.0.0.1:8080/
curl -f http://127.0.0.1:8080/health
```

You should see `Hello from Python on werewolf!` and `ok`.
Quit QEMU with `Ctrl-a x`. Relaunching preserves the VM's data and updates;
to try rebuilt code, choose a [fresh QEMU disk](../README.md#what-the-makefiles-do).

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once) to set
`GCP_PROJECT`, `GCP_BUCKET` and `GCP_SOURCE_RANGES`, then:

```sh
make -C examples/python deploy-gcp
```

Open the printed URL, then visit `/health`. To read the boot log:

```sh
make -C examples/python serial-gcp
```

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

Python, Wolfi-packaged dependencies and the kernel update automatically.
Your source code and vendored pip dependencies stay as built; changes to
those need a new image.

For application changes, rebuild, test with a fresh QEMU disk, then deploy
under a new name:

```sh
make -C examples/python deploy-gcp GCP_NAME=werewolf-python-v2
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove)
for package refreshes and rollback details.

## Clean up

These commands remove the example VMs, their disks and data, and deployment
resources. The shared bucket stays.

```sh
make -C examples/python delete-gcp
# If you deployed v2:
make -C examples/python delete-gcp GCP_NAME=werewolf-python-v2
```

Use the same settings as deployment. [Cleanup details](../README.md#change-update-and-remove).
