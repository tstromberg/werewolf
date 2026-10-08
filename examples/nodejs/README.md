# Node.js on werewolf

Run a Node.js HTTP server as the unprivileged `app` user.

Install the [build tools](../README.md#build-host), then run these commands
from the repository root.

`ARCH` defaults to your host architecture. Keep it the same for QEMU and GCP.

## Declare the app

The [form](../../forms/example-node/apko.yaml) inherits `node.yaml` and replaces
[server.js](../../forms/example-node/rootfs/usr/lib/app/server.js). The parent supplies
Node.js, the service and network settings, and inherits its user from `app`.

A form declares the machine's packages, users, services and network permissions.
Keep it with your code in version control. Building changes into a read-only
image gives each replacement VM the same starting configuration.

## Build and run

```sh
make -C examples/nodejs image
make -C examples/nodejs deploy-qemu

# In another terminal:
curl -f http://127.0.0.1:8080/
curl -f http://127.0.0.1:8080/health
```

You should see `Hello from Node.js on werewolf!` and `ok`.
Quit QEMU with `Ctrl-a x`. Relaunching preserves the VM's data and updates;
to try rebuilt code, choose a [fresh QEMU disk](../README.md#what-the-makefiles-do).

For npm dependencies, commit `package-lock.json`, run `npm ci --omit=dev` on
Linux with the guest's architecture and Node.js version, and include
`node_modules/` with the app.

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once) to set
`GCP_PROJECT`, `GCP_BUCKET` and `GCP_SOURCE_RANGES`, then:

```sh
make -C examples/nodejs deploy-gcp
```

Open the printed URL, then visit `/health`. To read the boot log:

```sh
make -C examples/nodejs serial-gcp
```

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

Node.js within its declared package stream and the kernel update automatically.
JavaScript and npm dependencies stay as built; changes to those, or a Node.js
major-version upgrade, need a new image.

For application changes, rebuild, test with a fresh QEMU disk, then deploy
under a new name:

```sh
make -C examples/nodejs deploy-gcp GCP_NAME=werewolf-nodejs-v2
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove)
for package refreshes and rollback details.

## Clean up

These commands remove the example VMs, their disks and data, and deployment
resources. The shared bucket stays.

```sh
make -C examples/nodejs delete-gcp
# If you deployed v2:
make -C examples/nodejs delete-gcp GCP_NAME=werewolf-nodejs-v2
```

Use the same settings as deployment. [Cleanup details](../README.md#change-update-and-remove).
