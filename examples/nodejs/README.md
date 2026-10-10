# Node.js on werewolf

Run a Node.js HTTP server as the unprivileged `app` user.

Install the [build tools](../README.md#build-host), then run these commands
from the repository root.

## Declare the app

The [form](../../forms/node-example/form.yaml) builds on
[node-app](../../forms/node-app/form.yaml), which supplies Node.js, a
[service](../../forms/node-app/form.yaml) that starts
`/usr/lib/app/server.js`, and its network settings, and ships no
application. The example brings
[server.js](../../forms/node-example/rootfs/usr/lib/app/server.js). The
service's `app` user gets its account from the build. Your own application
is `--with node-app --app ./myapp`, with `./myapp/server.js`.

A form declares the machine's packages, users, services and network permissions.
Keep it with your code in version control. Building changes into a read-only
image gives each replacement VM the same starting configuration.

## Build and run

```sh
build/host/howl run --with node-example
curl -f http://ADDRESS/          # ADDRESS as run printed it
curl -f http://ADDRESS/health
build/host/howl stop
```

You should see `Hello from Node.js on werewolf!` and `ok`. On a Mac `run` boots
the machine under Lima, at its own address, port 8080; elsewhere, or with
`--on qemu`, under QEMU, on a loopback port forwarded to it. Each `run`
replaces the last machine, so it boots what you last built, with an empty
`/data` ([the tutorials' guide](../README.md#with-werewolf)).

For npm dependencies, commit `package-lock.json`, run `npm ci --omit=dev` on
Linux with the guest's architecture and Node.js version, and include
`node_modules/` with the app.

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once), then:

```sh
build/host/howl create node --with node-example --on gcp --allow-from me
build/host/howl console node --on gcp     # the boot log
```

Open `http://ADDRESS:8080/`, at the address create printed, then visit `/health`.

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

Node.js within its declared package stream and the kernel update automatically.
JavaScript and npm dependencies stay as built; changes to those, or a Node.js
major-version upgrade, need a new image.

For application changes, rebuild, try it here, then create a machine under a
new name:

```sh
build/host/howl create node-v2 --with node-example --on gcp --allow-from me
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove)
for package refreshes and rollback details.

## Clean up

These commands delete the machines, their disks and data, and their
firewall rules. The image stays ([details](../README.md#change-update-and-remove)).

```sh
build/host/howl delete node --on gcp
build/host/howl delete node-v2 --on gcp   # if you made it
```
