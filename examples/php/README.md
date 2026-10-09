# PHP on werewolf

Run a PHP website with nginx and PHP-FPM, each under its own user.

Install the [build tools](../README.md#build-host), then run these commands
from the repository root.

## Declare the app

The [form](../../forms/php-example/form.yaml) builds on `php`, which
supplies nginx, php-fpm, their services and network settings, and brings
[index.php](../../forms/php-example/rootfs/usr/share/nginx/html/index.php).

A form declares the machine's packages, users, services and network permissions.
Keep it with your code in version control. Building changes into a read-only
image gives each replacement VM the same starting configuration.

## Build and run

```sh
build/host/howl run --with php-example
curl -f http://ADDRESS/          # ADDRESS as run printed it
curl -f http://ADDRESS/health
build/host/howl stop
```

You should see `Hello from PHP on werewolf!` and `ok`. On a Mac `run` boots
the machine under Lima, at its own address, port 80; elsewhere, or with
`--on qemu`, under QEMU, on a loopback port forwarded to it. Each `run`
replaces the last machine, so it boots what you last built, with an empty
`/data` ([the tutorials' guide](../README.md#with-werewolf)).

For Composer dependencies, install from `composer.lock` for the guest's PHP
version and extensions. Keep `vendor/` outside nginx's document root, for
example at `/usr/lib/app/vendor`, and load its autoloader from there.

## Deploy on GCP

Complete the [GCP setup](../README.md#prepare-gcp-once), then:

```sh
build/host/howl create php --with php-example --on gcp --allow-from me
build/host/howl console php --on gcp     # the boot log
```

Open `http://ADDRESS/`, at the address create printed, then visit `/health`.

## Automatic updates

After boot checks pass, werewolf checks for system updates, then every 20 hours.
It builds updates into a new image and reboots, keeping the previous image
for rollback. Both images share `/data`; rolling back does not undo data changes.

PHP-FPM, nginx, Wolfi-packaged extensions and the kernel update automatically.
PHP scripts and Composer dependencies stay as built; changes to those need
a new image.

For application changes, rebuild, try it here, then create a machine under a
new name:

```sh
build/host/howl create php-v2 --with php-example --on gcp --allow-from me
```

Check the new VM before moving traffic. New VMs start with empty data;
migrate any saved data first. See the [update guide](../README.md#change-update-and-remove)
for package refreshes and rollback details.

## Clean up

These commands delete the machines, their disks and data, and their
firewall rules. The image stays ([details](../README.md#change-update-and-remove)).

```sh
build/host/howl delete php --on gcp
build/host/howl delete php-v2 --on gcp   # if you made it
```
