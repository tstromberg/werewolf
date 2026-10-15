# cron - Hardened VM

[supercronic](https://github.com/aptible/supercronic) runs one service's jobs. A form takes it with `with: [cron]` or `base: cron` and lays a crontab over `etc/cron/crontab`. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/cron/index.html).

## Security Posture

- supercronic runs as its own user, on a 64 MiB leash, with no listener.
- There is no shell. Each job is one program and its arguments, through sh-shim.
- A pipe, a redirection, a variable, or a `;` is refused, and the job does not start.
- The crontab is part of the image. Change a job by changing the form and creating again.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create cron --with cron
```

This form has no jobs. Schedules are crontab lines, with an optional seconds field first, in UTC. A job never overlaps its own last run. Each event is a JSON line on the console.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create cron --with cron --on gcp --allow-from me
```

`--allow-from` opens no port: there is no listener. The jobs are the form's, not this command's.

### Importing data

The jobs are in the form. There is no database to import.

### Known Quirks

- The user is `supercronic`. Wolfi already has an account named `cron`.
- The crontab's `SHELL` is sh-shim. It runs one program. It does not run a shell script.
