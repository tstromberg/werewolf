# misp-serve

## Summary

misp-serve starts PHP, on loopback, and one of each MISP worker. The list is the
program. Nothing else can add to it.

## Background

The image runs supervisord, which is Python, as root, so it can switch its children
to `www-data`. It also opens a control socket. On this form the leash has already
become `_oci-misp`, and the web process is that same user. A control socket would let
a request start whatever the leash allows.

## Goals

- PHP listens on `127.0.0.1:8080` and nowhere else.
- The workers are the five queues and the scheduler, one each.
- The service executes no Python. The check `misp-serve` finds `misp-serve` and no
  `python` or `supervisord` in the service's processes.

## Non-Goals

- A supervisor control socket, or a config file of programs.
- Running the web process and the workers as different users. They share the image,
  and werewolf has no writable volume between two images.

## Detailed design

misp-run finishes the database and the administrator, then replaces itself with
misp-serve. misp-serve forks the seven programs and waits. The arguments are in the
binary. On SIGTERM, or when any child exits, it signals the others and exits. runit
starts the service again. Workers use Cake's PHP entrypoint directly, without its
shell wrapper or a PATH lookup. Bash is only for the bootstrap; Python never runs.

Before spawning, the launcher refuses inherited administrator, GPG or supervisor
password variables. Its start record reports that check and the local database/Redis
settings as booleans, without logging values. Tests inspect that record; they do not
read another sandbox's private process environment.

## Drawbacks

One worker exiting restarts PHP as well. That is the whole service coming back,
rather than a process left running with no one watching it.

## Alternatives Considered

- supervisord without `user=root`. It would still be Python, and its socket would
  still be a way to start programs.
- Leaving the workers in the background of the shell. A worker that exited would stay
  down until the whole machine restarted.
