# leash-reap(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

leash-reap — kill the remaining processes of a stopped service

## SYNOPSIS

**/etc/sv/NAME/finish** [*status signal*]

## DESCRIPTION

The **leash-reap** helper is a leashed service's runit finish program. It derives the
service name from its working directory, writes cgroup.kill, reports the remaining
process count and waits for the processes to die. The exit status arguments supplied
by runsv are ignored.

Detached children remain in the service's cgroup and are killed too. The helper runs
as root after a stop, restart, crash or shutdown, before runsv starts the service
again. On systems without cgroup2 it does nothing.

## FILES

- `/run/cgroup/svc/NAME`

  Service cgroup created by leash.

## SEE ALSO

leash(8), runit-stage(8)
