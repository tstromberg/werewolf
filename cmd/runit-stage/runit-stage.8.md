# runit-stage(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

runit-stage — run the system's supervision and shutdown stages

## SYNOPSIS

**/etc/runit/1**

**/etc/runit/2**

**/etc/runit/3**

## DESCRIPTION

The **runit-stage** program implements runit's three stages. The basename used to
invoke it selects the stage; it does not accept a stage number as an argument.

- Stage 1

  Return immediately. The initial setup was already performed by init(8).

- Stage 2

  Give services a blocking console and execute runsvdir for /etc/sv. Failure to
  execute the supervisor exits with status 111 so runit retries.

- Stage 3

  Stop applications, drain the logger and ask mount-broker(8) to unmount persistent
  storage and close encrypted data mappings. Shutdown waits are bounded.

These entry points are for runit and require the boot environment and inherited broker
channels. An unrecognized invocation name exits with status 2.

## SEE ALSO

init(8), leash-reap(8), mount-broker(8), reboot(8), syslogd(8)
