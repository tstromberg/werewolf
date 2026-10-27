# init(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

init — initialize the verified system and start supervision

## SYNOPSIS

**/init**

## DESCRIPTION

The Werewolf **init** program runs as process 1 after stage0(8) has opened the
verified root. It mounts runtime filesystems, configures kernel protections, reads
boot configuration, brings up networking and persistent storage, installs the machine
seal, and executes fence(8) to start runit. It is a boot program, not an operator
interface to the running supervisor.

Configuration comes from the image, validated `werewolf.*` kernel arguments and the
boot configuration archive. Cloud metadata is used when appropriate. Archive entries
must be plain relative names for directories or regular files; links and oversized
files are refused. No provisioning shell script is executed.

The mount broker, DHCP renewal and domain-age authority start before fence removes
privileges needed for their setup. Service programs then run under the machine's seal
and filesystem policy. Failure of a required protection stops boot. Other failed
setup steps are logged and boot proceeds where possible. Only a blank data disk may
be formatted automatically.

## FILES

- `/proc/cmdline`

  Kernel arguments.

- `/run/config`

  Validated machine configuration.

- `/run/werewolf`

  Runtime state and boot records.

- `/data`

  Persistent data, or temporary storage when persistence is unavailable.

## SEE ALSO

cloud-metadata(8), dhcp-client(8), fence(8), mount(8), runit-stage(8), seal-watch(8),
stage0(8)
