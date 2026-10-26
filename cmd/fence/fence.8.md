# fence(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

fence — install the machine's network and filesystem restrictions

## SYNOPSIS

**fence** *program* [*argument ...*]

## DESCRIPTION

The **fence** utility installs the image's policy and then executes *program*. At
boot, init(8) uses it to start runit. Descendants, including root sessions, inherit
restrictions they cannot remove.

Policy-routing rules deny network traffic unless the image grants it. DNS transport is
reserved for the resolver and explicitly declared DNS servers. Landlock restricts TCP
ports, filesystem writes, executable locations, signals and abstract sockets. Mounting
is forbidden. The capability bounding set loses CAP_SYS_ADMIN and, unless the form
explicitly permits them, CAP_NET_ADMIN and CAP_NET_RAW.

Writes are limited to the machine's writable runtime and data locations, declared
shared directories and permitted devices. Programs execute from the verified system or
embedded image roots. Services receive further restrictions from leash(8). The boot
sequence creates the mount broker and network renewal processes before entering this
domain.

## FILES

- `/usr/share/werewolf/net`

  Compiled network policy.

- `/run/werewolf/network`

  Detected resolver and network state.

## SEE ALSO

init(8), leash(8), mount-broker(8), posture(8), unwound(8)

## CAVEATS

Reply allowances are stateless. Broad port allowances cannot authenticate a peer;
fragmented UDP replies may lack the ports needed for matching. Failure to install
policy prevents the supervised system from starting.
