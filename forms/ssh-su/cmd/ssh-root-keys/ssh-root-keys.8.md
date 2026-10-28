# ssh-root-keys(8)

<!-- date: October 27, 2026 -->
<!-- os: Werewolf -->

## NAME

ssh-root-keys — authorize root SSH keys after checking local administrator access

## SYNOPSIS

**ssh-root-keys** *port* "ADDRESS PORT ADDRESS PORT"

## DESCRIPTION

OpenSSH invokes this command as root with its connection endpoints. The configured
listener port identifies which endpoint is the client.
For a connection originating on this machine, the command identifies the client
socket's UID in procfs and requires current membership in the wheel group.
It then prints root's authorized keys; SSH still requires a valid fresh signature.
A local client cannot bypass this check by invoking ssh directly instead of su.
An external client follows the existing root-key policy.

## FILES

/etc/passwd, /etc/group
: Current account and administrator membership.

/proc/net/tcp, /proc/net/tcp6
: Live client sockets and their owners.

/run/werewolf/keys/root
: Authorized root keys, managed by init and metadata configuration.

## EXIT STATUS

Zero means the lookup succeeded. An error produces no authorized keys.
