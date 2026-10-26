# ssh-host-key(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

ssh-host-key — prepare an SSH host key and optional local host pin

## SYNOPSIS

**ssh-host-key** *key* [*copy* [*known-hosts*]]

## DESCRIPTION

The **ssh-host-key** utility prepares the host key used by the SSH service. It reuses
a valid existing key or generates one when absent. If *copy* is given, it places a
runtime copy there. If *known-hosts* is also given, it publishes the public host-key
pin used for local SSH reauthentication. All paths must be absolute.

The helper runs before sshd, inside the service's confinement. A persistent key avoids
changing the machine's identity at every boot; the runtime copy permits the daemon to
read the key from its private directory. The local pin allows strict host verification
without an interactive trust prompt.

If persistent storage is unavailable but a copy path is supplied, the helper generates
a runtime key for this boot alone. Without a copy path, missing or RAM-backed
persistent storage is an error.

## EXIT STATUS

The **ssh-host-key** utility exits 0 on success, and >0 if an error occurs.

## SEE ALSO

su(1), leash(8)
