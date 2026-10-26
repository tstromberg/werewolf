# seal(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

seal — display the machine's system call policy and refusals

## SYNOPSIS

**seal**

## DESCRIPTION

The **seal** utility reports the machine seal's mode, the machine's promises, each
service's pledge, and system calls refused during this boot. It also lists calls that
are never allowed. It does not change policy.

The seal is a seccomp filter installed by init(8) and inherited by its descendants.
Neither root nor a service can remove it. leash(8) adds a service's own filter; calls
that filter refuses do not reach seal-watch(8) and do not appear in the machine's
refusal counts.

## FILES

- `/run/werewolf/seal/policy`

  Policy installed at boot.

- `/run/werewolf/seal/refused`

  Refusal counts maintained by the listener.

- `/etc/sv/*/service`

  Service declarations and pledges.

## EXIT STATUS

The **seal** utility exits 0 on success, and >0 if an error occurs.

## SEE ALSO

init(8), leash(8), posture(8), seal-watch(8)
