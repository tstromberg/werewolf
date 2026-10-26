# seal-watch(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

seal-watch — answer and record machine seal notifications

## SYNOPSIS

**seal-watch**

## DESCRIPTION

The **seal-watch** listener receives a seccomp notification descriptor and mode from
init(8) over its standard-input socket. It has no interactive command interface. In
enforcing mode, it returns ENOSYS for system calls outside the machine's promises,
logs each refused call once, and maintains refusal counts for seal(8).

After setup it runs as _seal, without capabilities, under confinement. It ignores
termination signals until final shutdown so callers continue to receive answers. If no
listener arrives from init, it exits with status 1.

Learning mode is selected by boot setup and permits observations used to construct
policy. Per-service pledge refusals return ENOSYS directly and do not reach this
listener.

## FILES

- `/run/werewolf/seal/refused`

  Refusal counts for the current boot.

## SEE ALSO

init(8), leash(8), seal(8)
