# crash-log

## Summary

crash-log.so is preloaded into a process so a fatal signal names the
instruction. Suricata dies with SIGILL and writes nothing after its
exception policy; the kernel record has the signal and not the address.

## Background

A handler installed by a parent does not survive `exec`. The dynamic
linker runs this library's constructor in the new process, before the
program's own, so the handler is in place for the whole run. Pledge
already allows `rt_sigaction` and `write`.

## Goals

- stderr, and `CRASH_LOG` when it names a file, get the signal, its
  code, the fault address, the pc, the instruction, the exception
  syndrome and the mapping that holds the address.
- The process then exits. It does not resume the faulting instruction.

## Non-Goals

- Decoding the instruction or choosing a fix.
- Catching anything but SIGILL, SIGTRAP, SIGBUS and SIGSEGV.

## Detailed design

The constructor installs one handler for those four signals. The
fault address is `siginfo`'s `si_addr`. The aarch64 context puts the
pc 432 bytes in, and the syndrome in the reserved area under the
magic `ESR`. The mapping and the instruction come from
`/proc/self/maps`. A second fault in the handler exits at once.

## Drawbacks

The process exits 128 plus the signal, so the kernel's own audit no
longer records the signal as an unhandled death. The line on stderr is
the record.

## Alternatives Considered

Raising Suricata's log level shows the last message it chose to write,
not the instruction. ptrace is refused, so a debugger cannot read the
pc after the fact.
