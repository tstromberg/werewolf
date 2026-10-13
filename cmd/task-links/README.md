# task-links

## Summary

A private helper reads process executable and working-directory link names for mount-broker.

## Background

Kernel `/proc/PID/{exe,cwd}` checks require tracing authority for non-dumpable processes.
The mount broker drops that authority, so it cannot identify supervised slot services directly.

## Goals

- Identify real service executables and directories without widening the mount broker's capabilities.
- Retain no ability to read or write process memory, attach a tracer or open files.

## Non-Goals

- Expose a named socket, accept arbitrary paths or authorize mount operations.

## Detailed design

Init starts the helper before dropping CAP_SYS_PTRACE, with a private socket on stdin.
Only mount-broker receives the other endpoint, after init seals the machine.
The helper retains CAP_SYS_PTRACE alone and then installs a restrictive seccomp filter.
It accepts fixed-size requests containing a positive bounded PID and either `exe` or `cwd`.
Responses contain at most 255 bytes; failed/truncated links produce an empty refusal.
The broker still pins the caller and checks its executable, argv, cwd and supervisor context.
Missing or dead helpers fail closed; there is no less strict identity fallback.

## Drawbacks

- Adds a privileged process and private IPC to the authentication path.

## Alternatives Considered

- Granting tracing authority to the mount broker also grants it process-memory access.
- Making every service dumpable weakens the process isolation used by guest-root defenses.
- Trusting argv alone allows a root shell to impersonate a slot service.

## Security Considerations

The filter permits only read/write on the private socket, readlinkat and process exit.
File opening, ptrace, process_vm_readv/writev, memory mapping, execution and mounting are refused.
The helper cannot turn its tracing capability into process-memory access through an allowed syscall.
The IPC is not mounted or named; services cannot connect to it or inherit its descriptor.
Executable/directory names are metadata, and neither keys nor configuration contents enter the helper.

## Reliability Considerations

EOF terminates the helper; malformed frames and unavailable metadata refuse authentication.
Default Lima lifecycle tests must prove normal commit and A/B rollback alongside forged-service rejection.
