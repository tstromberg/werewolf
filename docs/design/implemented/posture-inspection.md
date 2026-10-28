# Privileged posture inspection

**Status:** Implemented
[2026-10-17](https://github.com/werewolf-linux/werewolf/commit/168643df)

## Summary

Keep posture's protected inspection in one short-lived root process. Bound the
inputs it reads and stop its service without executing another program.

## Background

Posture inspects protected account files, other users' processes, kernel audit
records, IPE policy and stage0's TPM floor record. It also proves that forbidden
opens, writes and executions fail. Dropping root changes those observations: DAC
refusals could masquerade as kernel enforcement, and protected inspections could be
skipped.

## Goals

- Preserve protected inspection and genuine refusal evidence.
- Prevent mutable evidence from blocking on a FIFO or growing without a bound.
- End service execution after one report, with no final privileged exec.

## Non-Goals

- A general privileged inspection broker or a new service identity.
- A complete wall-clock bound for an inspection of arbitrary Linux mounts.

## Detailed design

Entry closes descriptors above stderr. The service waits at most 60 seconds for
other services to settle, inspects once, publishes its report and MOTD, then parks.
It opens only its own supervisor's control pipe, drops capabilities with errors
propagated, writes `d`, and exits. No service command or path comes from a report.

Evidence comes from kernel interfaces, immutable image metadata, account records,
service status and limited mutable update state. Text and ELF probes open with
O_NONBLOCK and accept only regular files after checking the opened descriptor.
Trusted symlinks and size-zero procfs files remain readable. Streaming reads stop
at 16 MiB. The separate nonblocking kernel-log reader also caps read attempts,
including overwritten-record retries, so a producer cannot extend it indefinitely.

Directory walks stay on the root filesystem, do not follow symlinks, and stop at
depth 40. Unprivileged attack probes fork and change identity before making raw
syscalls. Full attacks remain opt-in through the existing check mode or CLI flag.

## Drawbacks

Inspection still parses bounded host evidence as root. A very large audit log can
lose evidence beyond the read bound, which must not be treated as a proven refusal.
The settle limit does not bound all filesystem or device latency.

## Alternatives Considered

- Drop root before inspection: skips protected evidence and weakens refusal proofs.
- Snapshot everything through a root broker: creates a broad path, process and device
  interface while the broker still needs the same parsing and privileged probes.
- Fork only to format a report: moves trusted in-memory formatting, leaving the
  meaningful input parsing and inspection authority in the root process.
- Chroot the inspector: hides the host paths it must independently measure.

## Security Considerations

Fence and the seal remain in force. No new capability, syscall or filesystem grant
is added. The service consumes no remote protocol or arbitrary command stream.
No descriptor above stderr survives entry; evidence handles close after use. A
planted FIFO or device is not consumed as report text. Account ownership and kernel
protection settings remain unchanged.

## Reliability Considerations

Failures to drop capabilities or park propagate instead of being ignored. Unit
tests cover regular files, symlinks, procfs, FIFOs and devices. Guest checks cover
service parking, concurrent attack probes, stale scratch and fresh audit evidence.
