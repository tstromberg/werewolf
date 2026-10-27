# Missing refused-exec audit evidence

Investigated on 2026-10-13, with the last probes after midnight UTC on
2026-10-14. The gate remains failed; this report records a diagnosis in
progress, not a logging assurance or a production workaround.

## Reproduction

The clean baseline checkout at `51bedff24562de35601fe41ae724a0428d4eefbc`
reproduces `kernel-exec-log` in the minimal production appliance. PostgreSQL
and glibc-neutered are absent. The kernel is Alpine's aarch64
`6.18.56-0-virt`, booted under QEMU 11.1.2 with HVF on macOS.

The original probe returned only false on several different paths. It now
records the failed operation and syscall return/errno, the child PID and
wait status, or a timeout with the number of kernel records read. The child
reports its exec errno through its exit status; EACCES must be confirmed
before a matching audit record can pass the gate. Matching still requires
the child's PID, native execve syscall number, type 1300 and success=no.

A representative failure is:

```text
child=464: execve(/)=EACCES(13); records=6; no matching audit record within 100 ms
```

Other posture probes do produce refused-exec SYSCALL/PATH records. The
directory probe's child has no matching record in the captured console,
including after the timeout. It is not just a record-matching error.

## Controlled comparisons

Temporary experiments used the disposable checkout and appliance only.
None changes the shipped audit rule, kernel arguments or containment.

| Comparison | Result |
| --- | --- |
| Original rule, minimal production appliance | Gate fails after a confirmed EACCES; kernel records are readable. |
| Read back installed rules before locking | Native arch, failure field, syscall masks and record exclusions match the submitted rule. |
| Execute the non-executable `/etc/passwd` file | Same missing-record failure. |
| Remove arch and success field filters temporarily | Still fails; these field filters do not explain the missing evidence. |
| Add `audit=1` at boot | Still fails; also produces hold-queue overflow/lost-record messages. |
| Restore original rule with `audit=1` | Still fails. |
| Run the same directory exec immediately after audit setup, before the seal and fence | Child exits with EACCES (wait status 3328); its record is absent. |
| Remove record-type exclusions temporarily | Still fails. |

The packaged kernel config enables `CONFIG_AUDIT`, `CONFIG_AUDITSYSCALL`,
`CONFIG_HAVE_ARCH_AUDITSYSCALL` and `CONFIG_AUDIT_GENERIC`.

## Interpretation

The missing evidence reproduces without PostgreSQL, hardened libc or the
running process's containment. The actual cause within the audit path is
not yet established. No execution bypass was demonstrated. A blanket
claim that every refused exec is logged is not supported by these tests.

Keep the 100 ms gate and its failure; do not add an expected-failure entry,
substitute an unrelated audit event, relax confinement or enable a broader
production logging rule to make it pass. The next useful isolation is an
independent syscall-audit reproducer against this kernel and a second
kernel, with audit configuration and counters captured before privileges
are dropped.

Kernel references: [rule
evaluation](https://github.com/gregkh/linux/blob/v6.18.56/kernel/auditsc.c), [rule
installation](https://github.com/gregkh/linux/blob/v6.18.56/kernel/auditfilter.c),
[audit
UAPI](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/audit.h).


## Follow-up: publishing gate, 2026-10-17

The newer 7.2.11-werewolf kernel's publishing gate failed its second VM's
initial commit. The console captured the exact probe child (160), but
kauditd delivered its record after the 100 ms check had finished. The same
boot logged `audit_backlog=65 > audit_backlog_limit=64` and lost records
while the startup service and operator posture scans overlapped.

Init now reserves a bounded 8192-record backlog before locking audit.
The refused-exec rule, kernel-origin matching and 100 ms deadline remain
unchanged. Four simultaneous full posture scans in a protected guest all
matched their own refused-exec records. The concurrent posture regression
now requires that result for every scan, alongside its existing attacks.
This addresses the observed boot burst; missing evidence still fails.

## Follow-up: Grafana catalog boot, 2026-10-27

The x86_64 Grafana [catalog check][grafana-check] failed on kernel
7.3.0-werewolf with `records=0` after 100 ms. Its captured console contains
the exact child (151), native execve syscall (59), EACCES and failed SYSCALL
record. Grafana was concurrently running its initial database migrations.
This is delayed evidence, unlike the original investigation's absent record.

The probe now allows five seconds for asynchronous audit delivery. It still
returns immediately when the record arrives, follows the same log cursor,
matches the same child and kernel-origin fields, and fails on missing evidence.
Its 4096-read bound, spoof rejection, refused-exec rule, audit backlog and locked
configuration remain unchanged. This replaces the earlier 100 ms waiting budget;
it does not retry the exec or substitute another event.

[grafana-check]: https://github.com/werewolf-linux/werewolf/actions/runs/40505931736/job/122195117718
