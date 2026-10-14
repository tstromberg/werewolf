# posture

`/usr/lib/werewolf/posture`, in every form, measures how a Linux machine
protects itself: ✅ passed, ❌ failed, ⚠️ skipped, as there was nothing to
check. It exits 1 if any check fails. It assumes nothing of werewolf: copy
it to any Linux machine (it is a static binary) and run it as root to
compare, or, in a checkout there, run `make posture`, which builds it and
runs it with sudo.

The `/usr/share/werewolf` directory selects werewolf
checks. Other Linux systems omit image-specific IPE policy, TPM A/B
authorization, root-device naming, updater, generated service, leash and
compiled network-policy checks. Generic kernel, mount, capability, syscall
and SSH checks still run. A copied posture binary does not identify the
host as werewolf. Generic reports do not read image allowances or excuses.

```
Ubuntu 24.04.4 LTS, Linux 6.8.0-134-generic, on lima-werewolf-ci (root)

Kernel
  ❌ Kernel lockdown                       none
  ❌ Kernel module loading closed          kernel.modules_disabled is 0
  ✅ Only signed kernel modules
  …

✅ 5 passed   ❌ 33 failed   ⚠️ 2 skipped
```

A check that does not pass says what it found; long values are shortened
with `…` to keep each item within two rows. `--json` prints everything, with what each check
protects against (`why`) and how it was checked (`how`):

```sh
posture --json | jq '.summary'          # { "pass": 24, "fail": 9, "skip": 0 }
posture --json | jq -r '.checks[] | select(.result == "fail") | .name'
```

`--summary` runs fresh checks and shows the state and counts on one line,
followed by violations. It omits the timestamp because the scan is live.
Each row states the gap and its evidence in aligned columns. Declared gaps
use an amber `gap`; unexpected failures use a red `FAIL`. The labels also
work without color. A terminal colors passes green and the EXPECTED GAPS
state amber. Redirected output, `NO_COLOR` and `TERM=dumb` suppress color.
Each gap uses one row, shortened with `…` at the terminal width; the full
evidence remains in the detailed report and `--json`.

```text
Security posture: EXPECTED GAPS · 86 passed · 5 failed · 5 skipped
  gap   Shells present            /bin/sh, /bin/ash, /bin/bash
  gap   Download / network tools  /bin/wget, /bin/nc, /bin/netcat, /bin/telnet
  gap   Interpreters present      /bin/awk
  gap   Login servers present     /bin/sshd, /bin/telnetd
  gap   SSH security key policy   ordinary keys accepted
```

Program rows show installed tools, not proof that a server is running.
The SSH row names only unmet requirements: ordinary keys accepted, touch
not enforced, or both. All gaps still count as failed checks and exit 1.

| State | Meaning |
| --- | --- |
| NOMINAL | No failed checks. |
| EXPECTED GAPS | Every failure is excused by the image's declared weaknesses. |
| DEGRADED | At least one failure is not excused. |

These describe the measured checks, not a guarantee of security. Skips
remain visible in the totals, and non-root scans label their limited
coverage separately. NOMINAL does not mean every check ran.

Playground displays this summary for interactive terminal logins via
`/etc/profile.d/posture.sh`, which covers its default ash shell and bash
login shells. To add it to your own bashrc:

```sh
case $- in
    *i*) [ ! -t 1 ] || /usr/lib/werewolf/posture --summary || : ;;
esac
```

The login summary writes only to its terminal's stdout. As with any live
scan, refusal probes produce kernel audit records which may reach the
serial console. Noninteractive SSH commands and redirected logins do not
run the login summary. Reports with failures exit 1, including expected
failures; the login hook absorbs that status so the shell stays usable.

The audit proof waits on new kernel records for up to 100 ms rather than
sleeping and rereading the whole kernel log for a second. Missing audit
evidence still fails, including when printk rate limiting suppresses it.
Failures name the failed operation and numeric errno, or the probe child's
wait status. A timeout reports the child PID, its confirmed EACCES return,
and the number of kernel records read; it does not claim that every
failure means an audit record was absent. The timeout remains 100 ms.
This improves the usual playground scan; large filesystem trees, a
metadata connection timeout or `sshd -T` can still take longer than 200 ms.

`--line` prints one line, for a console or a log: the ids that failed,
sorted, between commas (`fail=` and nothing when none did), the counts,
and then the report as JSON with only the checks that failed, each with
its excuse where the image expects it (the passes are only counted;
`--json` has them all):

```
posture: fail=programs-no-shell,programs-services-no-shell pass=37 skip=0 {"tool":"posture",…}
```

Text uses two columns: a short description and the checked expectation.
Failures use Go's test/error shape, `expression = value, want expectation`;
passes omit the redundant `want`. Each item uses one row, or two when it
wraps. Long values are shortened; the full evidence stays in `--json`.

```text
❌ Core dumps disabled     /proc/1/limits core.hard = unlimited, want 0
❌ Kernel TLS unavailable  setsockopt(TCP_ULP, tls) = ENOTCONN(107), want ENOENT|ENOSYS
✅ SYN flood protection    /proc/sys: net.ipv4.tcp_syncookies = 1
```

JSON records `source`, `expected`, `observed` and the compact `comparison`.
Sources identify exact file fields or syscall arguments. For example,
`core.hard` is the `Max core file size` row's `Hard Limit` column in
`/proc/1/limits`; the vsyscall check records the complete `[vsyscall]`
mapping row; syscall probes include return values and numeric errno.
Composite checks retain individual values and fallback sources. Expected
image exceptions retain the original evidence.

`--verbose` prints progress and timings immediately to stderr, even while
the final report is still being collected:

```sh
doas /tmp/posture --verbose
doas /tmp/posture --verbose --summary
doas /tmp/posture --verbose --json >posture.json 2>posture-timing.log
```

It announces each phase, reports every completed check with elapsed
milliseconds, names potentially slow operations before they
start (filesystem walks, SSH settings, metadata and audit probes), and
prints phase and total scan times. Long walks report their entry count
and current directory roughly once a second. Check timings cover work
since the previous result within that phase; shared setup is attributed
to the next result. Verbose output adds its own overhead, so use it to
locate expensive work, then measure the ordinary command separately.

`--extended` adds the checks werewolf fails by choice, because meeting
them would slow what the machine runs, or is not yet shown to work with
fence: wiping freed memory, forced CPU mitigations, strict
reverse-path filtering, and ignoring IPv6 router advertisements
([security.md](security.md), "Not done, by choice"). It combines with
`--json` or `--line`.

Where it is safe, a check tests rather than reads:

- **Sysctl writes**: as root, `files-system-writes` opens settings under
  `kernel`, `vm`, `user`, `fs` and `net` with `O_WRONLY` and `O_RDWR`,
  without writing. Each existing setting must return `EACCES`, and
  `kernel.printk` must exist. `kernel-log-control` also asks `syslog(2)`
  to set the current console level; it must be refused, closing the
  alternate path that `dmesg -n` uses.
- **One-way settings** (lockdown, the module loader, ptrace, BPF) must read
  locked, and writing the unlocked value must be refused. It is written
  only when the setting already reads locked, when the kernel's refusal is
  certain, so a failing check never weakens the machine.
- **Running a program from a writable place**: posture copies itself into
  `/tmp`, `/var/tmp`, `/run`, `/dev/shm`, `/dev/mqueue` and `/data`, and
  into a memfd, and runs each copy with `--noop`, which exits at once. Each
  must fail to start.
- **Old and back-door interfaces**: posture writes, through
  `/proc/self/mem`, the bytes already in one of its own read-only pages,
  and expects the write refused. On x86_64 it makes a 32-bit `getpid`
  through `int 0x80`, in a child that handles the SIGSEGV a refusal brings
  so the kernel logs nothing, and reads the LDT with `modify_ldt(2)`; both
  must be refused.
- **Mounts**: every mount is `nosuid`; every mount but `/` is `noexec`;
  every mount but `/dev` and `/dev/pts` is `nodev`. No file on the root filesystem is
  setuid or setgid.
- **Tools an intruder wants**: no shell, downloader, network tool,
  interpreter, compiler or debugger on the system's PATH directories.
- **Refused execs logged**: posture runs `/` as a program, which every
  kernel refuses, and expects the kernel's audit record of it in the
  kernel log; then asks the kernel to stop auditing, which must be refused.

It reads no other process's memory and opens no `/dev/mem`: both would put
lines in the kernel log on every boot.

A werewolf machine whose form took back a default when it was built, as
`qemu-host` takes `kvm`, says so under its first line (`Its form allows:
kvm`) and in the JSON's `allow`. The checks still measure it: such a
machine fails `kernel-no-hypervisor`, because it has one.

| Area | Checks |
| --- | --- |
| boot | Secure Boot on (a `?` check where firmware takes the key), module signatures enforced by the kernel's own build (`sig_enforce`), IPE's single-root default-deny policy active and enforcing with CAP_MAC_ADMIN removed from PID 1's bounding set, and rollback refused by a TPM counter. Stock Alpine images excuse the IPE and signature gaps; opt-in IPE images must pass both. TPM rollback protection remains open ([design/ipe.md](design/ipe.md), [design/verified-boot.md](design/verified-boot.md)) |
| kernel | lockdown, module loading closed, signed modules only, kexec, ptrace, BPF, kernel pointers and log, perf events, user namespaces, io_uring, SysRq, core dumps, no hypervisor (`/dev/kvm`), and where one runs its guests cannot nest, booted with every kernel argument the image asks for (`/usr/share/werewolf/cmdline`), no debugfs, `/proc/self/mem` cannot write read-only memory, 32-bit and 16-bit system calls (x86_64), every process under PID 1's seccomp filter, no memory both writable and executable (Memory-Deny-Write-Execute, inherited from PID 1, and an anonymous writable and executable mapping tried and refused), the programs the kernel starts itself without kernel-code, hardware, tracing, mount or network capabilities and no uevent or modprobe helper, PID 1's bounding set without the capabilities to load kernel code, reach hardware, trace, make device files or mount (`CAP_SYS_ADMIN`) (or, unless the form allows them, change the network or open packet sockets), full address randomization, low memory unmappable, users' BPF JIT hardened, an oops or a warning panics, no userfaultfd for users, no vsyscall page, no core dumps at all (PID 1's hard limit), memory hardening on the kernel command line (`init_on_alloc`, `init_on_free`, `slab_nomerge`, `page_alloc.shuffle`, `randomize_kstack_offset`), no CPU flaw the kernel reports `Vulnerable`, no rarely used protocols, filesystems or buses (SCTP, DCCP, TIPC, squashfs, usb-storage, Thunderbolt and the like), no module that exploits in the wild went through (AF_ALG, kernel TLS, nf_tables, ebtables, x_tables, overlayfs), and, tried as an exploit's first step would try them, no AF_ALG socket, no kernel TLS, no notification pipe and, unless the form allows `pty`, no pseudo-terminal ([cve-mitigation-survey.md](cve-mitigation-survey.md)); every exec the kernel refuses logged by the kernel's audit, which nothing can stop (`lib/audit.zig`), and the kernel's notices, those refusals among them, reaching a serial or hypervisor console a cloud captures |
| processes | hidden from other users, no setuid or setgid files, web server workers unprivileged; every service leash starts (one with an `/etc/sv/NAME/service` file) runs as a user, with no capability but `CAP_NET_BIND_SERVICE`, `no_new_privs` set, and a umask that makes no file others may write; with `werewolf.check=1`, a copy of posture leashed as `nobody` (`posture --probe`) can do what its service file grants and nothing more: no file, program or TCP port it was not given |
| programs | no shell, downloaders, interpreters, compilers, debuggers, module tools or network configuration tools; every runit service starts from a program, not a script |
| files | read-only root, on a read-only dm-verity device named `root` with no corruption in the kernel log, no EFI system partition (vfat) mounted, `nosuid`/`noexec`/`nodev` on every mount, `nosymfollow` on every mount but `/`, `/proc`, `/sys`, `/dev` and `/data`, and a link made in `/tmp` not followed, no program runs from a writable place or a memfd, link and FIFO protections, every directory anyone may write is sticky and no file outside the temporary directories is writable by everyone, the account files (`passwd`, `group`, `shadow`, `gshadow`, wherever their links lead) root's alone, only root has uid 0 or gid 0, every password shadowed and locked, no name or id twice, every account's group exists, every file on the root owned by a known uid and gid, `/boot` read-only |
| network | only declared ports listen (the network policy, `/usr/share/werewolf/net`), Fence cannot be bypassed with `CAP_NET_ADMIN` or `CAP_NET_RAW`, no remote login; where there is sshd, `sshd -T` reports keys only (root by key at most), security keys alone and touched (`network-ssh-security-keys`) and no forwarding, tunnels, user environment or GSSAPI, few tries and little time for a guesser (`MaxAuthTries`, `LoginGraceTime`, `MaxStartups`, `MaxSessions`), dead sessions cut (`ClientAlive*`), verbose logging, host keys readable by no one else, no weak cipher, MAC, key exchange or signature, and a post-quantum key exchange; no forwarding, ICMP redirects neither taken nor sent on any interface, source routing refused, loopback addresses not routed from an interface, reverse-path filtering, martians logged, IPv6 router advertisements ignored, SYN cookies, broadcast pings, bogus ICMP errors and TIME-WAIT resets ignored |

In werewolf it is also a service, in every form: once per boot, when every
other service has run for 5 seconds or parked itself (or after 60 seconds,
whichever is first), it checks, keeps the JSON in
`/run/werewolf/posture.json`, prints its `--line` on the console, and parks
itself. The demo's page shows every check from that file
([demo.md](../forms/demo/README.md)). For comparison, Ubuntu 24.04's cloud image passes 5 of
40.
