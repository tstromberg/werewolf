# posture

`/usr/lib/werewolf/posture`, in every form, measures how a Linux machine
protects itself: ✅ passed, ❌ failed, ⚠️ skipped, as there was nothing to
check. It exits 1 if any check fails. It assumes nothing of werewolf: copy
the static binary to any Linux machine and run it as root to compare, or,
in a checkout there, run `make posture`, which builds it and runs it with
sudo. Only where `/usr/share/werewolf` exists does it add the werewolf
checks: the IPE policy, TPM A/B authorization, root device, updater, leash,
generated services and the compiled network policy. Elsewhere the kernel,
mount, capability, system-call and SSH checks still run, and the report
reads no image allowances or excuses.

```
Ubuntu 24.04.4 LTS, Linux 6.8.0-134-generic, on lima-werewolf-ci (root)

Kernel
  ❌ Kernel lockdown                       none
  ❌ Kernel module loading closed          kernel.modules_disabled is 0
  ✅ Only signed kernel modules
  …

✅ 5 passed   ❌ 33 failed   ⚠️ 2 skipped
```

Each item is a short description and the checked expectation. A failure
reads as Go's tests do, `expression = value, want expectation`; a pass omits
the `want`. Long values are shortened with `…` to keep an item within two
rows; the full evidence is in `--json`, with what each check protects
against (`why`), how it was checked (`how`), and `source`, `expected`,
`observed` and `comparison`, the source naming the exact file field or
system-call argument:

```sh
posture --json | jq '.summary'          # { "pass": 24, "fail": 9, "skip": 0 }
posture --json | jq -r '.checks[] | select(.result == "fail") | .name'
```

```text
❌ Core dumps disabled     /proc/1/limits core.hard = unlimited, want 0
❌ Kernel TLS unavailable  setsockopt(TCP_ULP, tls) = ENOTCONN(107), want ENOENT|ENOSYS
✅ SYN flood protection    /proc/sys: net.ipv4.tcp_syncookies = 1
```

`--summary` runs fresh checks and prints the state and counts on one line,
then one row per failure: an amber `gap` for one the image's declared
weaknesses excuse, a red `FAIL` for one they do not. The labels work without
colour, which redirected output, `NO_COLOR` and `TERM=dumb` suppress. A gap
still counts as a failure and exits 1.

```text
Security posture: EXPECTED GAPS · 86 passed · 5 failed · 5 skipped
  gap   Shells present            /bin/sh, /bin/ash, /bin/bash
  gap   Download / network tools  /bin/wget, /bin/nc, /bin/netcat, /bin/telnet
  gap   Interpreters present      /bin/awk
  gap   Login servers present     /bin/sshd, /bin/telnetd
  gap   SSH security key policy   ordinary keys accepted
```

| State | Meaning |
| --- | --- |
| NOMINAL | No failed checks. |
| EXPECTED GAPS | Every failure is excused by the image's declared weaknesses. |
| DEGRADED | At least one failure is not excused. |

These describe the measured checks, not a guarantee: NOMINAL does not mean
every check ran, and a non-root scan says its coverage is limited. Program
rows name installed tools, not running servers. `playground` shows this
summary at interactive terminal logins through `/etc/profile.d/posture.sh`;
for your own bashrc:

```sh
case $- in
    *i*) [ ! -t 1 ] || /usr/lib/werewolf/posture --summary || : ;;
esac
```

The hook absorbs the exit status so the shell stays usable, and runs only
for a terminal, not a noninteractive ssh command. Like any live scan, its
refusal probes leave kernel audit records, which may reach the console.

`--line` prints one line, for a console or a log: the ids that failed,
sorted, between commas (`fail=` and nothing when none did), the counts, and
the report as JSON with only the failed checks, each with its excuse where
the image expects it:

```
posture: fail=programs-no-shell,programs-services-no-shell pass=37 skip=0 {"tool":"posture",…}
```

`--verbose` prints each phase, each check with its elapsed milliseconds, and
the slow operations (filesystem walks, `sshd -T`, metadata and audit probes)
to stderr as they happen, to find where a scan's time goes.

`--extended` adds the checks werewolf fails by choice, because meeting them
would slow what the machine runs or is not yet shown to work with fence:
wiping freed memory, forced CPU mitigations, strict reverse-path filtering
and ignoring IPv6 router advertisements ([security.md](security.md), "Not
done, by choice"). It combines with `--json` or `--line`.

## What a check does

Where it is safe, a check tests rather than reads:

- **Sysctl writes**: as root, `files-system-writes` opens settings under
  `kernel`, `vm`, `user`, `fs` and `net` with `O_WRONLY` and `O_RDWR`,
  without writing; each must return `EACCES`. `kernel-log-control` asks
  `syslog(2)` to set the current console level, the path `dmesg -n` takes,
  and expects a refusal.
- **One-way settings** (lockdown, the module loader, ptrace, BPF) must read
  locked, and writing the unlocked value must be refused. It is written only
  when the setting already reads locked, so a failing check never weakens
  the machine.
- **Running a program from a writable place**: posture copies itself into
  `/tmp`, `/var/tmp`, `/run`, `/dev/shm`, `/dev/mqueue`, `/data` and a
  memfd, and runs each copy with `--noop`. Each must fail to start.
- **Old and back-door interfaces**: a write through `/proc/self/mem` of the
  bytes already in one of its read-only pages; on x86_64, a 32-bit `getpid`
  through `int 0x80` and `modify_ldt(2)`. Each must be refused.
- **Mounts**: every mount `nosuid`; every mount but `/` `noexec`; every
  mount but `/dev` and `/dev/pts` `nodev`; no setuid or setgid file on the
  root.
- **Tools an intruder wants**: no shell, downloader, network tool,
  interpreter, compiler or debugger on the system's PATH directories.
- **Refused execs logged**: posture runs `/` as a program, which every
  kernel refuses, and waits for the kernel's audit record of it
  ([lib/audit.zig](../lib/audit.zig)); missing evidence fails, rate-limited
  printk included. Then it asks the kernel to stop auditing, which must be
  refused.

It reads no other process's memory and opens no `/dev/mem`: both would put
lines in the kernel log on every boot. Concurrent attack scans lock their
shared fixtures, so one cannot mistake another's files for an escape.

A werewolf machine whose form took back a default when it was built, as
`qemu-host` takes `kvm`, says so under its first line (`Its form allows:
kvm`) and in the JSON's `allow`. The checks still measure it: such a machine
fails `kernel-no-hypervisor`, because it has one.

| Area | Checks ([cmd/posture](../cmd/posture), one file per area) |
| --- | --- |
| boot | Secure Boot on (a `?` check where firmware takes the key), module signatures enforced by the kernel's own build, IPE's single-root default-deny policy enforcing with `CAP_MAC_ADMIN` gone from PID 1, rollback refused by a TPM counter. Stock Alpine images excuse the IPE and signature gaps; opt-in IPE images must pass both ([design/ipe.md](design/ipe.md), [design/verified-boot.md](design/verified-boot.md)) |
| kernel | lockdown; module loading closed and signed modules only; kexec, ptrace, BPF, perf, user namespaces, io_uring, userfaultfd, SysRq, debugfs and core dumps closed; kernel pointers and log hidden; no hypervisor (`/dev/kvm`), and where one runs, no nesting; booted with every argument the image asks for (`/usr/share/werewolf/cmdline`) and its memory hardening (`init_on_alloc`, `init_on_free`, `slab_nomerge`, `page_alloc.shuffle`, `randomize_kstack_offset`); `/proc/self/mem` cannot write read-only memory; no 32-bit, 16-bit or vsyscall entry (x86_64); every process under PID 1's seccomp filter; no memory both writable and executable (MDWE, tried and refused); the kernel's own helpers and PID 1's bounding set without the capabilities to load kernel code, reach hardware, trace, make device files or mount, and, unless the form allows it, change the network or open packet sockets; full address randomization, low memory unmappable, BPF JIT hardened, an oops or warning panics; no CPU flaw reported `Vulnerable`; no rarely used protocol, filesystem or bus (SCTP, DCCP, TIPC, squashfs, usb-storage, Thunderbolt…) and no module exploited in the wild (AF_ALG, kernel TLS, nf_tables, ebtables, x_tables, overlayfs); tried as an exploit would, no AF_ALG socket, kernel TLS, notification pipe or, unless the form allows `pty`, pseudo-terminal ([cve-mitigation-survey.md](cve-mitigation-survey.md)); every refused exec logged by an audit nothing can stop, reaching a console the host captures |
| processes | hidden from other users; no setuid or setgid files; web server workers unprivileged; every service leash starts runs as a user with no capability but `CAP_NET_BIND_SERVICE`, `no_new_privs` and a umask that makes no file others may write; with `werewolf.check=1`, a copy of posture leashed as `nobody` (`posture --probe`) can do what its service file grants and nothing more |
| programs | no shell, downloader, interpreter, compiler, debugger, module tool or network configuration tool; every runit service starts from a program, not a script |
| files | read-only root on a dm-verity device named `root` with no corruption logged; no EFI system partition mounted; `nosuid`, `noexec` and `nodev` on every mount, `nosymfollow` on every mount but `/`, `/proc`, `/sys`, `/dev` and `/data`, and a link made in `/tmp` not followed; no program runs from a writable place or a memfd; link and FIFO protections; every world-writable directory sticky and no world-writable file outside them; the account files root's alone, only root with uid or gid 0, every password shadowed and locked, no name or id twice, every file owned by a known uid and gid; `/boot` read-only |
| network | only declared ports listen (`/usr/share/werewolf/net`); fence cannot be bypassed with `CAP_NET_ADMIN` or `CAP_NET_RAW`; no remote login, or where there is sshd, `sshd -T` reports keys only, security keys alone and touched (`network-ssh-security-keys`), no forwarding, tunnels, user environment or GSSAPI, few tries and little time for a guesser, dead sessions cut, verbose logging, host keys readable by no one else, no weak cipher, MAC, key exchange or signature, and a post-quantum key exchange; no forwarding, ICMP redirects neither taken nor sent, source routing refused, loopback not routed from an interface, reverse-path filtering, martians logged, router advertisements ignored, SYN cookies, broadcast pings, bogus ICMP errors and TIME-WAIT resets ignored |

In werewolf it is also a service, in every form: once per boot, when every
other service has run for 5 seconds or parked itself (or after 60 seconds,
whichever is first), it checks, keeps the JSON in
`/run/werewolf/posture.json`, prints its `--line` on the console, and parks
itself. `make check` judges each boot by that line
([testing.md](testing.md)), and the demo's page shows every check from the
file ([demo](../forms/demo/README.md)). For comparison, Ubuntu 24.04's
cloud image passes 5 of 40.
