# posture

`/usr/lib/werewolf/posture`, in every form, measures how a Linux machine
protects itself: ✅ passed, ❌ failed, ⚠️ skipped, as there was nothing to
check. It exits 1 if any check fails. It assumes nothing of werewolf: copy
it to any Linux machine (it is a static binary) and run it as root to
compare, or, in a checkout there, run `make posture`, which builds it and
runs it with sudo.

```
Ubuntu 24.04.4 LTS, Linux 6.8.0-134-generic, on lima-werewolf-ci (root)

Kernel
  ❌ Kernel lockdown                       none
  ❌ Kernel module loading closed          kernel.modules_disabled is 0
  ✅ Only signed kernel modules
  …

✅ 5 passed   ❌ 33 failed   ⚠️ 2 skipped
```

A check that does not pass says what it found; in a terminal, a long list
is cut to fit (`+3 more`). `--json` prints everything, with what each check
protects against (`why`) and how it was checked (`how`):

```sh
posture --json | jq '.summary'          # { "pass": 24, "fail": 9, "skip": 0 }
posture --json | jq -r '.checks[] | select(.result == "fail") | .name'
```

`--line` prints one line, for a console or a log: the ids that failed,
sorted, between commas (`fail=` and nothing when none did), the counts,
and then the whole report as JSON:

```
posture: fail=programs-no-shell,programs-services-no-shell pass=37 skip=0 {"tool":"posture",…}
```

Where it is safe, a check tests rather than reads:

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

It reads no other process's memory and opens no `/dev/mem`: both would put
lines in the kernel log on every boot.

| Area | Checks |
| --- | --- |
| kernel | lockdown, module loading closed, signed modules only, kexec, ptrace, BPF, kernel pointers and log, perf events, user namespaces, io_uring, SysRq, core dumps, no hypervisor (`/dev/kvm`), no debugfs, `/proc/self/mem` cannot write read-only memory, 32-bit and 16-bit system calls (x86_64), full address randomization, low memory unmappable, users' BPF JIT hardened, an oops panics, no userfaultfd for users, no vsyscall page, no core dumps at all (PID 1's hard limit), memory hardening on the kernel command line (`init_on_alloc`, `init_on_free`, `slab_nomerge`, `page_alloc.shuffle`, `randomize_kstack_offset`), no CPU flaw the kernel reports `Vulnerable`, no rarely used protocols, filesystems or buses (SCTP, DCCP, TIPC, squashfs, usb-storage, Thunderbolt and the like) |
| processes | hidden from other users, no setuid or setgid files, web server workers unprivileged |
| programs | no shell, downloaders, interpreters, compilers, debuggers, module tools or network configuration tools; every runit service starts from a program, not a script |
| files | read-only root, `nosuid`/`noexec`/`nodev` on every mount, no program runs from a writable place or a memfd, link and FIFO protections, every directory anyone may write is sticky and no file outside the temporary directories is writable by everyone, the account files (`passwd`, `group`, `shadow`, `gshadow`, wherever their links lead) root's alone, only root has uid 0 and no account has an empty password, `/victim` read-only |
| network | only declared ports listen (`/etc/werewolf/listen`), no remote login; where there is sshd, `sshd -T` reports keys only and no forwarding, tunnels or user environment, and no weak cipher, MAC, key exchange or signature; no forwarding, ICMP redirects neither taken nor sent on any interface, source routing refused, reverse-path filtering, martians logged, IPv6 router advertisements ignored, SYN cookies, broadcast pings, bogus ICMP errors and TIME-WAIT resets ignored |

In werewolf it is also a service, in every form: once per boot, when every
other service has run for 5 seconds or parked itself (or after 60 seconds,
whichever is first), it checks, keeps the JSON in
`/run/werewolf/posture.json`, prints its `--line` on the console, and parks
itself. The demo's page shows every check from that file
([demo.md](demo.md)). For comparison, Ubuntu 24.04's cloud image passes 5 of
40.
