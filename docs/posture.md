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

Where it is safe, a check tests rather than reads:

- **One-way settings** (lockdown, the module loader, ptrace, BPF) must read
  locked, and writing the unlocked value must be refused. It is written
  only when the setting already reads locked, when the kernel's refusal is
  certain, so a failing check never weakens the machine.
- **Running a program from a writable place**: posture copies itself into
  `/tmp`, `/var/tmp`, `/run`, `/dev/shm`, `/dev/mqueue` and `/data`, and
  into a memfd, and runs each copy with `--noop`, which exits at once. Each
  must fail to start.
- **Mounts**: every mount is `nosuid`; every mount but `/` is `noexec`;
  every mount but `/dev` and `/dev/pts` is `nodev`. No file on the root filesystem is
  setuid or setgid.
- **Tools an intruder wants**: no shell, downloader, network tool,
  interpreter, compiler or debugger on the system's PATH directories.

It reads no other process's memory and opens no `/dev/mem`: both would put
lines in the kernel log on every boot.

| Area | Checks |
| --- | --- |
| kernel | lockdown, module loading closed, signed modules only, kexec, ptrace, BPF, kernel pointers and log, perf events, user namespaces, io_uring, SysRq, core dumps |
| processes | hidden from other users, no setuid or setgid files, web server workers unprivileged |
| programs | no shell, downloaders, interpreters, compilers, debuggers, module tools or network configuration tools; every runit service starts from a program, not a script |
| files | read-only root, `nosuid`/`noexec`/`nodev` on every mount, no program runs from a writable place or a memfd, link and FIFO protections, `/victim` read-only |
| network | only declared ports listen (`/etc/werewolf/listen`), no remote login, no forwarding, ICMP redirects neither taken nor sent, source routing refused, SYN cookies |

The demo's page runs it once per boot and shows every check
([demo.md](demo.md)). For comparison, Ubuntu 24.04's cloud image passes 5 of
40.
