# posture

`/usr/lib/werewolf/posture`, in every form, measures how a Linux machine
protects itself and prints the answer as JSON. It exits 1 if any check
fails. It assumes nothing of werewolf: copy it to any Linux machine (it is
a static binary) and run it as root to compare.

```sh
posture | jq '.summary'          # { "pass": 24, "fail": 9, "skip": 0 }
posture | jq -r '.checks[] | select(.result == "fail") | .name'
```

Each check says what it protects against (`why`), how it was checked
(`how`), and what was found (`detail`). Where it is safe, a check tests
rather than reads:

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
| network | only declared ports listen (`/etc/werewolf/listen`), no remote login, no forwarding, ICMP redirects ignored, source routing refused, SYN cookies |

The demo's page runs it once per boot and shows every check
([demo.md](demo.md)). For comparison, Ubuntu 24.04's cloud image passes 5 of
31.
