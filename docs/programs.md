# werewolf's programs

werewolf writes its own programs only where the image needs one and no
package will do: `init`, `dhcp-client`, `cloud-metadata`, `fence`, `mount`,
`slot-update`, `status-page`, and others. Each is a single static Zig
binary, built ReleaseSafe from one source file. The file is in `cmd/`, or,
when only one form needs the program, in that form's `forms/NAME/cmd/`
(`pg-init`, `gitea-init`, `gitea-hook`, `status-page`). A form's program is
built for every form built on that form. The programs are written the way
OpenBSD writes its daemons: assume the input is hostile and the code has a
bug, and arrange that the bug can do nothing.

## The rules

1. **Separate the privileges.** The part that reads untrusted input, from
   the network or from another program's output, is not the part that
   changes the machine. Split them into two processes, as OpenBSD's
   dhclient and ntpd do: an unprivileged one that does the work, and a small
   privileged one that does only what needs privilege.
2. **Pass facts, not requests.** The two processes talk in fixed-size
   messages. The privileged side checks every field again. It treats a
   message it does not like as coming from a compromised peer, and ends
   both processes.
3. **Give everything up early.** Do what needs privilege first: open the
   sockets and files, then drop privileges. The unprivileged side runs as
   its own user, chrooted to the empty `/var/empty`, with no capabilities
   and an empty bounding set, and checks that it cannot get root back. The
   privileged side keeps the one capability it needs, with securebits
   locked so that root's uid brings no others.
4. **Allow, never deny.** A seccomp filter names the system calls a
   process may make, with arguments where they matter: which descriptor,
   which ioctl. Any other call kills the process, and so does a call made
   as another architecture. Landlock confines the process's writes to the
   directories it owns. no_new_privs is always set.
5. **Do it before the input arrives.** The sandbox is complete before the
   first byte of untrusted input is read. Filters on a socket go on, and
   are locked, before the socket is bound.
6. **Parse strictly.** Check every length against the data that is there.
   Ignore unknown things, reject malformed things, and read only the fields
   you use. Validate data where it is parsed and again where it is applied.
7. **Fail closed.** An allowlist that does not match, a sandbox step that
   fails, or a peer that misbehaves ends the program. runit restarts it.
8. **Allocate nothing after setup** in a program that runs for long. Use
   fixed buffers, or an arena freed on each pass, so memory does not grow
   with uptime.
9. **Run nothing else.** Use no shell, no hook scripts, and no helper
   programs where a system call will do.
10. **Log facts.** Write one JSON line per event on stdout, with the
    kernel's reason for any failure. Escape text from outside, or do not
    log it.

ReleaseSafe turns an out-of-bounds access or an overflow into a stopped
program rather than a corrupted one. The rules are for the bugs it does
not catch.

## Where each program stands

| Program | Runs | Separation and confinement |
| --- | --- | --- |
| `dhcp-client` | always, when there is no static address | Two processes. The engine runs as `_dhcp`, chrooted, with no capabilities, under seccomp. The filter lets it send and receive on its packet socket and write to the parent, and little else. The parent has only `CAP_NET_ADMIN`, under seccomp (four ioctls) and Landlock (`/run/werewolf/network`). A kernel socket filter passes only DHCP replies. |
| `cloud-metadata` | once at boot, on a known cloud with no local config | Two processes. The fetcher runs as `_cloud`, chrooted, with no capabilities, under Landlock (no files; TCP to port 80 only) and seccomp (a TCP socket, and little else). The parent has no capabilities and never touches the network. Landlock lets it write only beneath `/run/werewolf/cloud`. It checks the fetched tar and writes a new tar of what passed, so init extracts only what werewolf wrote. |
| `modload` | once at boot, by stage0 | One process. Everything it reads comes from the image, except a few tag lines from stage0: the slot's filesystem, and `hyperv` where the kernel found a VMBus. Tags only pick which of the list's tagged lines (xfs, btrfs, Hyper-V's disks) to load, and the kernel judges each module's signature. modload loads nothing unless lockdown or `module.sig_enforce` is on. It opens the list and every module beneath the module directory with symlinks refused. It pledges to `CAP_SYS_MODULE` under seccomp (`finit_module`, read, write, close, exit). Whatever happens, it closes the loader, and reads `kernel.modules_disabled` back to report it. |
| `iface-up` | once at boot, for a static address | One process. Its arguments come from the kernel command line, and it parses them strictly. It opens its socket, then pledges to `CAP_NET_ADMIN` under seccomp, which allows `ioctl` only for its five requests. A gateway outside the subnet gets a host route first. |
| `fence` | once, init's last step, before runit | One process, by design. It reads only the image's policy. It sets policy-routing rules: default deny, both directions, and the metadata server only for those the policy names. It applies the same rules to IPv6 where the form allows IPv6. As root, it applies a Landlock ruleset. For the network, the ruleset allows binding only declared ports and connecting only to ports the policy names, so a process that may bind a served port cannot connect anywhere from it. For files, it allows reading anywhere except `/dev`, which is closed except for the devices werewolf names. It allows executing only beneath `/usr` and `/oci` (image roots), and writing only in `/run`, `/tmp`, `/var/tmp`, `/dev/shm`, `/data` and to terminals (docs/design/fence.md, Files). Then fence execs runit, so every process inherits the Landlock restriction, which nothing can lift, root included: no mount, and no write to `/proc`, `/sys` or a disk. It fails closed: PID 1 ends and the machine rolls back. |
| `mount-broker` | from init, before fence, until the machine stops | One process, the only one outside fence's Landlock domain, which forbids mounting to everything else. It answers only root, on a socket in `/run`. It takes one word, never a path or option: `grub`, `esp`, `victim` or `shutdown`. The kernel command line and init's record say which filesystem that is, and the broker finds it by the UUID in its superblock. It mounts the filesystem detached, with nosuid, nodev and noexec, and unmounts it when the asker's connection closes. It keeps only `CAP_SYS_ADMIN`, locked, under seccomp, and runs nothing. |
| `mount` | once per mount: init at boot | One process. It reads only its arguments. Before it asks anything of the kernel, it sets `no_new_privs` and keeps only `CAP_SYS_ADMIN`, under seccomp. Its changes are one-way: it builds and restricts mounts detached, and remounts with `mount_setattr(2)`, with nothing to clear. Types, options and targets are allowlisted, and paths are resolved without symlinks. |
| `slot-update` | at boot and every hour | Root builds and installs the slot, and has no network at all. Every fetch runs in a child as `_update`. apk's network half runs under Landlock (read the image, run only apk, write only its cache, TCP to 443 and 53) and a traced seccomp allowlist. Root then takes the cache back and installs from it offline, checking every signature itself. For the CVE sources, a child chrooted to the resolver's files fetches them. Another child parses them with no network, no files, and only `pread64`, `write` and memory calls, and root checks its lines field by field. |
| `status-page` | the demo form: the page every minute, the scan hourly | Two services, each leashed as its own user. The page runs as `status`: it may reach nothing on the network, and may read only `/data/svc` and `/run/werewolf` beyond the floor. The scan runs as `grype`, the only user that may fetch, and writes only its own directory. It refuses to run as root. |
| `leash` | once per start of a service someone else wrote (nginx, PostgreSQL, the demo's page and scan) | It starts the service its `service` file describes, as the service's own user, never root. As root it only checks the file, requirements and secrets, makes the service's directories, puts the service in its cgroup (`/run/cgroup/svc/NAME`, with `memory.max` from the file), and builds the rules. Then it empties the bounding set (keeping `CAP_NET_BIND_SERVICE` only for a port below 1024), sets `no_new_privs`, and checks that root cannot be had back. It applies a Landlock ruleset of the paths, programs and TCP ports the file names, with scoping. It installs a seccomp filter of the file's `pledge` promises, on top of the machine seal. For a service with a `root` (an OCI image baked in at `/oci/NAME`), leash first enters it with `chroot`, as root and before any rule, so every path is the image's ([design/adhoc.md](design/adhoc.md)). Nothing of leash runs once the service has started. |
| `leash-reap` | a leashed service's `finish`, when runsv stops it | As root, it writes `cgroup.kill` for the service's cgroup. So the service's whole process tree, a detached child included, is killed on stop, restart and shutdown. It makes one write and reads the service name from its directory. It does nothing where the kernel has no cgroup2. |
| `pg-init` | before each start of PostgreSQL, leashed as `postgres` | It makes the cluster once with `initdb`, then applies the image's SQL in single-user mode. It reads nothing from outside the image ([postgresql.md](../forms/postgresql/README.md)). |
| `service-config` | before each start of a service that declares settings, inside its leash | It refuses root. It reads the image's `setting` and `render` declarations and the service's private copy of its JSON settings. It validates only declared names and types, and writes a private runtime file. The bastion declares only literal endpoints, and Tailscale only subnet routes. Settings cannot inject directives, default routes or privilege changes. See [settings.md](design/settings.md). |
| `popen-shim.so` | inside `initdb` and the servers it starts to set the cluster up, preloaded by pg-init | It provides `popen`, `pclose` and `system` without a shell, for commands of `initdb`'s one shape: an absolute program, plain or double-quoted words, `</dev/null`, `>/dev/null`, `2>&1`. It runs nothing else. `locale -a`, which the setup servers run, reads as empty. |
| `sh-shim` | as `/bin/sh`, or a leashed service's `SHELL`, in forms that take `sh-shim`: the cron form's jobs | Not separated, and not confined by itself: it runs inside the leash of the service that starts it, whose `run` lines alone decide what it may execute; the `sh` allowance lets every leashed service run it. It splits its command into words as sh would, refuses anything else sh would read specially, and execs one program with the environment unchanged ([sh-shim](../cmd/sh-shim/README.md)). |
| `stage0` | the kernel's first process, on every machine | Not separated. As root, it reads the kernel command line strictly (each key once, plain paths, well-formed UUIDs), and reads the filesystem superblocks it finds itself. It opens the root image through dm-verity, with the root hash beside it in the initramfs, using the device mapper's ioctls ([lib/dm.zig](../lib/dm.zig)) and no veritysetup. It mounts the image and forks the deadman, which holds no files while it sleeps. |
| `init` | PID 1, from stage0 until fence | Not yet separated: one process, as root, because it mounts, sets the kernel's settings and extracts the config. It parses what comes from outside strictly. Config tar entries must be plain relative names, and only directories and regular files up to 1 MiB, never links. NoCloud's user and uid must be plain, and the hostname must be a plain name. Lima's data importer accepts only `/run/config` destinations, at most 32 regular files of 32 KiB, refuses source links, and sets fixed root-only permissions. init runs werewolf's programs and the filesystem tools (`blkid`, `mke2fs`, `e2fsck`, `cryptsetup`) by full path, never a shell or provisioning script. Unlike the others it does not fail closed: it reports a failed step on the console, and the boot goes on as far as it can. |
| `runit-stage` | runit's three stages | It runs as root and reads nothing from outside. Stage 2 gives the services a blocking console and becomes `runsvdir`. Stage 3 stops the services and takes down `/data` and `/victim`. |
| `slot-keep` | once, on a slot on probation | As root, it reads `sv status`. To make the slot the default, it renames systemd-boot's entry, or writes GRUB's block with `grub-setenv`. |
| `power-button` | always, where the hypervisor has a power button | As root, it reads only input events, and asks runit to power off. |
| `posture` | once per boot, as a service | It runs as root and only reads, unless the kernel command line has `werewolf.check=1` (werewolf's tests). Then it also attacks. The attacks made as nobody run in a child with uid and gid 65534 and no new privileges. |

## Writing one

A program is `cmd/NAME/NAME.zig`; the Makefile finds it there. Confine it
with [lib/sandbox.zig](../lib/sandbox.zig), the one copy werewolf's
programs share. `Filter` builds a seccomp allowlist, `dropTo` gives up a
process's privileges for good, `keepOnly` keeps one capability and locks
the rest away, and `landlock` confines a process's files and ports.
`cmd/dhcp-client/dhcp-client.zig` shows them together. Test what you can
test without a kernel (parsers, the filters' jumps, message layouts), and
give the parser a fuzz target. Check the sandbox on a running machine:
`/proc/PID/status` should show the uid, `CapEff`, `CapBnd`,
`NoNewPrivs: 1` and `Seccomp: 2` you meant.

Write it as the Zig language reference's
[Style Guide](https://ziglang.org/documentation/0.17.0/#Style-Guide) says,
and let the tools hold you to it. `make fix` runs `tools/zigfix`. It lays
the code out as zig fmt does, and breaks lines longer than the guide's 100
columns where zig fmt keeps a break. It also rewrites calls the standard
library has deprecated to the replacement the library names. `make lint`
fails on:

- anything `make fix` would still change;
- a long line it could not break, except a multiline string's data and a
  URL in a comment;
- what `zig ast-check` finds;
- the guide's naming rules, as ziglint checks them. `.ziglint.zon` lists
  which rules are on, and why the others are off.
