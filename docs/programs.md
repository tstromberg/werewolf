# werewolf's programs

werewolf writes its own programs only where the image needs one and no
package will do: `init`, `dhcp-client`, `cloud-metadata`, `fence`, `mount`, `slot-update`, `status-page`, and others. Each is a single
static Zig binary, built ReleaseSafe from one source file: in `cmd/`, or,
where one form alone needs it, in that form's `forms/NAME/cmd/`
(`pg-init`, `gitea-init`, `gitea-hook`, `status-page`), built for every
form built on it. They are written
the way OpenBSD writes its daemons: assume the input is hostile and the
code has a bug, and arrange that the bug can do nothing.

## The rules

1. **Separate the privileges.** The part that reads untrusted input, from
   the network or from another program's output, is not the part that
   changes the machine. Split them into two processes, as OpenBSD's
   dhclient and ntpd do: an unprivileged one that does the work, and a small
   privileged one that does only what needs privilege.
2. **Pass facts, not requests.** The two processes talk in fixed-size
   messages. The privileged side checks every field again, and treats a
   message it does not like as a compromised peer: it ends both.
3. **Give everything up early.** Do what needs privilege first: open the
   sockets and files, then drop. The unprivileged side runs as its own
   user, chrooted to the empty `/var/empty`, with no capabilities and an
   empty bounding set, and checks that root cannot be had back. The
   privileged side keeps the one capability it needs, with securebits
   locked so root's uid brings no others.
4. **Allow, never deny.** A seccomp filter names the system calls a
   process may make, with arguments where they matter: which descriptor,
   which ioctl. Any other call kills the process, as does a call made as
   another architecture. Landlock confines what it may write to the
   directories it owns. no_new_privs is always set.
5. **Do it before the input arrives.** The sandbox is complete before the
   first byte of untrusted input is read. Filters on a socket go on, and
   are locked, before it is bound.
6. **Parse strictly.** Every length is checked against what is there.
   Unknown things are ignored, malformed things are rejected, and only the
   fields actually used are read. Validation happens where the data is
   parsed and again where it is applied.
7. **Fail closed.** An allowlist that does not match, a sandbox step that
   fails, a peer that misbehaves: each ends the program. runit restarts it.
8. **Allocate nothing after setup**, where a program runs for long: fixed
   buffers, or an arena freed on each pass. Memory does not grow with
   uptime.
9. **Run nothing else.** No shell, no hook scripts, no helper programs
   where a system call will do.
10. **Log facts.** One JSON line per event on stdout, with the kernel's own
    reason for any failure. Text from outside is escaped or not logged.

ReleaseSafe turns an out-of-bounds access or an overflow into a stopped
program rather than a corrupted one. The rules are for the bugs it does
not catch.

## Where each program stands

| Program | Runs | Separation and confinement |
| --- | --- | --- |
| `dhcp-client` | always, when there is no static address | Two processes. The engine runs as `_dhcp`, chrooted, with no capabilities, under seccomp, which lets it send and receive on its packet socket and write to the parent, and little else. The parent has `CAP_NET_ADMIN` alone, under seccomp (four ioctls) and Landlock (`/run/werewolf/network`). A kernel socket filter passes only DHCP replies. |
| `cloud-metadata` | once at boot, on a known cloud with no local config | Two processes. The fetcher runs as `_cloud`, chrooted, with no capabilities, under Landlock (no files; TCP to port 80 alone) and seccomp (a TCP socket, and little else). The parent has no capabilities, never touches the network, and writes only beneath `/run/werewolf/cloud` (Landlock); it checks the fetched tar and writes a new one of what passed, so init extracts only what werewolf wrote. |
| `modload` | once at boot, by stage0 | One process: nothing it reads comes from outside the image but a few lines from stage0, tags (the slot's filesystem; `hyperv` where the kernel found a VMBus), which only pick which of the list's tagged lines (xfs, btrfs, Hyper-V's disks) to load, and the kernel judges each module's signature. It loads nothing unless lockdown or `module.sig_enforce` is on; opens the list and every module beneath the module directory with symlinks refused; pledges to `CAP_SYS_MODULE` under seccomp (`finit_module`, read, write, close, exit); and closes the loader whatever happens, reading `kernel.modules_disabled` back to say so. |
| `iface-up` | once at boot, for a static address | One process: its arguments come from the kernel command line and are parsed strictly. It opens its socket, then pledges to `CAP_NET_ADMIN` under seccomp allowing `ioctl` only for its five requests. A gateway outside the subnet gets a host route first. |
| `fence` | once, init's last step, before runit | One process, by design: it reads only the image's own policy, sets policy-routing rules (default deny, both directions; the metadata server only for those named), applies the same rules to IPv6 where the form allows it, and applies a Landlock ruleset as root: binding only declared ports, connecting only to ports the policy names (so a process that may bind a served port cannot connect anywhere from it), and for files, read anywhere but `/dev`, which is closed but for the devices werewolf names, execute only beneath `/usr`, write only in `/run`, `/tmp`, `/var/tmp`, `/dev/shm`, `/data` and to terminals (docs/design/fence.md, Files). Then it execs runit, so every process inherits the Landlock restriction, which nothing can lift, root included: no mount, no write to `/proc`, `/sys` or a disk. It fails closed: PID 1 ends and the machine rolls back. |
| `mount-broker` | from init, before fence, until the machine stops | One process, the one outside fence's Landlock domain, which forbids mounting to everything else. It answers root alone, on a socket in `/run`, and takes one word, never a path or option: `grub`, `esp`, `victim` or `shutdown`. Which filesystem comes from the kernel command line and init's record, found by the UUID in its superblock; it is mounted detached with nosuid, nodev and noexec, and unmounted when the asker's connection closes. It keeps `CAP_SYS_ADMIN` alone, locked, under seccomp, and runs nothing. |
| `mount` | once per mount: init at boot | One process: it reads only its arguments, then sets `no_new_privs` and keeps `CAP_SYS_ADMIN` alone under seccomp before asking anything of the kernel. One-way: mounts are built and restricted detached, and remounts are `mount_setattr(2)` with nothing to clear. Allowlisted types, options and targets; paths resolved without symlinks. |
| `slot-update` | at boot and every 20 hours | Root builds and installs the slot and has no network at all. Every fetch is a child as `_update`: apk's network half, under Landlock (read the image, run only apk, write only its cache, TCP to 443 and 53) and a traced seccomp allowlist, after which root takes the cache back and installs from it offline, checking every signature itself; and the CVE sources, fetched by a child chrooted to the resolver's files and parsed by another with no network, no files and `pread64`, `write` and memory calls alone, whose lines root checks field by field. The updater goes away when it installs signed releases instead ([docs/design/verified-boot.md](design/verified-boot.md), phase 3). |
| `status-page` | the demo form: the page every minute, the scan hourly | Two services, each leashed as its own user: the page as `status`, which may reach nothing on the network and read only `/data/svc` and `/run/werewolf` beyond the floor, and the scan as `grype`, the only user that may fetch, and which writes only its own directory. It refuses to run as root. |
| `leash` | once per start of a service someone else wrote (nginx, PostgreSQL, the demo's page and scan) | Starts the service its `service` file describes, as its own user, never root. As root it only checks the file, requirements and secrets, makes the service's directories, puts it in its cgroup (`/run/cgroup/svc/NAME`, with `memory.max` from the file) and builds the rules; then it empties the bounding set (keeping `CAP_NET_BIND_SERVICE` only for a port below 1024), sets `no_new_privs`, checks that root cannot be had back, applies a Landlock ruleset of the paths, programs and TCP ports the file names with scoping, and installs a seccomp filter of the file's `pledge` promises (on top of the machine seal). Nothing of it runs once the service has started. |
| `leash-reap` | a leashed service's `finish`, when runsv stops it | As root: writes `cgroup.kill` for the service's cgroup, so its whole process tree -- a detached child included -- is killed on stop, restart and shutdown. One write, reading the service name from its directory; nothing where the kernel has no cgroup2. |
| `pg-init` | before each start of PostgreSQL, leashed as `postgres` | Makes the cluster once with `initdb`, then applies the image's SQL in single-user mode; reads nothing from outside the image ([postgresql.md](../forms/postgresql/README.md)). |
| `service-config` | before each start of a service that declares settings, inside its leash | Refuses root. Reads the image's `setting` and `render` declarations and the service's private JSON settings copy, validates only declared names and types, and writes a private runtime file. The bastion declares only literal endpoints; Tailscale only subnet routes. No injected directives, default routes or privilege changes. See [settings.md](design/settings.md). |
| `popen-shim.so` | inside `initdb` and the servers it starts to set the cluster up, preloaded by pg-init | `popen`, `pclose` and `system` without a shell, for commands of `initdb`'s one shape: an absolute program, plain or double-quoted words, `</dev/null`, `>/dev/null`, `2>&1`. Anything else is not run; `locale -a`, which the setup servers run, reads as empty. |
| `stage0` | the kernel's first process, on every machine | Not separated: as root, it reads the kernel command line (strictly: each key once, plain paths, well-formed UUIDs) and filesystem superblocks it finds itself, opens the root image through dm-verity with the root hash beside it in the initramfs (the device mapper's ioctls, [lib/dm.zig](../lib/dm.zig); no veritysetup), mounts it, and forks the deadman, which holds no files while it sleeps. |
| `init` | PID 1, from stage0 until fence | Not yet: one process, as root, since it mounts, sets the kernel's settings and extracts the config. What comes from outside is parsed strictly: config tar entries must be plain relative names, and only directories and regular files up to 1 MiB, never links; NoCloud's user and uid must be plain; the hostname must be a plain name. Lima's data importer accepts only `/run/config` destinations, at most 32 regular files of 32 KiB, with source links refused and fixed root-only permissions. It runs werewolf's programs and the filesystem tools (`blkid`, `mke2fs`, `e2fsck`, `cryptsetup`) by full path, never a shell or provisioning script. Unlike the others it does not fail closed: a step that fails is said on the console, and the boot goes on as far as it can. |
| `runit-stage` | runit's three stages | As root, with nothing from outside: stage 2 gives the services a blocking console and becomes `runsvdir`; stage 3 stops the services and puts `/data` and `/victim` down. |
| `slot-keep` | once, on a slot on probation | As root: it reads `sv status`, and renames systemd-boot's entry or writes GRUB's block with `grub-setenv` to make the slot the default. |
| `power-button` | always, where the hypervisor has a power button | As root: it reads only input events, and asks runit to power off. |
| `posture` | once per boot, as a service | As root, and only reading, unless the kernel command line has `werewolf.check=1` (werewolf's tests): then it also attacks, and those attacking as nobody run in a child with uid and gid 65534 and no new privileges. |

## Writing one

A program is `cmd/NAME/NAME.zig`; the Makefile finds it there. Confine it
with [lib/sandbox.zig](../lib/sandbox.zig), the one copy werewolf's programs
share: `Filter` builds a seccomp allowlist, `dropTo` gives up a process for
good, `keepOnly` keeps a capability and locks the rest away, and `landlock`
confines its files and ports. `cmd/dhcp-client/dhcp-client.zig` shows them together. Test
what can be tested without a kernel (parsers, the filters' jumps, message
layouts), give the parser a fuzz target, and check the sandbox on a
running machine: `/proc/PID/status` should show the uid, `CapEff`,
`CapBnd`, `NoNewPrivs: 1` and `Seccomp: 2` you meant.

Write it as the Zig language reference's
[Style Guide](https://ziglang.org/documentation/0.17.0/#Style-Guide) says,
and let the tools hold you to it. `make fix` runs `tools/zigfix`: it
lays the code out as zig fmt does, breaks lines longer than the guide's
100 where zig fmt keeps a break, and rewrites calls the standard library
has deprecated to what it names instead. `make lint` fails on anything
`make fix` would still change, on a long line it could not break (a
multiline string's data and a URL in a comment excepted, as common
sense), on what `zig ast-check` finds, and on the guide's naming rules as
ziglint checks them; `.ziglint.zon` lists which rules are on, and why the
others are off.
