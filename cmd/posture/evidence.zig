//! Authoritative sources for checks whose predicates are documented in how.
//! Sysctl and program-list helpers supply their expanded sources themselves.
const std = @import("std");

const sources = std.StaticStringMap([]const u8).initComptime(.{
    .{
        "boot-ipe-enforced",
        "/sys/kernel/security/ipe: policies/werewolf/policy, policies/werewolf/active and" ++
            " enforce; /proc/1/status: CapBnd bit 33 (CAP_MAC_ADMIN)",
    },
    .{
        "boot-secure-boot",
        "/sys/firmware/efi/efivars/{SecureBoot,SetupMode}-8be4df61-93ca-11d2-aa0d-00e098032b8c:" ++
            " byte 4 after the four-byte attributes",
    },
    .{ "boot-sig-enforced", "/sys/module/module/parameters/sig_enforce" },
    .{
        "boot-rollback-protected",
        "/dev/tpmrm0: protected release authorization; /proc/cmdline: release and slots;" ++
            " /boot/state; /run/werewolf/rollback-checked",
    },
    .{
        "kernel-lockdown",
        "/sys/kernel/security/lockdown: bracketed active mode; write(\"none\") only when" ++
            " already locked",
    },
    .{ "kernel-modules-signed", "/proc/sys/kernel/tainted: bit 13 (unsigned module)" },
    .{
        "kernel-kexec",
        "/proc/sys/kernel/kexec_load_disabled; /sys/kernel/security/lockdown: active mode",
    },
    .{ "kernel-perf", "/proc/sys/kernel/perf_event_paranoid" },
    .{ "kernel-no-hypervisor", "/dev/kvm and /sys/class/misc/kvm: existence" },
    .{
        "kernel-no-nested",
        "/sys/module/{kvm_intel,kvm_amd}/parameters/nested; /proc/cmdline: kvm-arm.mode;" ++
            " /dev/kvm and /sys/class/misc/kvm",
    },
    .{ "kernel-debugfs", "/proc/filesystems: filesystem-name column" },
    .{
        "kernel-proc-mem",
        "open(\"/proc/self/mem\", O_WRONLY|O_CLOEXEC), then pwrite of unchanged bytes into this" ++
            " program's read-only page",
    },
    .{ "kernel-legacy", "x86_64: int 0x80 getpid (syscall 20); modify_ldt(func=0)" },
    .{
        "kernel-bounding-set",
        "/proc/1/status: CapBnd; /etc/werewolf/allow: explicitly retained capabilities",
    },
    .{
        "kernel-helpers",
        "/proc/sys/kernel/usermodehelper/bset: low/high 32-bit words;" ++
            " /proc/sys/kernel/{hotplug,modprobe}",
    },
    .{ "kernel-seal", "/proc/1/status: Seccomp" },
    .{
        "kernel-write-xor-execute",
        "prctl(PR_GET_MDWE=66); mmap(PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS)",
    },
    .{ "kernel-aslr", "/proc/sys/kernel/randomize_va_space; /proc/sys/vm/mmap_rnd_bits" },
    .{
        "kernel-kaslr",
        "x86_64: /sys/kernel/boot_params/data: hdr.loadflags (0x211) bit 1, KASLR_FLAG;" ++
            " aarch64: /dev/kmsg: kernel-facility KASLR enabled|disabled record",
    },
    .{ "kernel-null-page", "/proc/sys/vm/mmap_min_addr" },
    .{ "kernel-bpf-jit", "/proc/sys/net/core/bpf_jit_harden" },
    .{ "kernel-oops", "/proc/sys/kernel/{panic_on_oops,warn_limit,panic}" },
    .{
        "kernel-cmdline",
        "/proc/cmdline: parsed arguments, compared with /usr/share/werewolf/cmdline and" ++
            " the arguments that weaken address randomization",
    },
    .{ "kernel-userfaultfd", "/proc/sys/vm/unprivileged_userfaultfd" },
    .{ "kernel-vsyscall", "/proc/self/maps: mapping pathname [vsyscall]" },
    .{ "kernel-core-limit", "/proc/1/limits: Max core file size row, Hard Limit column (bytes)" },
    .{
        "kernel-memory-hardening",
        "/sys/kernel/slab: symlink count (fallback /proc/cmdline: slab_nomerge);" ++
            " /sys/module/page_alloc/parameters/shuffle (fallback /proc/cmdline:" ++
            " page_alloc.shuffle); /dev/kmsg: mem auto-init heap alloc field (fallback" ++
            " /proc/cmdline: init_on_alloc)",
    },
    .{
        "kernel-memory-wipe",
        "/dev/kmsg: mem auto-init heap free field; fallback /proc/cmdline: init_on_free",
    },
    .{
        "kernel-cpu-mitigations",
        "/sys/devices/system/cpu/vulnerabilities/*: text beginning Vulnerable",
    },
    .{
        "kernel-rare-features",
        "/proc/modules: module-name column; /proc/net/protocols: protocol-name column;" ++
            " /proc/filesystems: filesystem-name column",
    },
    .{
        "kernel-exploited-modules",
        "/proc/modules: module-name column; /proc/net/protocols: protocol-name column;" ++
            " /proc/filesystems: filesystem-name column",
    },
    .{ "kernel-af-alg", "socket(AF_ALG=38, SOCK_SEQPACKET|SOCK_CLOEXEC, protocol=0)" },
    .{
        "kernel-ktls",
        "socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0); setsockopt(SOL_TCP=6, TCP_ULP=31," ++
            " \"tls\", length=3) on the unconnected socket",
    },
    .{ "kernel-watch-queue", "pipe2(O_CLOEXEC|O_NOTIFICATION_PIPE=0x80080)" },
    .{ "kernel-seccomp-listener", "seccomp(SECCOMP_GET_NOTIF_SIZES=3, flags=0, &sizes)" },
    .{
        "kernel-no-pty",
        "open(\"/dev/ptmx\", O_RDWR|O_NOCTTY|O_CLOEXEC); /etc/werewolf/allow: pty",
    },
    .{
        "kernel-exec-log",
        "execve(\"/\") in a child; /dev/kmsg: AUDIT_SYSCALL type=1300, success=no, child's pid" ++
            " and execve syscall; NETLINK_AUDIT: AUDIT_GET/AUDIT_SET(enabled=0)",
    },
    .{
        "kernel-log-control",
        "/proc/sys/kernel/printk: first integer; syslog(action=8, buffer=NULL, length=current" ++
            " console level)",
    },
    .{
        "kernel-console-log",
        "/proc/sys/kernel/printk: first integer (console_loglevel); /proc/consoles: enabled E" ++
            " and writable W serial/hypervisor console",
    },
    .{ "update-held", "/data/svc/autoupdate/held: existence and contents" },
    .{
        "updates-enabled",
        "/usr/share/werewolf/form, /etc/sv/autoupdate/{run,service,down}: existence",
    },
    .{ "processes-hidden", "/proc/self/mounts: /proc mount's options column" },
    .{
        "processes-no-setid",
        "descriptor-relative statx on /'s filesystem: regular file stx_mode bits S_ISUID" ++
            " (04000) and S_ISGID (02000), no symlinks followed",
    },
    .{
        "processes-workers",
        "/proc/*/cmdline: nginx worker prefix; /proc/PID/status: Uid real-user column",
    },
    .{
        "processes-services-leashed",
        "/etc/sv/*/service: configured capabilities; supervise/pid; /proc/PID/status: Uid," ++
            " CapInh, CapPrm, CapEff, CapBnd, CapAmb, NoNewPrivs and Umask",
    },
    .{
        "processes-service-dirs",
        "/etc/sv/*/service: share; statx(/run/svc/NAME and /data/svc/NAME): stx_mode & 07777",
    },
    .{
        "processes-image-roots",
        "/etc/sv/*/service: root; supervise/pid; readlink(/proc/PID/root); /proc/self/mounts:" ++
            " root/{tmp,run,data} mount options",
    },
    .{
        "programs-services-no-shell",
        "/etc/sv/*/run: ELF magic (first four bytes), following service links",
    },
    .{ "files-root-readonly", "/proc/self/mounts: / mount options column" },
    .{
        "files-root-verity",
        "statx(/): device major/minor; /sys/dev/block/MAJ:MIN/dm/name and ro; /dev/kmsg: verity" ++
            " corrupted records",
    },
    .{ "files-boot-unmounted", "/proc/self/mounts: filesystem-type column" },
    .{ "files-nosuid-everywhere", "/proc/self/mounts: each mount's options column" },
    .{
        "files-noexec-everywhere",
        "/proc/self/mounts: mount options; /proc/self/mountinfo: read-only EROFS root views",
    },
    .{ "files-nodev-everywhere", "/proc/self/mounts: options and filesystem-type columns" },
    .{
        "files-nosymfollow-everywhere",
        "/proc/self/mounts: options; /proc/self/mountinfo: root views; symlink/open in /tmp",
    },
    .{
        "files-exec-refused",
        "copy of this executable in /tmp, /var/tmp, /run, /dev/shm, /dev/mqueue and /data: exec" ++
            " --noop",
    },
    .{ "files-memfd-exec", "/proc/sys/vm/memfd_noexec; memfd_create copy and exec --noop" },
    .{
        "files-world-writable",
        "descriptor-relative statx under /run, /tmp, /var/tmp, /dev/shm, /dev/mqueue and /data:" ++
            " stx_mode world-write and sticky bits",
    },
    .{
        "files-account-db",
        "resolved /etc/{passwd,group,shadow,gshadow} and parent directories: statx stx_uid and" ++
            " stx_mode",
    },
    .{
        "files-accounts",
        "/etc/passwd: name, password, uid and gid fields; /etc/group: name and gid;" ++
            " /etc/shadow: password field",
    },
    .{
        "files-unowned",
        "descriptor-relative statx on /'s filesystem: stx_uid/stx_gid, compared with third" ++
            " fields of /etc/passwd and /etc/group",
    },
    .{ "files-boot-readonly", "/proc/self/mounts: /boot mount options column" },
    .{
        "files-system-writes",
        "open(O_WRONLY/O_RDWR|O_NOFOLLOW) on" ++
            " /proc/sys/{kernel/printk,kernel/kptr_restrict,kernel/dmesg_restrict,vm/" ++
            "memfd_noexec,vm/mmap_min_addr,user/max_user_namespaces,fs/" ++
            "protected_symlinks,net/ipv4/ip_forward}," ++
            " /sys/kernel/mm/transparent_hugepage/enabled and first whole disk from" ++
            " /sys/block",
    },
    .{
        "files-device-reads",
        "open(O_RDONLY|O_NOFOLLOW) on first whole disk from /sys/block, /dev/mapper/control and" ++
            " /dev/loop-control",
    },
    .{
        "network-ports",
        "/proc/net/{tcp,tcp6}: local_address and st=0A (LISTEN), excluding loopback;" ++
            " /usr/share/werewolf/net or /etc/werewolf/listen",
    },
    .{
        "network-fence-unbypassable",
        "/proc/1/status: CapBnd bits 12 (CAP_NET_ADMIN) and 13 (CAP_NET_RAW)",
    },
    .{
        "network-ssh-config",
        "sshd -T: effective authentication, forwarding and limit fields;" ++
            " statx(/etc/ssh/sshd_config): owner/mode; statx(hostkey paths): mode",
    },
    .{
        "network-ssh-crypto",
        "sshd -T: ciphers, macs, kexalgorithms, hostkeyalgorithms, pubkeyacceptedalgorithms," ++
            " casignaturealgorithms",
    },
    .{
        "network-ssh-security-keys",
        "sshd -T: pubkeyacceptedalgorithms, casignaturealgorithms and pubkeyauthoptions",
    },
    .{ "network-bind", "bind(AF_INET TCP, INADDR_ANY, undeclared port)" },
    .{ "network-outbound", "connect(AF_INET UDP, 192.0.2.1:9), no packets sent" },
    .{
        "network-root-dns-assigned",
        "/etc/resolv.conf nameserver lines (unwound); root UDP/TCP connect(port 53)",
    },
    .{
        "network-root-dns-arbitrary",
        "root UDP/TCP connect(port 53) to unwound's upstream resolvers and TEST-NET",
    },
    .{
        "network-root-https-arbitrary",
        "root nonblocking TCP connect(TEST-NET:443); no server response needed",
    },
    .{
        "network-metadata",
        "connect(AF_INET TCP, 169.254.169.254:80), then poll and getsockopt(SO_ERROR), 1 s" ++
            " deadline",
    },
    .{
        "network-inbound",
        "NETLINK_ROUTE RTM_GETRULE(AF_INET): action, priority, table, iif and selector attributes",
    },
    .{
        "network-ipv6",
        "/proc/sys/net/ipv6/conf/all/disable_ipv6; NETLINK_ROUTE RTM_GETRULE(AF_INET6): action," ++
            " priority, table, iif and selectors",
    },
    .{ "network-ipv6-ra", "/proc/sys/net/ipv6/conf/all/disable_ipv6" },
    .{ "processes-mem-attack", "open(/proc/1/mem); /dev/kmsg: Yama refusal" },
    .{
        "kernel-mem-attack",
        "open(/dev/mem); /proc/self/status: CapEff CAP_SYS_RAWIO; /dev/kmsg: lockdown refusal",
    },
    .{
        "processes-hidden-attack",
        "access(/proc/1, F_OK) as uid/gid 65534 with no supplementary groups",
    },
    .{ "files-run-attack", "open(/run/.posture-attack, O_CREAT|O_EXCL|O_WRONLY) as uid/gid 65534" },
    .{
        "files-links-attack",
        "exclusive files, symlink, hard-link and FIFO probes in /tmp, as root and uid/gid 65534",
    },
    .{
        "processes-leash-attack",
        "leash's generated service policy; posture --probe syscall exit bitmap and" ++
            " granted/denied file, exec, TCP and UNIX socket probes",
    },
});

pub fn source(id: []const u8) ?[]const u8 {
    return sources.get(genericAlias(id));
}

const Brief = struct { label: []const u8, expr: []const u8, want: []const u8 };
const briefs = std.StaticStringMap(Brief).initComptime(.{
    .{
        "boot-ipe-enforced",
        Brief{
            .label = "Image code enforced",
            .expr = "ipe/policies/werewolf + CapBnd",
            .want = "active=enforce=1, CAP_MAC_ADMIN=0",
        },
    },
    .{
        "boot-secure-boot",
        Brief{
            .label = "Secure Boot enabled",
            .expr = "efivars[4]",
            .want = "SecureBoot=1, SetupMode=0",
        },
    },
    .{
        "boot-sig-enforced",
        Brief{
            .label = "Module signatures enforced",
            .expr = "/sys/module/module/parameters/sig_enforce",
            .want = "Y",
        },
    },
    .{
        "boot-rollback-protected",
        Brief{
            .label = "Rollback protection",
            .expr = "TPM A/B release authorization",
            .want = "protected + boot matched",
        },
    },
    .{
        "kernel-lockdown",
        Brief{
            .label = "Kernel lockdown",
            .expr = "/sys/kernel/security/lockdown",
            .want = "confidentiality, unlock denied",
        },
    },
    .{
        "kernel-modules-signed",
        Brief{
            .label = "Signed modules only",
            .expr = "/proc/sys/kernel/tainted",
            .want = "bit 13=0",
        },
    },
    .{
        "kernel-kexec",
        Brief{
            .label = "Kernel replacement blocked",
            .expr = "/proc/sys/kernel/kexec_load_disabled",
            .want = "1 or confidentiality lockdown",
        },
    },
    .{
        "kernel-perf",
        Brief{
            .label = "Perf events restricted",
            .expr = "/proc/sys/kernel/perf_event_paranoid",
            .want = ">=2",
        },
    },
    .{
        "kernel-no-hypervisor",
        Brief{
            .label = "Nested hypervisor absent",
            .expr = "/dev/kvm|/sys/class/misc/kvm",
            .want = "absent",
        },
    },
    .{
        "kernel-no-nested",
        Brief{
            .label = "Guest nesting disabled",
            .expr = "kvm_{intel,amd}.nested|kvm-arm.mode",
            .want = "off|not nested",
        },
    },
    .{
        "kernel-debugfs",
        Brief{
            .label = "Debug filesystem absent",
            .expr = "/proc/filesystems debugfs",
            .want = "absent",
        },
    },
    .{
        "kernel-proc-mem",
        Brief{
            .label = "Read-only memory protected",
            .expr = "pwrite(/proc/self/mem, RO page)",
            .want = "denied",
        },
    },
    .{
        "kernel-legacy",
        Brief{
            .label = "Legacy syscalls blocked",
            .expr = "int 0x80|modify_ldt(0)",
            .want = "denied",
        },
    },
    .{
        "kernel-bounding-set",
        Brief{
            .label = "Root capabilities bounded",
            .expr = "/proc/1/status",
            .want = "forbidden CapBnd bits=0",
        },
    },
    .{
        "kernel-helpers",
        Brief{
            .label = "Kernel helpers restricted",
            .expr = "/proc/sys/kernel",
            .want = "helper caps bounded; hotplug=modprobe=∅",
        },
    },
    .{
        "kernel-seal",
        Brief{ .label = "Seccomp filter inherited", .expr = "/proc/1/status Seccomp", .want = "2" },
    },
    .{
        "kernel-write-xor-execute",
        Brief{
            .label = "Writable code blocked",
            .expr = "prctl(MDWE)|mmap(RWX)",
            .want = "REFUSE_EXEC_GAIN|denied",
        },
    },
    .{
        "kernel-aslr",
        Brief{
            .label = "Full address randomization",
            .expr = "/proc/sys/{kernel,vm}",
            .want = "randomize_va_space=2; mmap_rnd_bits>=32(x86)/33(arm)",
        },
    },
    .{
        "kernel-kaslr",
        Brief{
            .label = "Kernel base randomized",
            .expr = "boot_params KASLR_FLAG|/dev/kmsg KASLR",
            .want = "set|enabled",
        },
    },
    .{
        "kernel-null-page",
        Brief{
            .label = "Low mappings blocked",
            .expr = "/proc/sys/vm/mmap_min_addr",
            .want = ">=65536",
        },
    },
    .{
        "kernel-bpf-jit",
        Brief{
            .label = "BPF JIT hardened",
            .expr = "/proc/sys/net/core/bpf_jit_harden",
            .want = "1|2|absent",
        },
    },
    .{
        "kernel-oops",
        Brief{
            .label = "Kernel bugs reboot",
            .expr = "/proc/sys/kernel",
            .want = "panic_on_oops=warn_limit=1; panic≠0",
        },
    },
    .{
        "kernel-cmdline",
        Brief{
            .label = "Boot arguments enforced",
            .expr = "/proc/cmdline ∩ image cmdline",
            .want = "all required arguments; no weakening ones",
        },
    },
    .{
        "kernel-userfaultfd",
        Brief{
            .label = "Userfaultfd restricted",
            .expr = "/proc/sys/vm/unprivileged_userfaultfd",
            .want = "0|absent",
        },
    },
    .{
        "kernel-vsyscall",
        Brief{
            .label = "Vsyscall mapping absent",
            .expr = "/proc/self/maps [vsyscall]",
            .want = "absent",
        },
    },
    .{
        "kernel-core-limit",
        Brief{ .label = "Core dumps disabled", .expr = "/proc/1/limits core.hard", .want = "0" },
    },
    .{
        "kernel-memory-hardening",
        Brief{
            .label = "Kernel memory hardened",
            .expr = "slab|page_alloc|mem auto-init",
            .want = "aliases=0; shuffle=Y; heap alloc=on",
        },
    },
    .{
        "kernel-memory-wipe",
        Brief{
            .label = "Freed memory wiped",
            .expr = "/dev/kmsg heap free|init_on_free",
            .want = "on",
        },
    },
    .{
        "kernel-cpu-mitigations",
        Brief{
            .label = "CPU flaws mitigated",
            .expr = "/sys/devices/system/cpu/vulnerabilities/*",
            .want = "no Vulnerable entries",
        },
    },
    .{
        "kernel-rare-features",
        Brief{
            .label = "Unused kernel features absent",
            .expr = "/proc/{modules,net/protocols,filesystems} ∩ deny",
            .want = "∅",
        },
    },
    .{
        "kernel-exploited-modules",
        Brief{
            .label = "Exploited modules absent",
            .expr = "/proc/{modules,net/protocols,filesystems} ∩ deny",
            .want = "∅",
        },
    },
    .{
        "kernel-af-alg",
        Brief{ .label = "Kernel crypto unavailable", .expr = "socket(AF_ALG)", .want = "error" },
    },
    .{
        "kernel-ktls",
        Brief{
            .label = "Kernel TLS unavailable",
            .expr = "setsockopt(TCP_ULP, tls)",
            .want = "ENOENT|ENOSYS",
        },
    },
    .{
        "kernel-watch-queue",
        Brief{
            .label = "Notification pipes blocked",
            .expr = "pipe2(O_NOTIFICATION_PIPE)",
            .want = "error",
        },
    },
    .{
        "kernel-seccomp-listener",
        Brief{
            .label = "Seccomp listeners blocked",
            .expr = "seccomp(GET_NOTIF_SIZES)",
            .want = "error",
        },
    },
    .{
        "kernel-no-pty",
        Brief{
            .label = "Pseudo-terminals restricted",
            .expr = "open(/dev/ptmx)",
            .want = "error or allow.pty",
        },
    },
    .{
        "kernel-exec-log",
        Brief{
            .label = "Refused execs logged",
            .expr = "/dev/kmsg AUDIT_SYSCALL",
            .want = "matching child record; audit locked",
        },
    },
    .{
        "kernel-log-control",
        Brief{
            .label = "Console settings protected",
            .expr = "syslog(CONSOLE_LEVEL)",
            .want = "EPERM|EACCES|ENOSYS",
        },
    },
    .{
        "kernel-console-log",
        Brief{
            .label = "Console logging enabled",
            .expr = "/proc/sys/kernel/printk[0]|/proc/consoles",
            .want = ">=6|serial enabled",
        },
    },
    .{
        "update-held",
        Brief{ .label = "Updates resolve", .expr = "/data/svc/autoupdate/held", .want = "absent" },
    },
    .{
        "updates-enabled",
        Brief{
            .label = "Automatic updates enabled",
            .expr = "/etc/sv/autoupdate/{run,service,down}",
            .want = "run|service present, down absent",
        },
    },
    .{
        "processes-hidden",
        Brief{
            .label = "Other processes hidden",
            .expr = "/proc/self/mounts /proc",
            .want = "hidepid=2|invisible",
        },
    },
    .{
        "processes-no-setid",
        Brief{
            .label = "Set-ID files absent",
            .expr = "statx(/ filesystem) mode & 06000",
            .want = "∅",
        },
    },
    .{
        "processes-workers",
        Brief{
            .label = "Web workers unprivileged",
            .expr = "/proc/PID/status Uid[0] (nginx)",
            .want = "≠0",
        },
    },
    .{
        "processes-services-leashed",
        Brief{
            .label = "Service privileges restricted",
            .expr = "/proc/PID/status (leashed services)",
            .want = "Uid≠0; caps bounded; NoNewPrivs=1; Umask≥022",
        },
    },
    .{
        "processes-service-dirs",
        Brief{
            .label = "Service directories isolated",
            .expr = "statx({/run,/data}/svc/*).mode",
            .want = "0700|share mode",
        },
    },
    .{
        "processes-image-roots",
        Brief{
            .label = "Image roots isolated",
            .expr = "/proc/PID/root + mount options",
            .want = "configured root; noexec,nodev binds",
        },
    },
    .{
        "programs-services-no-shell",
        Brief{ .label = "Service scripts absent", .expr = "/etc/sv/*/run magic", .want = "ELF" },
    },
    .{
        "files-root-readonly",
        Brief{ .label = "Root filesystem read-only", .expr = "/proc/self/mounts /", .want = "ro" },
    },
    .{
        "files-root-verity",
        Brief{
            .label = "Root filesystem verified",
            .expr = "/sys/dev/block/*/{dm/name,ro}",
            .want = "root,1; no verity corruption",
        },
    },
    .{
        "files-boot-unmounted",
        Brief{
            .label = "Boot partition unmounted",
            .expr = "/proc/self/mounts type=vfat",
            .want = "∅",
        },
    },
    .{
        "files-nosuid-everywhere",
        Brief{
            .label = "Set-ID mounts disabled",
            .expr = "/proc/self/mounts !nosuid",
            .want = "∅",
        },
    },
    .{
        "files-noexec-everywhere",
        Brief{
            .label = "Writable mounts non-executable",
            .expr = "/proc/self/mounts !noexec (except /)",
            .want = "∅",
        },
    },
    .{
        "files-nodev-everywhere",
        Brief{
            .label = "Device mounts restricted",
            .expr = "/proc/self/mounts !nodev (except devtmpfs,devpts)",
            .want = "∅",
        },
    },
    .{
        "files-nosymfollow-everywhere",
        Brief{
            .label = "Writable symlinks blocked",
            .expr = "mounts.nosymfollow + open(/tmp symlink)",
            .want = "set|ELOOP",
        },
    },
    .{
        "files-exec-refused",
        Brief{
            .label = "Writable execution blocked",
            .expr = "exec(writable mounts)",
            .want = "denied",
        },
    },
    .{
        "files-memfd-exec",
        Brief{
            .label = "Memory execution blocked",
            .expr = "vm.memfd_noexec|exec(memfd)",
            .want = "2|denied",
        },
    },
    .{
        "files-world-writable",
        Brief{
            .label = "Shared writes restricted",
            .expr = "statx(shared trees).mode",
            .want = "sticky dirs; no world-writable persistent files",
        },
    },
    .{
        "files-account-db",
        Brief{
            .label = "Account files protected",
            .expr = "statx(/etc/{passwd,group,shadow,gshadow})",
            .want = "root owned; private writes; shadow private reads",
        },
    },
    .{
        "files-accounts",
        Brief{
            .label = "Accounts restricted",
            .expr = "/etc/{passwd,group,shadow}",
            .want = "one root; locked passwords; unique IDs",
        },
    },
    .{
        "files-unowned",
        Brief{
            .label = "File owners known",
            .expr = "statx(/ filesystem) uid,gid ∉ accounts",
            .want = "∅",
        },
    },
    .{
        "files-boot-readonly",
        Brief{
            .label = "Boot filesystem read-only",
            .expr = "/proc/self/mounts /boot",
            .want = "ro",
        },
    },
    .{
        "files-system-writes",
        Brief{
            .label = "Kernel writes blocked",
            .expr = "open(sysctls|sysfs|disk, WRONLY|RDWR)",
            .want = "EACCES",
        },
    },
    .{
        "files-device-reads",
        Brief{
            .label = "Device reads blocked",
            .expr = "open(disk|dm|loop, RDONLY)",
            .want = "EACCES|ENOENT",
        },
    },
    .{
        "network-ports",
        Brief{
            .label = "Listening ports declared",
            .expr = "/proc/net/{tcp,tcp6} LISTEN",
            .want = "subset of image policy",
        },
    },
    .{
        "network-fence-unbypassable",
        Brief{
            .label = "Network capabilities restricted",
            .expr = "/proc/1/status CapBnd",
            .want = "NET_ADMIN=NET_RAW=0",
        },
    },
    .{
        "network-ssh-config",
        Brief{
            .label = "SSH access restricted",
            .expr = "sshd -T",
            .want = "keys only; forwarding off; bounded limits",
        },
    },
    .{
        "network-ssh-crypto",
        Brief{
            .label = "SSH cryptography hardened",
            .expr = "sshd -T crypto",
            .want = "no weak algorithms; PQ KEX",
        },
    },
    .{
        "network-ssh-security-keys",
        Brief{
            .label = "SSH security keys required",
            .expr = "sshd -T pubkey*",
            .want = "sk-*; touch-required",
        },
    },
    .{
        "network-bind",
        Brief{
            .label = "Undeclared listeners blocked",
            .expr = "bind(TCP, undeclared port)",
            .want = "EACCES",
        },
    },
    .{
        "network-outbound",
        Brief{
            .label = "Undeclared egress blocked",
            .expr = "connect(UDP, 192.0.2.1:9)",
            .want = "EACCES",
        },
    },
    .{
        "network-root-dns-assigned",
        Brief{
            .label = "Root assigned DNS blocked",
            .expr = "root connect(DNS, assigned)",
            .want = "EACCES|EPERM",
        },
    },
    .{
        "network-root-dns-arbitrary",
        Brief{
            .label = "Root arbitrary DNS blocked",
            .expr = "root connect(DNS, other)",
            .want = "EACCES|EPERM",
        },
    },
    .{
        "network-root-https-arbitrary",
        Brief{
            .label = "Root arbitrary HTTPS blocked",
            .expr = "root connect(TCP, other:443)",
            .want = "EACCES|EPERM",
        },
    },
    .{
        "network-metadata",
        Brief{
            .label = "Cloud metadata restricted",
            .expr = "connect(TCP, 169.254.169.254:80)",
            .want = "EACCES",
        },
    },
    .{
        "network-inbound",
        Brief{
            .label = "Unsolicited traffic blocked",
            .expr = "RTM_GETRULE(AF_INET)",
            .want = "inbound blackhole; undeclared egress prohibited",
        },
    },
    .{
        "network-ipv6",
        Brief{
            .label = "IPv6 policy enforced",
            .expr = "disable_ipv6|RTM_GETRULE(AF_INET6)",
            .want = "off|same policy",
        },
    },
    .{
        "network-ipv6-ra",
        Brief{
            .label = "IPv6 advertisements disabled",
            .expr = "/proc/sys/net/ipv6/conf/all/disable_ipv6",
            .want = "1",
        },
    },
    .{
        "processes-mem-attack",
        Brief{
            .label = "Process memory protected",
            .expr = "open(/proc/1/mem)|/dev/kmsg",
            .want = "denied|Yama record",
        },
    },
    .{
        "kernel-mem-attack",
        Brief{
            .label = "Kernel memory protected",
            .expr = "open(/dev/mem)|/dev/kmsg",
            .want = "denied|lockdown record or no SYS_RAWIO",
        },
    },
    .{
        "processes-hidden-attack",
        Brief{
            .label = "Other processes inaccessible",
            .expr = "access(/proc/1, nobody)",
            .want = "denied",
        },
    },
    .{
        "files-run-attack",
        Brief{
            .label = "Runtime writes restricted",
            .expr = "open(/run probe, nobody)",
            .want = "denied",
        },
    },
    .{
        "files-links-attack",
        Brief{
            .label = "Link attacks blocked",
            .expr = "symlink|link|FIFO(/tmp)",
            .want = "denied",
        },
    },
    .{
        "processes-leash-attack",
        Brief{
            .label = "Service grants enforced",
            .expr = "leash(posture --probe)",
            .want = "granted operations only",
        },
    },
});

pub fn label(id: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, id, "network-bind-restricted")) return "TCP listeners restricted";
    if (std.mem.eql(
        u8,
        id,
        "network-outbound-restricted",
    )) return "Outbound connections restricted";
    return if (briefs.get(genericAlias(id))) |b| b.label else null;
}

pub fn comparison(
    gpa: std.mem.Allocator,
    id: []const u8,
    result: []const u8,
    observed: []const u8,
    detail: []const u8,
) ![]const u8 {
    const b = briefs.get(genericAlias(id)) orelse return gpa.dupe(
        u8,
        if (detail.len > 0) detail else observed,
    );
    if (std.mem.eql(
        u8,
        result,
        "skip",
    )) return gpa.print("{s}: {s}", .{ b.expr, if (detail.len > 0) detail else "unavailable" });
    const got = if (std.mem.eql(u8, observed, "no violations found"))
        b.want
    else if (detail.len > 0 and detail.len < observed.len)
        detail
    else
        observed;
    return if (std.mem.eql(u8, result, "fail"))
        gpa.print("{s} = {s}, want {s}", .{ b.expr, got, b.want })
    else
        gpa.print("{s} = {s}", .{ b.expr, got });
}

fn genericAlias(id: []const u8) []const u8 {
    if (std.mem.eql(u8, id, "network-bind-restricted")) return "network-bind";
    if (std.mem.eql(u8, id, "network-outbound-restricted")) return "network-outbound";
    if (std.mem.eql(u8, id, "network-capabilities-restricted")) return "network-fence-unbypassable";
    return id;
}
