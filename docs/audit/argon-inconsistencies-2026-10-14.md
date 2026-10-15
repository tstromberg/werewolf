# Werewolf Code & Architecture Audit: Complexity, Input Sanitization, and Hardening Inconsistencies

- **Audit date:** 2026-10-14
- **Auditor:** Gemini 4 Argon
- **Scope:** Full repository source (`cmd/`, `lib/`, `forms/`, `tools/`, `boot/`) following the IPE-by-default and `sshd`/`gvm-link` `leash` unification changes.
- **Lens:** Rob Pike (simplicity, orthogonality, one mechanism rather than special cases, zero duplicated plumbing) and Theo de Raadt (strict privilege separation, unforgeable kernel primitives, fail-closed error handling, strict input sanitization, and consistent hardening across all paths).

---

## Executive Summary

Moving `sshd` and `gvm-link` under `leash` and making IPE the default unless `--insecure` is passed eliminated two major architectural special cases. However, a thorough review of the remaining subsystems shows several areas where:

1. **Unification stopped halfway:** `slot-update` (`autoupdate`), `slot-keep`, `cloud-metadata`, and `debug-shell` still bypass `leash`, re-implementing their own startup plumbing, Landlock rules, capability drops, and seccomp filters while missing cgroup memory/PID caps and `leash-reap` process-tree cleanup.
2. **Ambient file descriptors cross supervision boundaries:** `init` duplicates the `mount-broker` client sockets onto descriptors `60`, `61`, and `62` without `FD_CLOEXEC`, leaving `runit` (PID 1), `runsvdir`, and every `runsv` supervisor holding open capability descriptors to `mount-broker`.
3. **Kernel mechanisms are used outside their security model:** `fence` uses stateless FIB routing rules (`RTM_NEWRULE`) as a host firewall (allowing trivial source-port spoofing and exposing ephemeral ports), and `seal` uses classic seccomp BPF to restrict `execveat(exec_fd, ..., AT_EMPTY_PATH)` even though seccomp cannot inspect the `pathname` pointer (allowing execution of any Landlock-permitted binary when `pathname` is non-empty) and does not block `fcntl(F_DUPFD, 1021)`.
4. **Duplicated helpers diverge in safety:** Nearly every program in `cmd/` copy-pastes its own `readFile`/`readAll`, `cleanPath`, `park`, and `Log.event` JSON writer, introducing subtle bugs (negative timestamp panics, silent file truncation, interior `..` path traversal, and swallowed errors).

---

## 1. Unnecessary Complexity & Incomplete Unification (Rob Pike Lens)

### 1.1 Four Supervised Daemons Still Bypass `leash` (`autoupdate`, `slot-keep`, `cloud-metadata`, `debug-shell`)
- **Severity:** Medium (Architectural Inconsistency / Defence-in-Depth Gap)
- **Location:**
  - `forms/prod/rootfs/etc/sv/autoupdate/run` -> `/usr/lib/werewolf/slot-update` (`cmd/slot-update/slot-update.zig:162-186`)
  - `forms/prod/rootfs/etc/sv/slot-keep/run` -> `/usr/lib/werewolf/slot-keep` (`cmd/slot-keep/slot-keep.zig:18-21`)
  - `forms/prod/rootfs/etc/sv/cloud-metadata/run` -> `/usr/lib/werewolf/cloud-metadata` (`cmd/cloud-metadata/cloud-metadata.zig:69-162`)
  - `forms/debug/rootfs/etc/sv/debug-shell/run` -> `/usr/lib/werewolf/debug-shell` (`cmd/debug-shell/debug-shell.zig:10-12`)
  - `cmd/posture/processes.zig:37-44` (`system_daemons`)

**Problem:**
Each of these services ships a hand-crafted `/etc/sv/<name>/run` symlink instead of a `service` declaration in `form.yaml` executed by `/usr/lib/werewolf/leash`. Consequently:
1. Every binary re-implements its own daemon setup: `close_range`, `PR_SET_SPECULATION_CTRL`, `sandbox.keepOnly`, `sandbox.landlock`, `sandbox.Filter`, `park()` (`sv down .`), and JSON/line logging.
2. None of them are placed into `/run/cgroup/svc/<name>`, so they have **no `memory.max` cap**, **no `pids.max` cap**, and **no `leash-reap` (`./finish`) cgroup cleanup** when stopped or restarted.
3. `slot-keep` runs with `fence`'s broad base Landlock ruleset and `seal`'s machine-wide seccomp filter rather than a per-service Landlock domain or narrow seccomp pledge.
4. `cloud-metadata`'s parent polling loop runs with **no per-service seccomp filter at all** (`cmd/cloud-metadata/cloud-metadata.zig:121-122`).
5. `cmd/posture/processes.zig:37-44` has to maintain a hardcoded `system_daemons` exception table because these daemons do not live in `/run/cgroup/svc/<name>`.

---

### 1.2 Ambient `mount-broker` Socket Descriptors (`60`, `61`, `62`) Inherited Across the Supervision Tree
- **Severity:** High
- **Location:** `cmd/init/init.zig:143-153`, `lib/broker.zig:21-38`, `cmd/runit-stage/runit-stage.zig:16-46`, `cmd/leash-reap/leash-reap.zig:1-40`

**Code:**
```zig
// cmd/init/init.zig:143-153
if (broker_clients) |clients| {
    for (broker_roles, clients) |role, fd| {
        const dst = broker.clientFd(role);
        _ = linux.dup2(fd, dst);
        if (fd != dst) _ = linux.close(fd);
    }
}
const err = std.process.replace(
    m.io,
    .{ .argv = &.{ "/usr/lib/werewolf/fence", "/usr/bin/runit" }, .environ_map = &m.env },
);
```

**Problem:**
1. `dup2(fd, dst)` clears `FD_CLOEXEC` on descriptors `60` (`.updater`), `61` (`.keeper`), and `62` (`.stage`).
2. `runit` (PID 1) holds all three descriptors open across `execve`.
3. `runit-stage` (`stage 2`, `cmd/runit-stage/runit-stage.zig:22`) closes descriptor `62` (`.stage`), but leaves `60` and `61` open without `FD_CLOEXEC` when execing `runsvdir -P /etc/sv`.
4. `runsvdir` and **every `runsv <service>` supervisor** on the system therefore inherit open capability sockets `60` (`.updater`) and `61` (`.keeper`) and pass them to every `./run`, `./finish`, and `./control/*` child they spawn.
5. `cmd/leash-reap/leash-reap.zig` (`./finish`) never closes descriptors `60..62`. Any future helper or `control/*` script that omits `close_range(3, maxInt)` silently inherits direct access to `mount-broker`.
6. Furthermore, while `broker.keepOnlyClient` (`lib/broker.zig:37`) sets `PR_SET_DUMPABLE = 0` on `slot-update` and `slot-keep`, neither `runit`, `runsvdir`, nor `runsv` sets `PR_SET_DUMPABLE = 0`.

---

### 1.3 Copy-Pasted Mini-Stdlib With Divergent Bugs Across `cmd/`
- **Severity:** Medium
- **Location:**
  - `cmd/mount-broker/mount-broker.zig:1034-1075`
  - `cmd/fence/fence.zig:974-1055`
  - `cmd/slot-keep/slot-keep.zig:154-183`
  - `cmd/stage0/stage0.zig:548-560`
  - `cmd/init/init.zig:420-510`
  - `cmd/slot-update/slot-update.zig:864-879`
  - `lib/compose.zig:845-860`
  - `cmd/howl/oci.zig:348-359, 802-813`

**Problem:**
Instead of sharing a tiny, audited internal library for common low-level operations, individual commands re-implement them with subtle discrepancies:
1. **Unclamped negative `CLOCK_REALTIME` panic:** `mount-broker.zig:1058` and `fence.zig:1036` execute `@intCast(ts.sec)` (`isize` -> `u64`). If the hardware RTC is unset/pre-1970 at boot, both processes panic on their first log event. `slot-keep.zig:109` and `seal-watch.zig:254` guard with `@max(0, ...)`.
2. **In-place JSON buffer splicing via `@memmove`:** Both `mount-broker.zig:1068-1072` and `fence.zig:1038-1042` format JSON prefix text, call `std.json.Stringify.value(fields, .{}, &w)`, and then execute `@memmove(l.buf[mark .. w.end - 1], l.buf[mark + 1 .. w.end])` to strip the leading `{`, assuming `fields` always serializes to `{...}` with length `>= 2`.
3. **Silent file truncation in `readFile` / `readAll`:**
   - `mount-broker.zig:1034-1045` (`readFile`) stops when `buf` is full or when `linux.read` returns any error (including `EINTR`), returning `buf[0..got]` as if it were the complete file. At line `841`, it reads `/proc/cmdline` into `cmd_buf[0..4096]` without checking for truncation or `cmdline.parse`, and at line `979` it reads `/proc/self/mounts` into a 16 KiB buffer (if `/proc/self/mounts` exceeds 16 KiB, `isMounted(mounts, "/data")` and `isMounted(mounts, "/boot")` return `false` at shutdown!).
   - `stage0.zig:548-560` (`readAll`) and `slot-keep.zig:162-168` (`readAll`) return `""` on any open/read error. Because `cmdline.parse("", &refused)` succeeds and returns an empty `Cmdline{}`, an unreadable `/proc/cmdline` in `stage0` silently downgrades to an unverified default `Cmdline{}` instead of failing closed.
4. **Three incompatible path-cleaning functions:**
   - `fence.zig:974-981` (`cleanPath`) and `service.zig` (`isCleanPath`) properly iterate path segments and reject empty, `.`, and `..` components.
   - `lib/compose.zig:845-860` (`prune`) only checks `startsWith` and `endsWith` for `/`, `./`, `../`, `/.`, `/..`, missing interior `usr/../../etc/passwd`, `usr/./bin`, and `usr//bin`.
   - `cmd/howl/oci.zig` duplicates symlink-prefix traversal checks in `throughNoLink` (`348-359`) and `place` (`802-813`), and in `unpack()` (`261-265`) `.directory` entries do not check if the final component `name` is already a symlink before calling `root.createDirPath(io, name)`.
5. **Dead/duplicate SHA-256 helper:** `Update.sha256Of` (`cmd/slot-update/slot-update.zig:864-879`) duplicates `signed.hashFile` (`lib/prebuilt.zig`).

---

## 2. Confinement & Hardening Gaps (Theo de Raadt Lens)

### 2.1 Stateless FIB Routing Rules Used as a Firewall in `fence`
- **Severity:** High
- **Location:** `cmd/fence/fence.zig:220-228`, `461-489`, `573-603`

**Code:**
```zig
// cmd/fence/fence.zig:574-586
for (p.connect[0..p.nconnect], 0..) |c, i| {
    if (c.proto == .icmp or c.any) continue;
    const seen = for (p.connect[0..i]) |d| {
        if (d.proto == c.proto and d.port == c.port) break true;
    } else false;
    if (!seen) rules.add(.{
        .priority = pref.in_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_LOCAL,
        .proto = c.proto,
        .sport = c.port,
    });
}
```

**Weaknesses:**
1. **Source-port spoofing bypasses `in_drop`:** Because FIB routing rules (`RTM_NEWRULE`) are stateless and cannot inspect connection state (`ctstate ESTABLISHED`) or TCP flags (`SYN` vs `ACK`), `fence` permits inbound reply packets by routing **all incoming packets whose source port matches any allowed outbound port** (e.g., TCP 443 or UDP 53) to `RT_TABLE_LOCAL` at priority 300 (`pref.in_allow`), ahead of `pref.in_drop` (priority 399). Any remote attacker who binds source port 443 or 53 can send unsolicited inbound packets to **every** port on the machine (except TCP ports explicitly listed in `p.loopback` at priority 290 `pref.in_private`).
2. **Ephemeral port range exposed under `connect: [any]` (`591-603`):** When any service uses `connect: [any]` (`wide = true`), `fence` routes all unsolicited inbound TCP packets targeting `32768..60999` (`ephemeral_lo..ephemeral_hi`) into `RT_TABLE_LOCAL`. Any internal listener bound to an ephemeral port on `0.0.0.0`/`::` becomes reachable from the network.
3. **Loopback isolation (`pref.loopback_refuse`) bypassed via the machine's own NIC IP (`461-489`):**
   - `pref.loopback_refuse` (priority 9) blocks `connect: [any]` users from connecting to `127.0.0.0/8` and `::1/128`. However, if the service connects to the machine's own NIC IPv4/IPv6 address, the packet misses priority 9 and matches `pref.local_out` (priority 10, `from_here -> RT_TABLE_LOCAL`), reaching any local service bound to `0.0.0.0` or `::`.
   - `pref.loopback_allow` (line 462) is only emitted when `family == linux.AF.INET`, so IPv6 connections to `[::1]:allowed_port` hit `pref.loopback_refuse` and fail with `EACCES`.
4. **Incomplete IPv6 `non_public6` blocklist (`220-228`):** `non_public6` omits IPv4-mapped IPv6 (`::ffff:0:0/96`), SIIT (`::ffff:0:0:0/96`), 6to4 (`2002::/16`), discard (`100::/64`), and documentation (`2001:db8::/32`).

---

### 2.2 Seccomp `execveat` Bypass & 32-Bit Argument Truncation in `lib/seal.zig`
- **Severity:** High
- **Location:** `lib/seal.zig:244-254`, `370-400`, `464-555`, `cmd/leash/leash.zig:452-476`

**Code:**
```zig
// lib/seal.zig:464-483
if (per_service and !promises.contains(.exec) and exec_fd != null) {
    put(buf, &n, JEQ_K, 0, 6, number(.execveat));
    put(buf, &n, LD_W_ABS, 0, 0, 16); // seccomp_data.args[0], low word: fd
    put(buf, &n, JEQ_K, 0, 3, exec_fd.?);
    put(buf, &n, LD_W_ABS, 0, 0, 48); // seccomp_data.args[4], low word: flags
    put(buf, &n, JEQ_K, 0, 1, AT_EMPTY_PATH);
    put(buf, &n, RET_K, 0, 0, linux.SECCOMP.RET.ALLOW);
    put(buf, &n, RET_K, 0, 0, other);
    for (if (@import("builtin").cpu.arch == .x86_64)
        [_]linux.SYS{ .dup2, .dup3 }
    else
        [_]linux.SYS{.dup3}) |sys|
    {
        put(buf, &n, JEQ_K, 0, 4, number(sys));
        put(buf, &n, LD_W_ABS, 0, 0, 24); // seccomp_data.args[1], low word: newfd
        put(buf, &n, JEQ_K, 0, 1, exec_fd.?);
        put(buf, &n, RET_K, 0, 0, other);
        put(buf, &n, LD_W_ABS, 0, 0, 0);
    }
}
```

**Weaknesses:**
1. **`execveat(1021, "/path/to/bin", argv, envp, AT_EMPTY_PATH)` ignores `fd 1021` in the kernel:**
   - In Linux `fs/exec.c` (`do_execveat_common` / `getname_flags`), `AT_EMPTY_PATH` only executes the file referred to by `fd` **if the user-space `pathname` string (`args[1]`) is empty (`""`)**. If `pathname` starts with `/` (an absolute path), the kernel ignores `fd` completely and resolves `pathname`! And if `pathname` is a non-empty relative path while `fd` is `1021` (closed after `execveat` due to `O_CLOEXEC`), the kernel only checks `fd` if `pathname` is relative.
   - Because classic seccomp BPF cannot dereference user pointers (`args[1]`), a compromised service whose pledge **omits `exec`** can still call `execveat(1021, "/path/to/allowed/bin", argv, envp, AT_EMPTY_PATH)` at any time after startup to execute any binary allowed by its Landlock domain (such as re-executing `s.exec[0]` with arbitrary attacker-controlled `argv` and `envp`, or executing `/usr/lib/werewolf/leash` when `s.narrow.len > 0`).
2. **`fcntl(fd, F_DUPFD, 1021)` is not blocked:**
   - Lines 472–482 block `dup2` and `dup3` with `newfd == 1021`, but `fcntl` is in `stdio` (`lib/seal.zig:60`) and `fcntl(fd, F_DUPFD, 1021)` / `fcntl(fd, F_DUPFD_CLOEXEC, 1021)` duplicates `fd` onto descriptor `1021` when `1021` is free (which it is immediately after the initial `execveat` closes `O_CLOEXEC` fd `1021`).
3. **32-bit syscall argument truncation (`466-554`):**
   - Every argument check in `lib/seal.zig` inspects only the low 32 bits (`LD_W_ABS` at offsets `16, 24, 32, 48`) and never verifies that the high 32-bit word (`offsets 20, 28, 36, 52`) is `0`.
4. **Missing `vmsplice` (`244-254`):**
   - `vmsplice` is neither in `splice` nor in `never_names`.

---

### 2.3 `leash` Confinement Inconsistencies
- **Severity:** Medium
- **Location:** `cmd/leash/leash.zig:113-132`, `203-231`, `401-418`, `523-545`, `cmd/leash-reap/leash-reap.zig:20-35`

**Weaknesses:**
1. **`s.before` commands run with full service secrets and without the service's seccomp filter (`401-409`):**
   - `s.before` commands are spawned before `pledgeAndExec` installs the service's seccomp filter, and receive `&env` (containing all `s.secrets`).
   - A compromised `before` command can call syscalls outside the service's pledge and can `fork()` a background process that remains alive inside `/run/cgroup/svc/<name>` **without the service's seccomp filter** and without the `exec_only` Landlock layer applied at lines `410-418`.
2. **`leash` does not kill lingering cgroup processes before starting (`203-231`):**
   - If `leash-reap` (`cmd/leash-reap/leash-reap.zig:20-35`) timed out or did not run (e.g., on first start or if `cgroup.procs` was momentarily empty), `leash` joins `/run/cgroup/svc/<name>` without writing `"1"` to `cgroup.kill` first.
3. **Ineffective `RLIMIT_DATA` in `narrow` (`540-544`):**
   - `narrow` applies `n.memory` using `setrlimit(.DATA, ...)`. On Linux, `RLIMIT_DATA` only restricts `brk()`/`sbrk()` and does **not** restrict `mmap(MAP_ANONYMOUS)`, which modern allocators (musl, Zig, Go, Rust, JVM) use.
4. **Inconsistent UID/GID floor (`113-132`, `523-525`):**
   - `s.groups` requires `gid >= 1 << 16` (`65536`), whereas `user.uid` and `user.gid` only require `> 70`.
5. **Fail-open when `cgroup2` is missing (`203-231`, `cmd/init/kernel.zig:69-79`):**
   - If `/run/cgroup/svc` is absent, `leash` logs an `"uncapped"` event and starts the service without memory or PID limits.

---

### 2.4 Confined Root Rollback via `update-control.sock` & Unbound Local Package Staging on `/data`
- **Severity:** High
- **Location:** `cmd/slot-update/control.zig:46-76`, `cmd/slot-update/slot.zig:53-224`, `243-278`, `314-380`, `cmd/slot-update/images.zig:176-194`

**Weaknesses:**
1. **Unauthenticated `try` rollback & immediate reboot via `/run/werewolf/update-control.sock` (`control.zig:57-76`, `slot.zig:243-278`):**
   - `control.accept()` accepts commands from any `uid == 0` process (`cred.uid == 0`).
   - Sending `"try"` (with `declaration == null`) calls `slot.tryOther(&u, null)` inside the supervised `slot-update` daemon. `tryOther` calls `images.verifyOther(u, null, true, true)` with `rollback = true`—skipping `fresh(u, image)` (`images.zig:191`)—and then calls `broker.espArm()` (using `slot-update`'s privileged fd `60`) and `/usr/bin/reboot`.
   - Any confined root process can therefore bypass `mount-broker`'s role separation, bypass `image-floor` anti-rollback checks (when TPM retirement is not active), arm an older slot, and immediately reboot the system.
2. **Local package updates (`u.image == null`) build in `/data/svc/autoupdate/work` (`slot.zig:53-224, 314-380`):**
   - `fence` grants confined root write access to `/data`.
   - When `u.image == null` (package-based updates), `buildSlot()` constructs `work/root`, `work/stage0`, and `work/slot/{root.erofs,vmlinuz,stage0.zst,cmdline}` directly inside `/data/svc/autoupdate/work`. Then `installEsp()` hashes whatever files are in `/data/svc/autoupdate/work/slot/*` (`signed.hashFile`) and tells `mount-broker` to install those hashes onto the ESP and `/boot/slot/<other>`!
   - Confined root can modify files in `/data/svc/autoupdate/work` during `buildSlot()` before `mkfs.erofs`, `writeCpio`, or `signed.hashFile()` runs, injecting arbitrary code into the next slot's rootfs or initramfs.
3. **Destructive disarm/overwrite before verifying all staged ESP artifacts (`cmd/mount-broker/mount-broker.zig:822-836`):**
   - `espInstallNow` unlinks the other slot's loader entries (`825-827`) and overwrites `vmlinuz` (`830`) before verifying `stage0.zst` (`831`) and `uki.efi` (`833`). If `stage0.zst` or `uki.efi` fails `copyChecked`, the other slot on the ESP is left half-written.

---

### 2.5 Fail-Open Paths in `stage0`, `init`, `slot-keep`, and `modload`
- **Severity:** Medium to High
- **Location:**
  - `cmd/stage0/stage0.zig:305-343`
  - `cmd/slot-keep/slot-keep.zig:145-151`
  - `cmd/init/init.zig:248-251`
  - `cmd/init/kernel.zig:135-140`
  - `cmd/init/data.zig:51-59`
  - `cmd/modload/modload.zig:105-122`

**Weaknesses:**
1. **`stage0` deadman switch runs unconfined in initramfs and trusts `/run/werewolf/committed` (`stage0.zig:305-343`):**
   - `deadman` forks before `init` applies `seal`, `fence`, `MDWE`, or capability bounding drops, mounts a second `procfs` at `/deadman` without `hidepid=invisible`, and only checks `access("/deadman/1/root/run/werewolf/committed", F_OK)`. Any process with write access to `/run/werewolf` (such as confined root) can touch `/run/werewolf/committed` to disarm rollback without committing the slot in `mount-broker`.
2. **`slot-keep` swallows `markCommitted` write failure (`slot-keep.zig:145-151`):**
   ```zig
   fn markCommitted(io: Io) !void {
       Dir.cwd().writeFile(
           io,
           .{ .sub_path = committed, .data = "" },
       ) catch |err| say(io, "{s}: {s}", .{ committed, @errorName(err) });
   }
   ```
   `markCommitted` returns `!void` and callers use `try markCommitted(io)` before `park(io)`, yet `markCommitted` catches and logs the error without returning it. If writing `/run/werewolf/committed` fails, `slot-keep` parks permanently and `stage0`'s deadman reboots a slot that was already committed on the ESP.
3. **`init` ignores mount, lockdown, `modload`, and `/boot` read-only remount failures:**
   - `m.mount()` (`cmd/init/init.zig:248-251`) discards the exit code of `/usr/lib/werewolf/mount`.
   - `cmd/init/kernel.zig:135-137` ignores errors writing `"confidentiality"` to `/sys/kernel/security/lockdown` and never verifies that lockdown took effect (unlike `cmd/tpm-enroll/tpm-enroll.zig:50-53`).
   - `cmd/init/kernel.zig:139` logs a message and continues if `/usr/lib/werewolf/modload` fails (potentially leaving `kernel.modules_disabled` unset).
   - `cmd/init/data.zig:51-59` logs a message and continues booting with `/boot` **mounted read-write** if remounting `/boot` read-only fails.
4. **`modload` loads ALL kernel modules when stdin is empty (`cmd/modload/modload.zig:105-122`):**
   - In `cmd/init/kernel.zig:139`, `init` runs `/usr/lib/werewolf/modload` with stdin redirected to `/dev/null` (empty stdin). Because `named` is `false` when stdin is empty, `modload` loads **every** tagged module in `/usr/lib/modules/load.order` (`@btrfs`, `@xfs`, `@hyperv`, `@esp`) into the kernel before locking `modules_disabled`.

---

## 3. Input Sanitization, Parser Bugs & Cryptographic Inconsistencies

### 3.1 TPM Candidate Boot PCR Verification, Unverified `boot.release`, and DA Lockout Risk
- **Severity:** High
- **Location:** `lib/tpm.zig:476-525`, `802-828`, `cmd/stage0/stage0.zig:203`, `cmd/tpm-enroll/tpm-enroll.zig:39-42`, `lib/enrollment.zig:14-17`

**Weaknesses:**
1. **`checkPcr` skips PCR 11 comparison for candidate boots (`lib/tpm.zig:824-828`):**
   ```zig
   fn checkPcr(record: Record, release: [32]u8, pcr: [32]u8) !void {
       try measured(pcr);
       if (std.mem.eql(u8, &release, &record.retained) and !std.mem.eql(u8, &pcr, &record.pcr))
           return error.UnmeasuredBoot;
   }
   ```
   Because `Record` only stores one `pcr: [32]u8` field (for `retained`), when booting a candidate release (`release == record.candidate`), `checkPcr` only checks `pcr != [0; 32]`.
2. **`stage0` trusts `boot.release` from `/proc/cmdline` without binding it to `params.root` (`stage0.zig:203`):**
   - `stage0` parses `werewolf.release=<hex>` from `/proc/cmdline` and passes `boot.release` to `tpm.boot()`, never verifying that the mounted `/root` (`params.root` dm-verity digest or `/root/usr/share/werewolf/...`) matches `boot.release`.
3. **`tpm-enroll` does not check EFI variable attributes or `PK`/`KEK`/`db` (`tpm-enroll.zig:39-42`, `enrollment.zig:14-17`):**
   - `enrollment.firmware()` checks `on.len != 5 or setup.len != 5 or on[4] != 1 or setup[4] != 0`, ignoring the 4-byte EFI variable attribute mask (`0x00000006`) and never verifying `PK`, `KEK`, or `db` in `efivarfs` against `/enrollment/publisher.pub` (unlike `lib/boot-authority.zig:84-87`).
4. **`hierarchyProtected()` sends failing platform auth commands on every `floor()` / `anchor()` call (`lib/tpm.zig:511-525`):**
   - When `phEnable == 1` with firmware-held random auth, `hierarchyProtected()` sends `TPM2_HierarchyControl(TPM_RH_PLATFORM, 1)` with an empty password expecting `TPM_RC_AUTH_FAIL` (`0x98e`) or `TPM_RC_BAD_AUTH` (`0x9a2`). On TPMs where platform hierarchy auth failures increment the Dictionary Attack counter, repeated calls trigger `TPM_RC_LOCKOUT` (`0x921`).
5. **Debug-only `std.debug.assert` bounds checks in `lib/tpm.zig:852` and `lib/tpm-bootstrap.zig:493`:**
   - `Bytes.bytes` and `Packet.bytes` use `std.debug.assert(raw.len <= b.data.len - b.len)` instead of returning an error or panicking unconditionally in release builds.

---

### 3.2 `lib/apk.zig` `u16` Integer Truncation Panic & `lib/package.zig` Metadata Injection
- **Severity:** Medium
- **Location:** `lib/apk.zig:20`, `334-356`, `lib/package.zig:117-189`, `264-304`

**Weaknesses:**
1. **`u16` overflow panic in `signatureSegment` (`lib/apk.zig:334, 356`):**
   - `max_signature` is `64 << 10` (`65536`), and line 334 allows `sig.len <= max_signature`.
   - Line 351 computes `body = tar[0 .. 512 + std.mem.alignForward(usize, sig.len, 512)]`. When `sig.len` is between `65024` and `65536`, `body.len` is `65536` or `66048`, panicking at `const len: u16 = @intCast(body.len)` (line 356).
2. **Unchecked newlines/NULs in `lib/package.zig` (`117-189, 264-304`):**
   - `pack()` formats `info.name`, `info.version`, `info.arch`, `info.description`, `info.url`, `info.license`, `info.depends`, and `info.provides` into `.PKGINFO` and `APKINDEX` stanzas without rejecting `\n` or control characters.

---

### 3.3 NoCloud `cidata` Injection, Line-by-Line SSH Key Scraping, and Unvalidated `users` Keys
- **Severity:** Medium to High
- **Location:** `cmd/init/config.zig:59-72`, `520-570`, `lib/people.zig:65-90`, `cmd/cloud-metadata/cloud-metadata.zig:656-690`

**Weaknesses:**
1. **`cidata` ISO9660 volume is mounted even when `config.tar` already exists (`cmd/init/config.zig:59-72`):**
   - When `/boot/config.tar` (or a `config.tar` block device) is present (`tar != null`), `config()` still mounts `seed_dev` (`cidata`) and runs `nocloud(m)`, creating an interactive shell user (`/bin/ash`) from an untrusted attached CD/USB/secondary volume.
2. **Structure-blind `parseNoCloud` (`cmd/init/config.zig:520-570`):**
   - `parseNoCloud` calls `sshKeys(gpa, line, &found_keys)` on every line of `/mnt/user-data` without tracking YAML indentation or sections, assigning any SSH public key found anywhere in `user-data` (comments, `write_files`, or other user blocks) to the first user.
3. **Unvalidated SSH keys in `lib/people.zig` (`65-90`) and `gcpUsers` (`cloud-metadata.zig:656-690`):**
   - Unlike `lib/sshd.zig:281-312` (`peopleKeys`), which validates key type and base64 structure (`ssh-ed25519`, `sk-*`, `ecdsa-*`), `lib/people.zig` accepts any string without `\r` or `\x00`—allowing `authorized_keys` options (`command="..."`, `environment="..."`) or weak `ssh-rsa` keys into `/run/werewolf/keys/<user>` and `/run/werewolf/keys/root`.
4. **Empty GCP `user-data` fabricates a 1024-byte zero tar (`cloud-metadata.zig:124-126, 437-446`):**
   - When `metadata_users` is enabled on GCP and `bundle.config.len == 0`, `run()` fabricates 1024 zero bytes and writes `/run/werewolf/cloud/config.tar`, causing `poll()` to poll forever even when no cloud config was provided at boot.
5. **Ambiguous HTTP `Content-Length` / `Transfer-Encoding` parsing (`cloud-metadata.zig:838-940`):**
   - `parseHead` accepts duplicate `Content-Length` headers (last wins) and responses with both `Transfer-Encoding: chunked` and `Content-Length`.

---

### 3.4 Host & Helper Tooling Inconsistencies (`howl`, `mount`, `dhcp-client`)
- **Severity:** Low to Medium
- **Location:**
  - `cmd/howl/qemu.zig:281-286`
  - `cmd/howl/apply.zig:379-384`
  - `cmd/howl/firecracker.zig:247, 320-348`
  - `cmd/howl/local-secure.zig:808-812`
  - `cmd/mount/mount.zig:135-143, 205, 431-442`
  - `cmd/dhcp-client/dhcp-client.zig:940-982`

**Weaknesses:**
1. **Unsanitized guest console output in `howl console` on QEMU (`cmd/howl/qemu.zig:281-286, 337`):**
   - `cmd/howl/verbs.zig:383-408` defines `inert()` to strip terminal escape sequences from guest console logs, but `qemu.attach()` writes `console.log` and live console bytes directly to `stdout` without `inert()`.
2. **`howl apply` drops `users` and `--SERVICE.KEY=VALUE` settings (`cmd/howl/apply.zig:379-384`):**
   - `keepMachineConfig` preserves `network`, `data.key`, `authorized_keys`, `hostname`, `machine-transport`, and `update-policy.json`, but silently drops `users` and `settings/*.json` entries created via CLI flags at `howl create` time.
3. **Unverified PID `SIGCONT`/`SIGKILL` and CWD-relative state path in `firecracker.zig` (`247, 320-348`):**
   - `running()` sends `SIGCONT` (rather than signal `0`) and `stop()` sends `SIGKILL` to the raw PID in `firecracker.pid` without checking `/proc/<pid>/comm`, and `forward_marker` (`"build/host/ip_forward-was-off"`) is relative to the current working directory.
4. **Predictable `/tmp/ww-tpm-*` socket path (`cmd/howl/local-secure.zig:808-812`):**
   - Places `swtpm` sockets at `/tmp/ww-tpm-<sha256(at)[0..12]>` in world-writable `/tmp`, allowing any local user on a multi-user host to pre-create the directory and DoS local Secure Boot VM startup.
5. **`cmd/mount` omits `AT_RECURSIVE` on `mount_setattr` and overwrites `-o` (`cmd/mount/mount.zig:141, 205, 438`):**
   - `setattr` passes `AT_EMPTY_PATH` without `AT_RECURSIVE` (`0x8000`).
   - Passing multiple `-o` flags silently discards earlier `-o` flags.
   - Bind mounts whose source starts with `/dev/` (such as `/dev/shm` or `/dev/pts`) omit `ATTR.NODEV` (`line 205`).
6. **`dhcp-client` `withdraw()` / `apply()` state cleanup (`cmd/dhcp-client/dhcp-client.zig:940-982`):**
   - `withdraw()` resets the IP address to `0.0.0.0`, but leaves an attacker-supplied MTU and stale `/run/werewolf/network/resolv.conf` / `lease.json` in place.

---

### 3.5 Live VM Runtime Confinement Findings (`howl run --build`)
- **Severity:** Medium
- **Location:**
  - `cmd/stage0/stage0.zig:305-378`
  - `cmd/slot-update/slot-update.zig:181-206, 335-344, 1194-1239`
  - `lib/broker.zig:26-41`
  - `cmd/posture/posture.zig:141-147`, `cmd/power-button/power-button.zig:249-256`, `cmd/debug-shell/debug-shell.zig:91-99`, `cmd/cloud-metadata/cloud-metadata.zig:283-290`

**Weaknesses Discovered & Resolved in Live Runtime:**
1. **`stage0` deadman child ran for 600s with full initramfs capabilities (`CapEff: 000001fdffffffff`), no seccomp filter (`Seccomp: 0`), and open `/dev/console` descriptors (`stage0.zig:324-340`):**
   - Closed all inherited descriptors except the private `procfs` and `/dev/kmsg` descriptors (`sandbox.closeAllBut`), dropped capabilities to `CAP_SYS_BOOT | CAP_SYS_PTRACE` (`0x00480000`), and installed a strict seccomp allowlist (`nanosleep`, `clock_nanosleep`, `restart_syscall`, `faccessat`, `faccessat2`, `openat`, `write`, `close`, `reboot`, `exit`, `exit_group`).
2. **`slot-update` (`autoupdate` daemon) ran with `NoNewPrivs: 0` and all 22 `fence` capabilities (`CapEff: 00000024b5c4cdff`) (`slot-update.zig:181-206, 1194-1239`):**
   - Bounded `slot-update` at daemon startup to `0x000401df` (`CHOWN`, `DAC_OVERRIDE`, `DAC_READ_SEARCH`, `FOWNER`, `FSETID`, `SETGID`, `SETUID`, `SETPCAP`, `SYS_CHROOT`) with `NoNewPrivs: 1`.
   - Dropped capabilities in `execTool` so `mkfs.erofs`, `zstd`, and `reboot` run with zero capabilities (`sandbox.keepOnly(0)`) and offline `apk` runs with only filesystem capabilities (`0x1f`).
3. **`broker.keepOnlyClient` only closed fds `60..62`, leaving stray `runsv` descriptors open in `slot-update` and `slot-keep` (`lib/broker.zig:26-41`):**
   - Replaced the 3-fd loop with `linux.close_range` across `3..maxInt(fd_t)` (excluding the retained broker socketpair descriptor).
4. **Services parking via `sv down .` (`posture`, `power-button`, `debug-shell`, `cloud-metadata`, `slot-update`) retained capabilities across `execve`:**
   - Added `sandbox.keepOnly(0)` before executing `/usr/bin/sv down .`.

