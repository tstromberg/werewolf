//! Kernel IPE integration probe. It deliberately has no Landlock, seccomp,
//! or noexec mount, so a refusal proves the IPE boundary itself.
const std = @import("std");
const linux = std.os.linux;
const dm = @import("dm");
const verity = @import("verity");
const ipe = @import("ipe");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len > 1) {
        if (std.mem.eql(u8, args[1], "admin") and canWrite(ipe.base ++ "/enforce", "0"))
            std.process.exit(99);
        return;
    }
    run(io, gpa) catch |err| {
        std.debug.print("ipe-check: FAIL {s}\n", .{@errorName(err)});
        poweroff();
    };
    std.debug.print("ipe-check: PASS\n", .{});
    poweroff();
}

fn run(io: std.Io, gpa: std.mem.Allocator) !void {
    try mount("proc", "/proc", "proc", 0);
    try mount("sysfs", "/sys", "sysfs", 0);
    try mount("devtmpfs", "/dev", "devtmpfs", 0);
    try mount("securityfs", "/sys/kernel/security", "securityfs", 0);
    // This short-lived probe has no audit daemon. Keep all refusal records
    // on the console instead of exhausting printk's ten-message burst.
    try write("/proc/sys/kernel/printk_ratelimit", "0");
    try verifiedMount(io, gpa, "/dev/vda", "/verity", "root", "/trusted");
    try verifiedMount(io, gpa, "/dev/vdb", "/other-verity", "other", "/other");
    // Executable tmpfs, deliberately. noexec must not explain a refusal.
    try mount("tmpfs", "/untrusted", "tmpfs", 0);
    try std.Io.Dir.cwd().copyFile(
        "/trusted/usr/lib/werewolf/ipe-probe",
        .cwd(),
        "/untrusted/probe",
        io,
        .{},
    );
    try std.Io.Dir.cwd().setFilePermissions(io, "/untrusted/probe", .fromMode(0o755), .{});
    try std.Io.Dir.cwd().copyFile(
        "/trusted/usr/bin/busybox",
        .cwd(),
        "/untrusted/busybox",
        io,
        .{},
    );
    const signed = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "/ipe.p7b",
        gpa,
        .limited(ipe.max_policy),
    );
    try write(ipe.base ++ "/new_policy", signed);
    try write(ipe.active, "1");
    try write(ipe.base ++ "/enforce", "1");
    try execResult(
        "/trusted/usr/lib/werewolf/ipe-probe",
        &.{ "/trusted/usr/lib/werewolf/ipe-probe", "noop" },
        false,
    );
    try execResult("/untrusted/probe", &.{ "/untrusted/probe", "noop" }, true);
    try execResult("/other/probe", &.{ "/other/probe", "noop" }, true);
    // The trusted loader must not map an ELF from the executable tmpfs.
    const loader_path: [:0]const u8 = switch (@import("builtin").cpu.arch) {
        .aarch64 => "/trusted/usr/lib/ld-linux-aarch64.so.1",
        .x86_64 => "/trusted/usr/lib/ld-linux-x86-64.so.2",
        else => unreachable,
    };
    try execResult(
        loader_path,
        &.{ loader_path, "--library-path", "/trusted/usr/lib", "/untrusted/busybox", "true" },
        true,
    );
    // Also prove this loader works for the trusted copy with the same libs.
    try execResult(
        loader_path,
        &.{ loader_path, "--library-path", "/trusted/usr/lib", "/trusted/usr/bin/busybox", "true" },
        false,
    );
    try mapping(io, "/trusted/usr/lib/werewolf/ipe-probe", false);
    try mapping(io, "/untrusted/probe", true);
    try anonymousMapping();
    try ipe.lockAdmin();
    if (canWrite(ipe.base ++ "/enforce", "0")) return error.PolicyDisabled;
    if (canWrite(ipe.active, "1")) return error.PolicyAdminRetained;
    if (canWrite(ipe.base ++ "/new_policy", signed)) return error.PolicyReplaceable;
    const cap = linux.prctl(23, 33, 0, 0, 0);
    if (linux.errno(cap) != .SUCCESS or cap != 0) return error.CapabilityRegained;
    try execResult(
        "/trusted/usr/lib/werewolf/ipe-probe",
        &.{ "/trusted/usr/lib/werewolf/ipe-probe", "admin" },
        false,
    );
    // The restriction must survive fork and exec as well as the current PID.
    try execResult("/untrusted/probe", &.{ "/untrusted/probe", "noop" }, true);
    // kauditd emits asynchronously; give its queue time before poweroff.
    try io.sleep(.fromSeconds(1), .awake);
}

fn verifiedMount(
    io: std.Io,
    gpa: std.mem.Allocator,
    dev: []const u8,
    params_path: []const u8,
    name: [:0]const u8,
    at: [:0]const u8,
) !void {
    const params = try verity.Params.parse(try std.Io.Dir.cwd().readFileAlloc(
        io,
        params_path,
        gpa,
        .limited(4096),
    ));
    var buf: [512]u8 = undefined;
    const table = try verity.table(&buf, dev, params);
    const number = try dm.create(
        name,
        "verity",
        params.data_blocks * (verity.block_size / 512),
        table,
    );
    const node = try gpa.printSentinel("/dev/mapper/{s}", .{name}, 0);
    if (linux.errno(linux.mknodat(linux.AT.FDCWD, node, linux.S.IFBLK | 0o600, number)) != .SUCCESS)
        return error.DeviceNode;
    try mount(node, at, "erofs", linux.MS.RDONLY);
}

fn execResult(path: [:0]const u8, args: []const [:0]const u8, refused: bool) !void {
    var argv: [9:null]?[*:0]const u8 = @splat(null);
    for (args, 0..) |arg, i| argv[i] = arg;
    const env = [_:null]?[*:0]const u8{};
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.Fork;
    if (pid == 0) {
        const e = linux.errno(linux.execve(path, &argv, &env));
        linux.exit_group(if (refused and e == .ACCES) 42 else 99);
    }
    var raw_status: i32 = 0;
    const waited = linux.errno(linux.waitpid(@intCast(pid), &raw_status, 0)) == .SUCCESS;
    const status: u32 = @bitCast(raw_status);
    const code = linux.W.EXITSTATUS(status);
    const loader_denied = memLoader(path) and code == 127;
    if (!waited or !linux.W.IFEXITED(status) or
        (if (refused) code != 42 and !loader_denied else code != 0))
    {
        std.debug.print(
            "ipe-check: exec {s} expected {s}, status {d}\n",
            .{ path, if (refused) "deny" else "allow", status },
        );
        return error.Exec;
    }
}

fn memLoader(path: []const u8) bool {
    return std.mem.indexOf(u8, path, "/ld-linux-") != null;
}

fn mapping(io: std.Io, path: []const u8, refused: bool) !void {
    const f = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    const result = linux.mmap(
        null,
        4096,
        .{ .READ = true, .EXEC = true },
        .{ .TYPE = .PRIVATE },
        f.handle,
        0,
    );
    const e = linux.errno(result);
    if (e == .SUCCESS) _ = linux.munmap(@ptrFromInt(result), 4096);
    if ((refused and e != .ACCES) or (!refused and e != .SUCCESS)) return error.Mapping;
    const readable = linux.mmap(null, 4096, .{ .READ = true }, .{ .TYPE = .PRIVATE }, f.handle, 0);
    if (linux.errno(readable) != .SUCCESS) return error.ReadMapping;
    const address: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(readable);
    defer _ = linux.munmap(address, 4096);
    const protected = linux.errno(linux.mprotect(address, 4096, .{ .READ = true, .EXEC = true }));
    if ((refused and protected != .ACCES) or (!refused and
        protected != .SUCCESS)) return error.Protect;
}

fn mount(source: [:0]const u8, target: [:0]const u8, kind: [:0]const u8, flags: u32) !void {
    _ = linux.mkdir(target, 0o755);
    if (linux.errno(linux.mount(source, target, kind, flags, 0)) != .SUCCESS) return error.Mount;
}

fn anonymousMapping() !void {
    const PR_SET_MDWE = 65;
    const PR_MDWE_REFUSE_EXEC_GAIN = 1;
    // Before PR_SET_MDWE is set (as on an allow: [jit] form), anonymous
    // memory can be made executable under IPE; file-backed memory cannot.
    const jit = linux.mmap(
        null,
        4096,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    if (linux.errno(jit) != .SUCCESS) return error.AnonymousReadMapping;
    const jit_addr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(jit);
    defer _ = linux.munmap(jit_addr, 4096);
    if (linux.errno(linux.mprotect(jit_addr, 4096, .{ .READ = true, .EXEC = true })) != .SUCCESS)
        return error.JitProtect;
    // Once PID 1 sets PR_SET_MDWE (every non-JIT form), anonymous W^X is refused.
    if (linux.errno(linux.prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0)) != .SUCCESS)
        return error.Mdwe;
    const executable = linux.mmap(
        null,
        4096,
        .{ .READ = true, .WRITE = true, .EXEC = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    if (linux.errno(executable) == .SUCCESS) _ = linux.munmap(@ptrFromInt(executable), 4096);
    if (linux.errno(executable) != .ACCES) return error.AnonymousExecutable;
    const readable = linux.mmap(
        null,
        4096,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    if (linux.errno(readable) != .SUCCESS) return error.AnonymousReadMapping;
    const address: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(readable);
    defer _ = linux.munmap(address, 4096);
    if (linux.errno(linux.mprotect(address, 4096, .{ .READ = true, .EXEC = true })) != .ACCES)
        return error.AnonymousProtect;
}

fn canWrite(path: [:0]const u8, text: []const u8) bool {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    return linux.write(@intCast(fd), text.ptr, text.len) == text.len;
}

fn write(path: [:0]const u8, text: []const u8) !void {
    if (!canWrite(path, text)) return error.Write;
}

fn poweroff() noreturn {
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    linux.exit_group(1);
}
