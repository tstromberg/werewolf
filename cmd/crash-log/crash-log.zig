//! crash-log.so is preloaded into a process that dies on a signal before
//! it can say why. It writes the signal, the pc and the mapping to stderr,
//! and to CRASH_LOG when that names a file, then exits. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

fn install() callconv(.c) void {
    if (comptime builtin.os.tag != .linux or builtin.cpu.arch != .aarch64) return;
    const signals = [_]linux.SIG{ .ILL, .TRAP, .BUS, .SEGV };
    for (signals) |sig| {
        const act = linux.Sigaction{
            .handler = .{ .sigaction = note },
            .mask = std.mem.zeroes(linux.sigset_t),
            .flags = linux.SA.SIGINFO,
        };
        _ = linux.sigaction(sig, &act, null);
    }
}

// The dynamic linker runs .init_array before the program's own constructors.
// A Mach-O test binary has no such section.
comptime {
    if (builtin.os.tag == .linux) {
        @export(&install, .{ .name = "crash_log_install" });
        asm (
            \\.section .init_array,"aw"
            \\.quad crash_log_install
        );
    }
}

// The kernel's aarch64 ucontext (arch/arm64/include/uapi/asm/ucontext.h):
// flags, link, stack_t (24), a 1024-bit sigset (128), then sigcontext.
// sigcontext's pc is fault_address, x0-x30, sp, then pc.
const pc_at: usize = 8 + 8 + 24 + 128 + 8 + 31 * 8 + 8;
// pstate follows pc. The reserved area is 16-aligned, so 8 bytes of padding.
const reserved_at: usize = pc_at + 8 + 8 + 8;
const esr_magic: u32 = 0x45535201;

var once: bool = false;

fn note(sig: linux.SIG, info: *const linux.siginfo_t, ctx: ?*anyopaque) callconv(.c) void {
    if (once) linux.exit_group(128);
    once = true;
    // si_addr is the faulting instruction. The context's pc is printed
    // too: a wrong offset must not be the only address on the line.
    const fault: u64 = @intFromPtr(info.fields.sigfault.addr);
    const pc: u64 = if (ctx) |c|
        std.mem.readInt(u64, @as([*]const u8, @ptrCast(c))[pc_at..][0..8], .little)
    else
        0;
    var buf: [512]u8 = undefined;
    writeOut(format(&buf, @backingInt(sig), info.code, fault, pc, null));
    const maps = loadMaps();
    writeOut(mapFor(fault, maps, &buf));
    writeOut(insnLine(fault, maps, &buf));
    if (fault != pc) writeOut(mapFor(pc, maps, &buf));
    if (covering(maps, fault) == null) writeOut(firstExec(ctx, maps, &buf));
    // The syndrome is last. A bad offset faults, and the lines above stay.
    if (ctx) |c| if (findEsr(@as([*]const u8, @ptrCast(c))[reserved_at..][0..4096])) |esr| {
        writeOut(format(&buf, @backingInt(sig), info.code, fault, pc, esr));
    };
    linux.exit_group(128 + @as(u8, @truncate(@backingInt(sig))));
}

fn writeOut(line: []const u8) void {
    if (line.len == 0) return;
    _ = linux.write(2, line.ptr, line.len);
    if (crashPath()) |path| {
        var zbuf: [128]u8 = undefined;
        if (path.len + 1 > zbuf.len) return;
        @memcpy(zbuf[0..path.len], path);
        zbuf[path.len] = 0;
        const fd = linux.open(
            zbuf[0..path.len :0],
            .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true },
            0o644,
        );
        if (linux.errno(fd) != .SUCCESS) return;
        _ = linux.write(@intCast(fd), line.ptr, line.len);
        _ = linux.close(@intCast(fd));
    }
}

fn crashPath() ?[]const u8 {
    if (comptime builtin.os.tag != .linux) return null;
    const block = std.c.environ;
    var i: usize = 0;
    while (block[i]) |entry| : (i += 1) {
        const s = std.mem.span(entry);
        const v = std.mem.cutPrefix(u8, s, "CRASH_LOG=") orelse continue;
        if (v.len == 0 or v[0] != '/') return null;
        return v;
    }
    return null;
}

/// format writes one line. esr is omitted when the context has none.
fn format(buf: []u8, sig: u32, code: i32, addr: u64, pc: u64, esr: ?u64) []u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (esr) |e| {
        w.print(
            "crash-log: signal {d} code {d} addr 0x{x} pc 0x{x} esr 0x{x}\n",
            .{ sig, code, addr, pc, e },
        ) catch return buf[0..0];
    } else {
        w.print(
            "crash-log: signal {d} code {d} addr 0x{x} pc 0x{x}\n",
            .{ sig, code, addr, pc },
        ) catch return buf[0..0];
    }
    return w.buffered();
}

fn findEsr(reserved: []const u8) ?u64 {
    var i: usize = 0;
    while (i + 16 <= reserved.len) : (i += 8) {
        if (std.mem.readInt(u32, reserved[i..][0..4], .little) != esr_magic) continue;
        const size = std.mem.readInt(u32, reserved[i + 4 ..][0..4], .little);
        if (size < 16 or i + size > reserved.len) continue;
        return std.mem.readInt(u64, reserved[i + 8 ..][0..8], .little);
    }
    return null;
}

var maps_buf: [48 * 1024]u8 = undefined;

fn loadMaps() []const u8 {
    if (comptime builtin.os.tag != .linux) return maps_buf[0..0];
    const fd = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return maps_buf[0..0];
    defer _ = linux.close(@intCast(fd));
    const n = linux.read(@intCast(fd), &maps_buf, maps_buf.len);
    if (linux.errno(n) != .SUCCESS) return maps_buf[0..0];
    return maps_buf[0..n];
}

fn mapFor(pc: u64, maps: []const u8, buf: []u8) []u8 {
    const line = covering(maps, pc) orelse return buf[0..0];
    var w: std.Io.Writer = .fixed(buf);
    const shown = line[0..@min(line.len, 240)];
    w.print("crash-log: map {s}\n", .{shown}) catch return buf[0..0];
    return w.buffered();
}

fn insnLine(addr: u64, maps: []const u8, buf: []u8) []u8 {
    const line = covering(maps, addr) orelse return buf[0..0];
    const sp = std.mem.findScalar(u8, line, ' ') orelse return buf[0..0];
    if (sp + 1 >= line.len or line[sp + 1] != 'r' or addr % 4 != 0) return buf[0..0];
    const word = @as(*const u32, @ptrFromInt(addr)).*;
    var w: std.Io.Writer = .fixed(buf);
    w.print("crash-log: insn 0x{x}\n", .{word}) catch return buf[0..0];
    return w.buffered();
}

/// firstExec reports the first executable mapping a context word points at.
/// The computed pc can miss; the word that lands in a text mapping does not.
fn firstExec(ctx: ?*anyopaque, maps: []const u8, buf: []u8) []u8 {
    const c = ctx orelse return buf[0..0];
    const raw: [*]const u8 = @ptrCast(c);
    var off: usize = 0;
    while (off + 8 <= 1024) : (off += 8) {
        const v = std.mem.readInt(u64, raw[off..][0..8], .little);
        const line = covering(maps, v) orelse continue;
        const sp = std.mem.findScalar(u8, line, ' ') orelse continue;
        if (sp + 3 >= line.len or line[sp + 3] != 'x') continue;
        var w: std.Io.Writer = .fixed(buf);
        const shown = line[0..@min(line.len, 180)];
        w.print("crash-log: ctx {d} 0x{x} {s}\n", .{ off, v, shown }) catch return buf[0..0];
        return w.buffered();
    }
    return buf[0..0];
}

fn covering(maps: []const u8, pc: u64) ?[]const u8 {
    var it = std.mem.splitScalar(u8, maps, '\n');
    while (it.next()) |line| {
        const dash = std.mem.findScalar(u8, line, '-') orelse continue;
        const start = std.fmt.parseInt(u64, line[0..dash], 16) catch continue;
        const rest = line[dash + 1 ..];
        const sp = std.mem.findScalar(u8, rest, ' ') orelse continue;
        const end = std.fmt.parseInt(u64, rest[0..sp], 16) catch continue;
        if (pc >= start and pc < end) return line;
    }
    return null;
}

test "format names the signal and the pc" {
    var buf: [128]u8 = undefined;
    const line = format(&buf, 4, 1, 0xabc, 0xdef, null);
    try std.testing.expectEqualStrings("crash-log: signal 4 code 1 addr 0xabc pc 0xdef\n", line);
}

test "format keeps an esr" {
    var buf: [128]u8 = undefined;
    const line = format(&buf, 4, 1, 0x10, 0x20, 0x34000000);
    try std.testing.expectEqualStrings(
        "crash-log: signal 4 code 1 addr 0x10 pc 0x20 esr 0x34000000\n",
        line,
    );
}

test "covering finds the mapping that holds the pc" {
    const maps =
        \\00400000-00410000 r--p 00000000 00:01 1 /usr/bin/suricata
        \\00410000-00500000 r-xp 00010000 00:01 1 /usr/bin/suricata
        \\
    ;
    const line = covering(maps, 0x420000) orelse return error.Missed;
    try std.testing.expect(std.mem.startsWith(u8, line, "00410000-00500000 r-xp"));
}

test "findEsr reads the exception syndrome" {
    var raw: [32]u8 = @splat(0);
    std.mem.writeInt(u32, raw[8..][0..4], esr_magic, .little);
    std.mem.writeInt(u32, raw[12..][0..4], 16, .little);
    std.mem.writeInt(u64, raw[16..][0..8], 0x34000000, .little);
    try std.testing.expectEqual(@as(u64, 0x34000000), findEsr(&raw).?);
}
