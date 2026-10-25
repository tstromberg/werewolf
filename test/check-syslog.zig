//! check-syslog boots the shipped logger and its attack probes under QEMU,
//! without building a whole form.
//!
//!     check-syslog --arch ARCH --kernel KERNEL --daemon SYSLOGD --probe PROBE
//!         --leash LEASH --work DIR [--modules DIR]
//!
//! PROBE (test/syslog-init.zig) is init and the attacking client. MODULES,
//! for older development kernels, is a modules directory whose virtio and
//! ext4 modules, with what they depend on, go into the initramfs.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const dir_mode = 0o040000;
const char_mode = 0o020000;
const file_mode = 0o100000;
const link_mode = 0o120000;

const Options = struct {
    arch: []const u8 = "",
    kernel: []const u8 = "",
    daemon: []const u8 = "",
    probe: []const u8 = "",
    leash: []const u8 = "",
    work: []const u8 = "",
    modules: ?[]const u8 = null,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const o = try options(try init.minimal.args.toSlice(gpa));
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(io, o.work);

    var root: Io.Writer.Allocating = .init(gpa);
    const w = &root.writer;
    for ([_][]const u8{
        "dev", "proc",      "run", "run/syslog", "run/config", "data",
        "var", "var/empty", "etc", "usr",        "usr/lib",    "usr/lib/werewolf",
    }) |name| {
        const private = std.mem.eql(u8, name, "run/config");
        try entry(w, name, dir_mode | @as(u32, if (private) 0o700 else 0o755), "", 0, 0);
    }
    try entry(w, "dev/console", char_mode | 0o600, "", 5, 1);
    const probe = try read(io, gpa, o.probe);
    try entry(w, "init", file_mode | 0o755, probe, 0, 0);
    try entry(w, "client", file_mode | 0o755, probe, 0, 0);
    try entry(w, "syslogd", file_mode | 0o755, try read(io, gpa, o.daemon), 0, 0);
    try entry(w, "leash", file_mode | 0o755, try read(io, gpa, o.leash), 0, 0);
    try entry(w, "usr/lib/werewolf/syslogd", link_mode | 0o777, "/syslogd", 0, 0);
    if (o.modules) |dir| try modules(io, gpa, w, dir);
    try entry(w, "TRAILER!!!", 0, "", 0, 0);
    const initrd = try gpa.print("{s}/initramfs.cpio", .{o.work});
    try cwd.writeFile(io, .{ .sub_path = initrd, .data = root.written() });

    const disk = try gpa.print("{s}/data.ext4", .{o.work});
    {
        const file = try cwd.createFile(io, disk, .{});
        defer file.close(io);
        try file.setLength(io, 128 << 20);
    }
    const mke2fs = try std.process.run(gpa, io, .{
        .argv = &.{ "mke2fs", "-q", "-F", "-t", "ext4", disk },
    });
    if (mke2fs.term != .exited or mke2fs.term.exited != 0) {
        std.debug.print("check-syslog: mke2fs: {s}", .{mke2fs.stderr});
        return error.Mke2fs;
    }

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        try gpa.print("qemu-system-{s}", .{o.arch}), "-m",         "256",  "-smp",   "1",
        "-nographic",                                "-no-reboot", "-net", "none",   "-kernel",
        o.kernel,                                    "-initrd",    initrd, "-drive",
        try gpa.print(
            "file={s},format=raw,if=virtio",
            .{disk},
        ),
    });
    const aarch64 = std.mem.eql(u8, o.arch, "aarch64");
    if (aarch64) {
        try argv.appendSlice(gpa, &.{
            "-M", "virt", "-cpu", "cortex-a72", "-append", "console=ttyAMA0 panic=1 audit=1",
        });
    } else {
        try argv.appendSlice(gpa, &.{ "-append", "console=ttyS0 panic=1 audit=1" });
    }
    if (builtin.os.tag == .macos and aarch64) {
        try argv.appendSlice(gpa, &.{ "-accel", "hvf", "-cpu", "host" });
    } else if (builtin.os.tag == .linux) {
        if (cwd.access(io, "/dev/kvm", .{ .read = true, .write = true })) {
            try argv.appendSlice(gpa, &.{ "-accel", "kvm", "-cpu", "host" });
        } else |_| {}
    }

    const log = try gpa.print("{s}/console.log", .{o.work});
    const passed = try boot(io, argv.items, log);
    const text = try cwd.readFileAlloc(io, log, gpa, .limited(64 << 20));
    if (std.mem.find(u8, text, "syslogd: {\"") != null and
        std.mem.find(u8, text, "\"source\":\"kmsg\"") != null)
        fatal("kmsg input echoed to console; see {s}", .{log});
    if (!passed or std.mem.find(u8, text, "syslog-check: PASS") == null or
        std.mem.find(u8, text, "syslog-check: FAIL") != null)
    {
        std.debug.print("{s}\n", .{text[text.len -| 10000..]});
        fatal("failed; see {s}", .{log});
    }
    var stdout = Io.File.stdout().writerStreaming(io, &.{});
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "syslog-check:"))
            try stdout.interface.print("{s}\n", .{std.mem.trimEnd(u8, line, "\r")});
    }
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.debug.print("syslog-check: " ++ format ++ "\n", args);
    std.process.exit(1);
}

fn options(args: []const []const u8) !Options {
    var o: Options = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 2) {
        if (i + 1 == args.len) return usage();
        const value = args[i + 1];
        const flag = args[i];
        if (std.mem.eql(u8, flag, "--arch")) {
            o.arch = value;
        } else if (std.mem.eql(u8, flag, "--kernel")) {
            o.kernel = value;
        } else if (std.mem.eql(u8, flag, "--daemon")) {
            o.daemon = value;
        } else if (std.mem.eql(u8, flag, "--probe")) {
            o.probe = value;
        } else if (std.mem.eql(u8, flag, "--leash")) {
            o.leash = value;
        } else if (std.mem.eql(u8, flag, "--work")) {
            o.work = value;
        } else if (std.mem.eql(u8, flag, "--modules")) {
            o.modules = value;
        } else return usage();
    }
    if (!std.mem.eql(u8, o.arch, "aarch64") and !std.mem.eql(u8, o.arch, "x86_64")) return usage();
    for ([_][]const u8{ o.kernel, o.daemon, o.probe, o.leash, o.work }) |required|
        if (required.len == 0) return usage();
    return o;
}

fn usage() noreturn {
    std.debug.print("usage: check-syslog --arch aarch64|x86_64 --kernel KERNEL " ++
        "--daemon SYSLOGD --probe PROBE --leash LEASH --work DIR [--modules DIR]\n", .{});
    std.process.exit(2);
}

fn read(io: Io, gpa: Allocator, path: []const u8) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(256 << 20));
}

/// entry writes one newc cpio member, owned by root, its name and data each
/// padded to four bytes.
fn entry(
    w: *Io.Writer,
    name: []const u8,
    mode: u32,
    data: []const u8,
    major: u32,
    minor: u32,
) !void {
    const fields = [_]usize{
        1, mode, 0, 0, 1, 0, data.len, 0, 0, major, minor, name.len + 1, 0,
    };
    try w.writeAll("070701");
    for (fields) |field| try w.print("{x:0>8}", .{field});
    try w.writeAll(name);
    try w.writeByte(0);
    const prefix = 6 + fields.len * 8 + name.len + 1;
    try w.splatByteAll(0, (4 - prefix % 4) % 4);
    try w.writeAll(data);
    try w.splatByteAll(0, (4 - data.len % 4) % 4);
}

/// modules adds virtio_pci, virtio_blk and ext4, each after what it depends
/// on, as modules/N.ko in the order init loads them.
fn modules(io: Io, gpa: Allocator, w: *Io.Writer, dir: []const u8) !void {
    const dep = try read(io, gpa, try gpa.print("{s}/modules.dep", .{dir}));
    var needs: std.array_hash_map.String([]const []const u8) = .empty;
    var lines = std.mem.splitScalar(u8, dep, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.findScalar(u8, line, ':') orelse return error.BadModulesDep;
        var deps: std.ArrayList([]const u8) = .empty;
        var words = std.mem.tokenizeAny(u8, line[colon + 1 ..], " \t");
        while (words.next()) |word| try deps.append(gpa, word);
        try needs.put(gpa, line[0..colon], deps.items);
    }
    var selected: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "virtio_pci", "virtio_blk", "ext4" }) |want| {
        for (needs.keys()) |path| {
            const base = std.fs.path.basename(path);
            const stem = base[0 .. std.mem.find(u8, base, ".ko") orelse base.len];
            if (std.mem.eql(u8, stem, want)) try include(gpa, &needs, &selected, path);
        }
    }
    try entry(w, "modules", dir_mode | 0o755, "", 0, 0);
    for (selected.items, 0..) |path, index| {
        const raw = try read(io, gpa, try gpa.print("{s}/{s}", .{ dir, path }));
        var input: Io.Reader = .fixed(raw);
        const data = if (std.mem.endsWith(u8, path, ".gz")) gz: {
            const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
            var d: std.compress.flate.Decompress = .init(&input, .gzip, window);
            break :gz try d.reader.allocRemaining(gpa, .unlimited);
        } else if (std.mem.endsWith(u8, path, ".xz")) xz: {
            var d: std.compress.xz.Decompress = try .init(&input, gpa, &.{});
            break :xz try d.reader.allocRemaining(gpa, .unlimited);
        } else raw;
        try entry(w, try gpa.print("modules/{d}.ko", .{index}), file_mode | 0o600, data, 0, 0);
    }
}

fn include(
    gpa: Allocator,
    needs: *const std.array_hash_map.String([]const []const u8),
    selected: *std.ArrayList([]const u8),
    path: []const u8,
) !void {
    for (selected.items) |done| if (std.mem.eql(u8, done, path)) return;
    for (needs.get(path) orelse return error.MissingModule) |dependency|
        try include(gpa, needs, selected, dependency);
    try selected.append(gpa, path);
}

const Ending = union(enum) {
    exited: std.process.Child.WaitError!std.process.Child.Term,
    timeout: Io.Cancelable!void,
};

/// boot runs QEMU with its console in log, for 90 seconds at most, and says
/// whether it exited 0 in time.
fn boot(io: Io, argv: []const []const u8, log: []const u8) !bool {
    const file = try Io.Dir.cwd().createFile(io, log, .{});
    defer file.close(io);
    var qemu = try std.process.spawn(io, .{
        .argv = argv,
        .stdout = .{ .file = file },
        .stderr = .{ .file = file },
    });
    const pid = qemu.id.?;
    var buffer: [2]Ending = undefined;
    var race: Io.Select(Ending) = .init(io, &buffer);
    try race.concurrent(.exited, std.process.Child.wait, .{ &qemu, io });
    try race.concurrent(.timeout, Io.sleep, .{ io, .fromSeconds(90), .awake });
    switch (try race.await()) {
        .exited => |term| {
            _ = race.cancel();
            const t = try term;
            return t == .exited and t.exited == 0;
        },
        .timeout => {
            // A hung boot is killed; its wait then ends the race.
            std.posix.kill(pid, .KILL) catch {};
            _ = try race.await();
            return false;
        },
    }
}
