//! Howl's disposable Linux storage appliance. Its code comes from the normal
//! trusted build pipeline. Attached data never supplies executable code.
const std = @import("std");
const data = @import("data-transfer");
const native = @import("build.zig");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub fn build(b: *native.B, rootfs: []const u8, overlay: []const u8) !void {
    if (!mem.eql(u8, b.name, "data-transfer-helper")) return error.TransferHelperForm;
    const out = try b.path("{s}/helper.cpio.zst", .{b.p.out});
    const began = try b.begin(out, &.{ rootfs, overlay }) orelse return;
    const work = try b.path("{s}/helper", .{b.p.out});
    try Dir.cwd().createDirPath(b.io, work);
    const init = try b.path("{s}/init", .{work});
    if (b.spec.published) {
        const file = try Dir.cwd().createFile(b.io, init, .{ .permissions = .fromMode(0o755) });
        defer file.close(b.io);
        try b.run(&.{ "bsdtar", "-xOf", rootfs, "usr/lib/werewolf/data-transfer-helper" }, .{ .stdout = file });
    } else try b.copy(try b.path("{s}/data-transfer-helper/usr/lib/werewolf/data-transfer-helper", .{b.p.programs}), init);
    const init_tar = try b.path("{s}/init.tar", .{b.p.out});
    try b.run(&.{ "bsdtar", "-cf", init_tar, "-C", work, "init" }, .{});
    const cpio = try b.path("{s}/helper.cpio", .{b.p.out});
    try b.run(&.{ "bsdtar", "-cf", cpio, "--format", "newc", "--uid", "0", "--gid", "0", "--numeric-owner", try b.path("@{s}", .{rootfs}), try b.path("@{s}", .{overlay}), try b.path("@{s}", .{init_tar}) }, .{});
    const temp = try b.tmp(out);
    try b.run(&.{ "zstd", "-1", "-q", "-T1", "-f", cpio, "-o", temp }, .{});
    try b.rename(temp, out);
    try Dir.cwd().deleteFile(b.io, cpio);
    try b.done(out, began);
}

pub const Guest = struct {
    arch: howl.Arch,
    kernel: []const u8,
    initramfs: []const u8,
    image: []const u8,
    verity: @import("verity").Params,
};
pub const Devices = struct { data: []const u8, control: []const u8, writable: bool = false, guard: ?Io.File = null };

pub fn run(io: Io, a: Allocator, g: Guest, d: Devices, work: []const u8) !data.Policy {
    const console = try a.print("{s}/console.log", .{work});
    const output = try a.print("{s}/archive.tar.zst", .{work});
    const status = try a.print("{s}.status", .{console});
    for ([_][]const u8{ console, output, status }) |path| {
        const f = try Dir.cwd().createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        f.close(io);
    }
    try executeLocked(io, try argv(a, g, d, console, output), .fromSeconds(12 * 3600), d.guard);
    const approved = try policy(a, try Dir.cwd().readFileAlloc(io, status, a, .limited(1 << 20)));
    if (!mem.eql(u8, approved.image, &std.fmt.bytesToHex(g.verity.root, .lower)) or
        !mem.eql(u8, @tagName(approved.arch), @tagName(g.arch))) return error.TransferImage;
    return approved;
}

/// Reap the fixed helper command on completion or deadline, including errors.
pub fn execute(io: Io, args: []const []const u8, timeout: Io.Duration) !void {
    return executeLocked(io, args, timeout, null);
}

fn executeLocked(io: Io, args: []const []const u8, timeout: Io.Duration, guard: ?Io.File) !void {
    var child = try std.process.spawn(io, .{
        .argv = args,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
        .inherit_files = if (guard) |file| &.{file} else &.{},
    });
    defer child.kill(io);
    const Event = union(enum) { process: std.process.Child.WaitError!std.process.Child.Term, timeout: Io.Cancelable!void };
    var events: [2]Event = undefined;
    var select = Io.Select(Event).init(io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.process, std.process.Child.wait, .{ &child, io });
    try select.concurrent(.timeout, Io.sleep, .{ io, timeout, .awake });
    switch (try select.await()) {
        .timeout => return error.TransferTimeout,
        .process => |ended| if (!(try ended).success()) return error.TransferHelper,
    }
}

/// The disk is private and immutable for the helper's lifetime. mke2fs copies
/// only our staging tree, never an arbitrary archive or guest filesystem.
pub fn controlDisk(io: Io, a: Allocator, work: []const u8, request: anytype, archive: ?[]const u8, key: ?[]const u8, why: *howl.Why) ![]const u8 {
    const files = try a.print("{s}/control", .{work});
    try Dir.cwd().createDir(io, files, .fromMode(0o700));
    try @import("boot-image.zig").durable(io, try a.print("{s}/request.json", .{files}), try std.json.Stringify.valueAlloc(a, request, .{}));
    var size: u64 = 32 << 20;
    if (archive) |path| {
        const input = try Dir.cwd().openFile(io, path, .{});
        defer input.close(io);
        const st = try input.stat(io);
        if (st.kind != .file) return error.TransferFileType;
        size = try std.math.add(u64, size, st.size + st.size / 16);
        try copy(io, input, try a.print("{s}/archive.tar.zst", .{files}));
    }
    if (key) |path| {
        const contents = try Dir.cwd().readFileAlloc(io, path, a, .limited(4096));
        if (contents.len < 32) return error.TransferKey;
        try @import("boot-image.zig").durable(io, try a.print("{s}/key", .{files}), contents);
    }
    const disk = try a.print("{s}/control.img", .{work});
    const f = try Dir.cwd().createFile(io, disk, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.setLength(io, size);
    const mk = @import("ext4.zig").findMke2fs(io, a) orelse return why.refuse("no mke2fs; install e2fsprogs", .{});
    try howl.run(io, why, &.{ mk, "-q", "-F", "-t", "ext4", "-m", "0", "-E", "lazy_itable_init=0,lazy_journal_init=0", "-d", files, disk });
    try f.sync(io);
    return disk;
}

fn copy(io: Io, source: Io.File, destination: []const u8) !void {
    const out = try Dir.cwd().createFile(io, destination, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer out.close(io);
    var buf: [128 << 10]u8 = undefined;
    while (true) {
        const n = source.readStreaming(io, &.{&buf}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        try out.writeStreamingAll(io, buf[0..n]);
    }
    try out.sync(io);
}

fn escaped(a: Allocator, text: []const u8) ![]const u8 {
    for (text) |c| if (std.ascii.isControl(c)) return error.TransferPath;
    if (!std.fs.path.isAbsolute(text)) return error.TransferPath;
    return mem.replaceOwned(u8, a, text, ",", ",,");
}

/// Fixed device roles; no user-supplied QEMU options, network or host shares.
pub fn argv(a: Allocator, g: Guest, d: Devices, console: []const u8, output: []const u8) ![]const []const u8 {
    const host = howl.hostArch() orelse return error.UnsupportedHostArch;
    if (g.arch != host) return error.TransferArchitecture;
    const mac = @import("builtin").os.tag == .macos;
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(a, &.{ if (g.arch == .aarch64) "qemu-system-aarch64" else "qemu-system-x86_64", "-M", if (g.arch == .aarch64) "virt,gic-version=3" else "q35", "-accel", if (mac) "hvf" else "kvm", "-cpu", "host", "-smp", "2", "-m", "2048", "-nodefaults", "-no-reboot", "-display", "none", "-monitor", "none", "-nic", "none", "-serial", try a.print("file:{s}", .{try escaped(a, console)}), "-kernel", g.kernel, "-initrd", g.initramfs, "-append", if (g.arch == .aarch64) "console=ttyAMA0 panic=-1 rdinit=/init" else "console=ttyS0 panic=-1 rdinit=/init" });
    for ([_][]const u8{ d.data, d.control, g.image }, 0..) |path, i| {
        try args.appendSlice(a, &.{ "-drive", try a.print("if=none,id=d{d},format=raw,readonly={s},file={s}", .{ i, if (i == 0 and d.writable) "off" else "on", try escaped(a, path) }), "-device", try a.print("virtio-blk-pci,drive=d{d}", .{i}) });
    }
    try args.appendSlice(a, &.{ "-device", "virtio-serial-pci", "-chardev", try a.print("file,id=transfer,path={s}", .{try escaped(a, output)}), "-device", "virtserialport,chardev=transfer,name=werewolf.transfer", "-chardev", try a.print("file,id=status,path={s}.status", .{try escaped(a, console)}), "-device", "virtserialport,chardev=status,name=werewolf.transfer.status", "-object", "rng-random,id=rng0,filename=/dev/urandom", "-device", "virtio-rng-pci,rng=rng0" });
    // Retain the already-held flock in QEMU's private descriptor set. If Howl
    // dies, another lifecycle operation still waits until this helper exits.
    if (d.guard) |file| try args.appendSlice(a, &.{ "-add-fd", try a.print("fd={d},set=9,opaque=transfer-lifecycle", .{file.handle}) });
    return args.toOwnedSlice(a);
}

pub fn policy(a: Allocator, console: []const u8) !data.Policy {
    if (console.len > 1 << 20) return error.TransferConsole;
    var lines = mem.tokenizeAny(u8, console, "\r\n");
    var result: ?data.Policy = null;
    var completed = false;
    while (lines.next()) |line| {
        const prefix = "werewolf-transfer-policy: ";
        if (mem.startsWith(u8, line, prefix)) {
            if (result != null or completed) return error.TransferConsole;
            result = try std.json.parseFromSliceLeaky(data.Policy, a, line[prefix.len..], .{});
        } else if (mem.eql(u8, line, "werewolf-transfer-complete")) {
            if (completed or result == null) return error.TransferConsole;
            completed = true;
        } else if (mem.startsWith(u8, line, "werewolf-transfer-error:")) {
            // Report fixed failure codes, never guest-controlled text or paths.
            inline for (.{ error.TransferUnclean, error.TransferKey, error.TransferImage, error.TransferImageUnrecorded, error.TransferPostgresUnclean, error.TransferPostgresVersion, error.TransferPostgresControl, error.TransferFilesystem, error.TransferRead, error.TransferInstall, error.TransferHelperUnmount }) |err| {
                if (mem.eql(u8, line, "werewolf-transfer-error: " ++ @errorName(err))) return err;
            }
            return error.TransferHelper;
        }
    }
    if (!completed) return error.TransferIncomplete;
    return result orelse return error.TransferIncomplete;
}

test "helper command attaches only explicit storage with no network or shares" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try argv(a, .{ .arch = howl.hostArch().?, .kernel = "/kernel", .initramfs = "/init", .image = "/image", .verity = .{ .data_blocks = 1, .hash_start = 1, .salt = @splat(0), .root = @splat(0) } }, .{ .data = "/a,b/data", .control = "/control" }, "/console", "/output");
    var disks: usize = 0;
    for (args, 0..) |arg, i| {
        try t.expect(!mem.eql(u8, arg, "-netdev") and !mem.eql(u8, arg, "-virtfs"));
        if (mem.eql(u8, arg, "-nic")) try t.expectEqualStrings("none", args[i + 1]);
        if (mem.eql(u8, arg, "-drive")) {
            disks += 1;
            try t.expect(mem.find(u8, args[i + 1], "readonly=on") != null);
        }
    }
    try t.expectEqual(@as(usize, 3), disks);
    try t.expectError(error.TransferPath, escaped(a, "relative"));
    try t.expectEqualStrings("/a,,b/data", try escaped(a, "/a,b/data"));
}

test "helper success requires one policy and explicit terminal completion" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const line = "werewolf-transfer-policy: {\"image\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"arch\":\"aarch64\",\"services\":[],\"users\":[],\"groups\":[]}\n";
    try t.expectError(error.TransferIncomplete, policy(a, line));
    _ = try policy(a, line ++ "werewolf-transfer-complete\r\n");
    try t.expectError(error.TransferConsole, policy(a, line ++ line ++ "werewolf-transfer-complete\n"));
    try t.expectError(error.TransferKey, policy(a, line ++ "werewolf-transfer-error: TransferKey\n"));
    try t.expectError(error.TransferUnclean, policy(a, "werewolf-transfer-error: TransferUnclean\n"));
    try t.expectError(error.TransferHelper, policy(a, "werewolf-transfer-error: untrusted diagnostic\n"));
    try t.expectError(error.TransferConsole, policy(a, "werewolf-transfer-complete\n"));
}
