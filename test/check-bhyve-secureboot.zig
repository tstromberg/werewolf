//! check-bhyve-secureboot HOWL FIXTURE boots a signed x86_64 provider A/B
//! fixture (test/ab-fixture.zig) on bhyve with one bit of its native UKI
//! changed: the manually enrolled firmware must refuse it before stage0.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;
const json = std.json;
const Provider = host.provider.Provider;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "bhyve-secureboot") catch std.process.exit(1);
    c.finish(run(&c));
}

/// Outcome is what a console says of a changed UKI so far.
pub const Outcome = enum { waiting, refused, reached };

/// outcome judges a tampered boot's console: it must never reach stage0,
/// and the firmware must say it denied the image.
pub fn outcome(console: []const u8) Outcome {
    if (mem.find(u8, console, "stage0:") != null or
        mem.find(u8, console, "handing over to runit") != null) return .reached;
    if (std.ascii.findIgnoreCase(console, "access denied") != null or
        std.ascii.findIgnoreCase(console, "security violation") != null) return .refused;
    return .waiting;
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    if (c.args.len != 3) return c.fail("usage: check-bhyve-secureboot HOWL FIXTURE", .{});
    const howl = try c.absolute(c.args[1]);
    const text = try Io.Dir.cwd().readFileAlloc(io, c.args[2], gpa, .limited(16 << 20));
    const options: json.ParseOptions = .{ .ignore_unknown_fields = true };
    var fixture = try json.parseFromSliceLeaky(host.provider.Fixture, gpa, text, options);
    if (!mem.eql(u8, fixture.arch, "x86_64") or !fixture.secure())
        return c.fail("bhyve refusal test requires a signed x86_64 fixture", .{});
    const check_dir = c.env.get("CHECK") orelse "build/ipe-check";
    const logs = try std.fs.path.join(gpa, &.{ check_dir, "bhyve-secureboot" });
    try Io.Dir.cwd().createDirPath(io, logs);
    var id: [6]u8 = undefined;
    io.random(&id);
    const work = try gpa.print("/tmp/ww-ab-refused-{s}", .{&std.fmt.bytesToHex(id, .lower)});
    try Io.Dir.cwd().createDir(io, work, .fromMode(0o700));
    defer Io.Dir.cwd().deleteTree(io, work) catch {};
    try c.setWork(work);
    const result = refuse(c, &fixture, howl);
    copyLogs(io, gpa, work, logs) catch {};
    return result;
}

fn refuse(c: *host.Check, fixture: *host.provider.Fixture, howl: []const u8) !void {
    const io = c.io;
    const gpa = c.gpa;
    const raw = try c.path("tampered.img");
    const source = fixture.disk;
    const to_raw = [_][]const u8{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", source, raw };
    _ = try c.must(&to_raw, "convert", .{});
    const uki = try c.path("uki.efi");
    const esp = try gpa.print("{s}@@1048576", .{raw});
    _ = try c.must(&.{ "mcopy", "-i", esp, "::/werewolf/a/uki.efi", uki }, "extract", .{});
    const data = try Io.Dir.cwd().readFileAlloc(io, uki, gpa, .unlimited);
    if (data.len == 0) return c.fail("the fixture's native UKI is empty", .{});
    data[data.len / 2] ^= 1;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = uki, .data = data });
    _ = try c.must(&.{ "mcopy", "-o", "-i", esp, uki, "::/werewolf/a/uki.efi" }, "tamper", .{});
    const disk = try c.path("tampered.qcow2");
    const to_qcow2 = [_][]const u8{ "qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, disk };
    _ = try c.must(&to_qcow2, "convert", .{});
    fixture.disk = disk;
    const machine = try gpa.create(Provider);
    machine.init(io, gpa, .bhyve, fixture.*, c.work, howl, &c.env) catch |err|
        return failed(c, machine, err);
    const booted = boot(c, machine);
    const stopped = machine.stop();
    try booted;
    stopped catch |err| return failed(c, machine, err);
    c.say("pass   bhyve-secureboot: enrolled firmware refused the changed UKI before stage0", .{});
}

fn boot(c: *host.Check, machine: *Provider) !void {
    machine.start() catch |err| return failed(c, machine, err);
    const deadline = host.qemu.after(c.io, 120);
    while (Io.Clock.Timestamp.now(c.io, .awake).compare(.lt, deadline)) {
        const console = machine.console() catch |err| return failed(c, machine, err);
        switch (outcome(console)) {
            .reached => return c.fail("changed UKI reached stage0", .{}),
            .refused => return,
            .waiting => try c.io.sleep(.fromSeconds(2), .awake),
        }
    }
    return c.fail("missing explicit firmware rejection; see console.raw.log", .{});
}

fn copyLogs(io: Io, gpa: std.mem.Allocator, from: []const u8, to: []const u8) !void {
    var dir = try Io.Dir.cwd().openDir(io, from, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| if (e.kind == .file and mem.endsWith(u8, e.name, ".log"))
        try dir.copyFile(e.name, .cwd(), try std.fs.path.join(gpa, &.{ to, e.name }), io, .{});
}

test "a tampered boot passes only on the firmware's refusal" {
    try std.testing.expectEqual(.waiting, outcome("BdsDxe: loading Boot0001\r\n"));
    const denied = "BdsDxe: failed to load Boot0001: Access Denied\r\n";
    try std.testing.expectEqual(.refused, outcome(denied));
    try std.testing.expectEqual(.refused, outcome("Image: SECURITY VIOLATION\r\n"));
    try std.testing.expectEqual(.reached, outcome("Access Denied\r\nstage0: slot a\r\n"));
    try std.testing.expectEqual(.reached, outcome("werewolf: up in 1s, handing over to runit\r\n"));
}

/// failed is err, as a provider's reason when it gave one.
fn failed(c: *host.Check, machine: *Provider, err: anyerror) anyerror {
    if (err == error.ProviderFailed) return c.fail("{s}", .{machine.why});
    return err;
}
