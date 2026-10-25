//! check-lima-secureboot DISK ENROLLED WORK boots a signed release disk
//! under Lima on an arm64 Mac, in a private LIMA_HOME: through QEMU on the
//! immutable enrolled firmware, it must pass posture with Secure Boot
//! enforced and the native slot verified, leaving the enrollment unchanged;
//! through VZ, which cannot meet the requirement, stage0 must refuse it.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;
const json = std.json;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "lima-secureboot") catch std.process.exit(1);
    c.finish(run(&c));
}

pub const Backend = enum { qemu, vz };

/// passed is whether a console shows backend's outcome yet, true once it
/// does; a console that shows the wrong one refuses, with why.
pub fn passed(backend: Backend, console: []const u8, why: *host.check.Why) !bool {
    switch (backend) {
        .vz => {
            const refusal = "Secure Boot required outside setup mode";
            if (mem.find(u8, console, refusal) == null) return false;
            if (mem.find(u8, console, "handing over to runit") != null)
                return why.refuse("VZ handed over a release that requires Secure Boot", .{});
            return true;
        },
        .qemu => {
            if (mem.find(u8, console, "Kernel panic") != null)
                return why.refuse("the guest kernel panicked", .{});
            if (mem.find(u8, console, "posture: fail=") == null) return false;
            if (mem.find(u8, console, "\"unexpected\":[]") == null) return false;
            for ([_][]const u8{
                "Secure Boot enforced outside setup mode",
                "Secure Boot admits only this image's signer",
                "native UKI selected slot a",
                "verified (root hash",
            }) |sign| if (mem.find(u8, console, sign) == null)
                return why.refuse("posture passed without \"{s}\" on the console", .{sign});
            return true;
        },
    }
}

fn run(c: *host.Check) !void {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64)
        return c.fail("check-lima-secureboot requires an arm64 Mac", .{});
    if (c.args.len != 4) return c.fail("usage: check-lima-secureboot DISK ENROLLED WORK", .{});
    const io = c.io;
    const gpa = c.gpa;
    const disk = try c.absolute(c.args[1]);
    const enrolled = try c.absolute(c.args[2]);
    try c.setWork(c.args[3]);
    try Io.Dir.cwd().setFilePermissions(io, c.work, .fromMode(0o700), .{});
    const variables = try std.fs.path.join(gpa, &.{ enrolled, "vars.fd" });
    const before = try host.check.digest(io, variables);
    // Keep Lima's socket paths below macOS's 104-byte Unix path limit.
    var id: [6]u8 = undefined;
    io.random(&id);
    const state = try gpa.print("/tmp/ww-sb-lima-{s}", .{&std.fmt.bytesToHex(id, .lower)});
    try Io.Dir.cwd().createDir(io, state, .fromMode(0o700));
    defer Io.Dir.cwd().deleteTree(io, state) catch {};
    try c.env.put("LIMA_HOME", state);
    try boot(c, .qemu, disk, enrolled, variables);
    if (!mem.eql(u8, &try host.check.digest(io, variables), &before))
        return c.fail("Lima's QEMU changed the immutable enrollment", .{});
    try boot(c, .vz, disk, enrolled, variables);
    c.say("pass   lima-secureboot: QEMU enforces immutable enrollment; " ++
        "VZ refuses required Secure Boot", .{});
}

const Image = struct {
    location: []const u8,
    arch: []const u8 = "aarch64",
    vmType: ?[]const u8 = null,
};

fn boot(
    c: *host.Check,
    backend: Backend,
    disk: []const u8,
    enrolled: []const u8,
    variables: []const u8,
) !void {
    const io = c.io;
    const gpa = c.gpa;
    const name = try gpa.print("secureboot-{t}", .{backend});
    var env = try c.env.clone(gpa);
    var firmware: ?struct { images: []const Image } = null;
    if (backend == .qemu) {
        const code = try std.fs.path.join(gpa, &.{ enrolled, "code.fd" });
        firmware = .{ .images = try gpa.dupe(Image, &.{.{ .location = code, .vmType = "qemu" }}) };
        // QEMU reads a doubled comma as one in an option's value.
        const file = try mem.replaceOwned(u8, gpa, variables, ",", ",,");
        const drive = try gpa.print("if=pflash,format=raw,unit=1,readonly=on,file={s}", .{file});
        const quoted = try host.check.quote(gpa, drive);
        const qemu = try gpa.print("qemu-system-aarch64 -drive {s}", .{quoted});
        try env.put("QEMU_SYSTEM_AARCH64", qemu);
    }
    const config = try json.Stringify.valueAlloc(gpa, .{
        .vmType = @tagName(backend),
        .plain = true,
        .arch = "aarch64",
        .cpus = 2,
        .memory = "1GiB",
        .mounts = [_][]const u8{},
        .containerd = .{ .system = false, .user = false },
        .images = [_]Image{.{ .location = disk }},
        .firmware = firmware,
    }, .{ .emit_null_optional_fields = false });
    const template = try c.path(try gpa.print("{t}.yaml", .{backend}));
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = template, .data = config });
    const lima = try std.fs.path.join(gpa, &.{ env.get("LIMA_HOME").?, name });
    const host_log = try c.path(try gpa.print("{t}-host.log", .{backend}));
    var client: host.qemu.Machine = undefined;
    const start = [_][]const u8{
        "limactl",
        "start",
        "--tty=false",
        try gpa.print("--name={s}", .{name}),
        template,
    };
    try client.start(io, gpa, &start, .{ .log = host_log, .environ_map = &env });
    var seen: []const u8 = "";
    const outcome = watch(c, backend, &client, lima, host_log, &seen);
    const console_log = try c.path(try gpa.print("{t}-console.log", .{backend}));
    Io.Dir.cwd().writeFile(io, .{ .sub_path = console_log, .data = seen }) catch {};
    const delete = [_][]const u8{ "limactl", "delete", "--force", name };
    const deleted = host.check.command(io, gpa, &delete, .{ .environ_map = &env });
    client.stop(.fromSeconds(30));
    try outcome;
    const d = deleted catch |err| return c.fail("limactl delete {s}: {t}", .{ name, err });
    if (!d.ok()) return c.fail("limactl delete {s}: {s}", .{ name, d.stderr });
}

fn watch(
    c: *host.Check,
    backend: Backend,
    client: *host.qemu.Machine,
    lima: []const u8,
    host_log: []const u8,
    seen: *[]const u8,
) !void {
    const io = c.io;
    const deadline = host.qemu.after(io, 120);
    while (Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline)) {
        seen.* = try serials(io, c.gpa, lima);
        var why: host.check.Why = .{};
        const done = passed(backend, seen.*, &why) catch
            return c.fail("{t}: {s}", .{ backend, why.text });
        if (done) return;
        if (client.exited() and !client.term.?.success())
            return c.fail("Lima failed; see {s}", .{host_log});
        try io.sleep(.fromMilliseconds(500), .awake);
    }
    return c.fail("missing firmware outcome: {t}", .{backend});
}

/// serials is Lima's serial logs of a machine, in name order.
fn serials(io: Io, gpa: mem.Allocator, dir: []const u8) ![]const u8 {
    var d = Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch return "";
    defer d.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (!mem.startsWith(u8, e.name, "serial") or !mem.endsWith(u8, e.name, ".log")) continue;
        try names.append(gpa, try gpa.dupe(u8, e.name));
    }
    mem.sortUnstable([]const u8, names.items, {}, lessThan);
    var out: std.ArrayList(u8) = .empty;
    for (names.items) |n| try out.appendSlice(gpa, try d.readFileAlloc(io, n, gpa, .unlimited));
    return out.items;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

test "each backend passes only on its own evidence" {
    var why: host.check.Why = .{};
    const required = "stage0: Secure Boot required outside setup mode\n";
    const handed = "werewolf: up in 1s, handing over to runit\n";
    try std.testing.expect(!try passed(.vz, "booting\n", &why));
    try std.testing.expect(try passed(.vz, required, &why));
    try std.testing.expectError(error.Refused, passed(.vz, required ++ handed, &why));
    const enforced = "stage0: Secure Boot enforced outside setup mode\n";
    const good = enforced ++
        "stage0: Secure Boot admits only this image's signer\n" ++
        "stage0: native UKI selected slot a\n" ++
        "stage0: slot a: verified (root hash ab)\n" ++
        "posture: fail= pass=90 {\"known\":{\"unexpected\":[]}}\n";
    try std.testing.expect(try passed(.qemu, good, &why));
    try std.testing.expect(!try passed(.qemu, enforced, &why));
    const panicked = "Kernel panic - not syncing\n";
    try std.testing.expectError(error.Refused, passed(.qemu, panicked, &why));
    const gpa = std.testing.allocator;
    const unsigned = try mem.replaceOwned(u8, gpa, good, "native UKI selected slot a", "slot a");
    defer gpa.free(unsigned);
    try std.testing.expectError(error.Refused, passed(.qemu, unsigned, &why));
}
