//! service-config renders a service's settings into the file its daemon reads.
//! leash runs it as `service-config DIR` at each start of a service with settings.
//! See README.md.

const std = @import("std");
const settings = @import("settings");
const sandbox = @import("sandbox");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch std.process.exit(1);
    if (args.len != 2 or args[1].len == 0 or args[1][0] != '/') {
        log(io, .{ .event = "settings", .why = "usage: service-config DIR" });
        std.process.exit(1);
    }
    const service = std.fs.path.basename(args[1]);
    if (std.os.linux.getuid() == 0) {
        log(io, .{ .event = "settings", .service = service, .why = "run as root" });
        std.process.exit(1);
    }
    run(io, gpa, args[1], service) catch |err| switch (err) {
        error.Refused => std.process.exit(1),
        else => {
            log(io, .{ .event = "settings", .service = service, .why = @errorName(err) });
            std.process.exit(1);
        },
    };
}

fn run(io: Io, gpa: Allocator, path: []const u8, service: []const u8) !void {
    var stdin = Io.File.stdin().readerStreaming(io, &.{});
    var why: []const u8 = "";
    const decl = declarations(
        gpa,
        try stdin.interface.allocRemaining(gpa, .limited(64 << 10)),
        &why,
    ) catch |err| switch (err) {
        error.BadDeclaration => {
            log(io, .{ .event = "settings", .service = service, .why = why });
            return error.Refused;
        },
        else => return err,
    };
    var dir = try Dir.cwd().openDir(io, path, .{ .follow_symlinks = false });
    defer dir.close(io);
    const input = try dir.readFileAlloc(
        io,
        settings.input_file,
        gpa,
        .limited(settings.max_input + 1),
    );
    const base = if (decl.render.from) |from|
        try Dir.cwd().readFileAlloc(io, from, gpa, .limited(settings.max_input))
    else
        null;
    try pledge();

    var diag: settings.Diagnostic = .{};
    const values = settings.parseValues(gpa, decl.settings, input, &diag) catch |err| switch (err) {
        error.Invalid => {
            log(io, .{
                .event = "settings",
                .service = service,
                .setting = diag.setting,
                .index = diag.index,
                .why = diag.why,
            });
            return error.Refused;
        },
        else => return err,
    };
    const output = settings.render(gpa, decl.settings, decl.render, values, base) catch |err|
        switch (err) {
            error.Invalid => return error.BaseNotAnObject,
            else => return err,
        };

    // Unlink and create anew rather than truncate: a planted hard link would
    // make the write land in another file.
    dir.deleteFile(io, decl.render.file) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    var out = try dir.createFile(
        io,
        decl.render.file,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    defer out.close(io);
    try out.writeStreamingAll(io, output);

    var set: std.ArrayList([]const u8) = .empty;
    for (decl.settings, values) |s, v| if (v != null) try set.append(gpa, s.name);
    log(io, .{ .event = "settings", .service = service, .set = set.items });
}

const Declarations = struct {
    settings: []settings.Setting,
    render: settings.Render,
};

/// pledge allows only the calls left once every input is read: memory,
/// replacing one file, writes and exit. rt_sigaction is there because Zig's
/// I/O restores its SIGIO handler at exit. Any other call kills the process.
fn pledge() !void {
    var f: sandbox.Filter = .{};
    inline for (.{
        "mmap",   "munmap", "mremap",       "unlinkat", "openat",
        "writev", "close",  "rt_sigaction", "exit",     "exit_group",
    }) |call| f.allow(call);
    try f.install();
}

/// declarations parses the `setting` and `render` lines leash passed. leash
/// already checked them with the same functions, so a refusal here is a bug;
/// why says which line.
fn declarations(gpa: Allocator, text: []const u8, why: *[]const u8) !Declarations {
    var list: std.ArrayList(settings.Setting) = .empty;
    var r: ?settings.Render = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        while (it.next()) |w| try words.append(gpa, w);
        if (words.items.len == 0) continue;
        const key = words.items[0];
        const rest = words.items[1..];
        if (std.mem.eql(u8, key, "setting")) {
            try list.append(
                gpa,
                settings.parseSetting(rest, why) catch return error.BadDeclaration,
            );
        } else if (std.mem.eql(u8, key, "render") and r == null) {
            r = settings.parseRender(rest, why) catch return error.BadDeclaration;
        } else {
            why.* = "a line that is not one setting or the render";
            return error.BadDeclaration;
        }
    }
    const render = r orelse {
        why.* = "no render line";
        return error.BadDeclaration;
    };
    settings.declare(gpa, list.items, render, why) catch |err| switch (err) {
        error.Invalid => return error.BadDeclaration,
        else => return err,
    };
    return .{ .settings = list.items, .render = render };
}

/// log writes one JSON line to stderr. If it does not fit, it writes a short
/// line saying so, never nothing: leash points at this line when it parks a service.
fn log(io: Io, fields: anytype) void {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const line = if (format(&w, fields))
        w.buffered()
    else |_|
        "service-config: {\"event\":\"settings\",\"why\":\"a line too long to say\"}\n";
    Io.File.stderr().writeStreamingAll(io, line) catch {};
}

fn format(w: *Io.Writer, fields: anytype) !void {
    try w.writeAll("service-config: ");
    try std.json.Stringify.value(fields, .{ .emit_null_optional_fields = false }, w);
    try w.writeByte('\n');
}

test declarations {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: []const u8 = "";
    const d = try declarations(gpa,
        \\setting destinations addrport... as PermitOpen
        \\render conf destinations
        \\
    , &why);
    try std.testing.expectEqualStrings("PermitOpen", d.settings[0].key.?);
    try std.testing.expectEqual(settings.Format.conf, d.render.format);
    for ([_][]const u8{
        "setting destinations addrport...\n",
        "render conf x\nrender conf y\nsetting a ip\n",
        "setting a string\nrender conf x\n",
        "exec /bin/sh\nsetting a ip\nrender conf x\n",
    }) |text| {
        why = "";
        try std.testing.expectError(error.BadDeclaration, declarations(gpa, text, &why));
        try std.testing.expect(why.len > 0);
    }
}
