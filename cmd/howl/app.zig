//! app stages --app DIR, a built application, for the build to lay over a form's
//! image at the path form.yaml's app: names, and compiles the tutorials'
//! applications (examples/README.md). See README.md.

const std = @import("std");
const howl = @import("howl.zig");
const native = @import("build.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const B = native.B;

/// Example is a tutorial whose application compiles on this host, for an
/// image with no toolchain: form go-example, rust-example or aspnet-example.
pub const Example = enum { go, rust, aspnet };

/// example returns which compiled tutorial form name is, or null.
pub fn example(name: []const u8) ?Example {
    const suffix = "-example";
    if (!std.mem.endsWith(u8, name, suffix)) return null;
    return std.meta.stringToEnum(Example, name[0 .. name.len - suffix.len]);
}

/// compiled returns what compile makes in out, OUT: aspnet's stamp, or the
/// server binary.
pub fn compiled(gpa: Allocator, out: []const u8, e: Example) ![]const u8 {
    return if (e == .aspnet)
        gpa.print("{s}/application.stamp", .{out})
    else
        gpa.print("{s}/application/usr/lib/app/server", .{out});
}

/// compile builds the form's tutorial application, if it is one, into
/// OUT/application/usr/lib/app, unless it is newer than its source and
/// howl. Each arch has its own; nothing is written into examples/.
pub fn compile(b: *B) !void {
    const e = example(b.name) orelse return;
    const target = try compiled(b.gpa, b.p.out, e);
    const sources: []const []const u8 = switch (e) {
        .go => &.{"examples/go/main.go"},
        .rust => &.{"examples/rust/main.rs"},
        .aspnet => &.{ "examples/aspnet/Program.cs", "examples/aspnet/App.csproj" },
    };
    const inputs = try std.mem.concat(b.gpa, []const u8, &.{ sources, &.{b.self} });
    const began = try b.begin(target, inputs) orelse return;
    const arm = b.spec.arch == .aarch64;
    switch (e) {
        .go => {
            try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(target).?);
            var env = try b.env.clone(b.gpa);
            try env.put("CGO_ENABLED", "0");
            try env.put("GOOS", "linux");
            try env.put("GOARCH", if (arm) "arm64" else "amd64");
            try b.run(&.{
                "go",
                "build",
                "-trimpath",
                "-buildvcs=false",
                "-ldflags=-s -w",
                "-o",
                target,
                sources[0],
            }, .{ .env = &env });
        },
        .rust => {
            try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(target).?);
            try b.run(try std.mem.concat(b.gpa, []const u8, &.{ try rustc(b.gpa), &.{
                "--edition=2021",
                "--target",
                try b.path("{t}-unknown-linux-musl", .{b.spec.arch}),
                "-C",
                "linker=rust-lld",
                "-C",
                "target-feature=+crt-static",
                "-C",
                "opt-level=2",
                "-C",
                "strip=symbols",
                "-o",
                target,
                sources[0],
            } }), .{});
        },
        // App.dll and App.pdb hold these absolute paths, and the sources'.
        .aspnet => {
            try b.run(&.{
                "dotnet",
                "publish",
                sources[1],
                "--configuration",
                "Release",
                "--runtime",
                if (arm) "linux-arm64" else "linux-x64",
                "--self-contained",
                "false",
                "-p:UseAppHost=false",
                "--artifacts-path",
                try b.absolute(try b.path("{s}/dotnet", .{b.p.out})),
                "--output",
                try b.absolute(try b.path("{s}/application/usr/lib/app", .{b.p.out})),
            }, .{});
            try Dir.cwd().writeFile(b.io, .{ .sub_path = target, .data = "" });
        },
    }
    try b.done(target, began);
}

/// rustc returns the command that compiles Rust: RUSTC, split at spaces, if
/// it is set, else rustup's stable rustc.
fn rustc(gpa: Allocator) ![]const []const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeAny(u8, howl.environ.get("RUSTC") orelse "", " \t\n");
    while (it.next()) |w| try words.append(gpa, w);
    if (words.items.len == 0) return &.{ "rustup", "run", "stable", "rustc" };
    return words.items;
}

const File = struct { path: []const u8, exec: bool };

pub const Staged = struct { files: usize, bytes: u64, digest: [64]u8 };

/// stage copies the regular files and directories under src to root/at and
/// returns their count, size and digest. It refuses links, devices and
/// setuid or setgid files, which an application never needs. The digest
/// covers every path, executable bit and byte, so the same DIR gives the
/// same image.
pub fn stage(
    io: Io,
    gpa: Allocator,
    src: []const u8,
    root: []const u8,
    at: []const u8,
    why: *howl.Why,
) !Staged {
    var from = Dir.cwd().openDir(io, src, .{ .iterate = true }) catch |err|
        return why.refuse("--app {s}: {s}", .{ src, @errorName(err) });
    defer from.close(io);

    var files: std.ArrayList(File) = .empty;
    var dirs: std.ArrayList([]const u8) = .empty;
    var walker = try from.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        // Skip macOS Finder files so they do not change the digest.
        if (std.mem.eql(u8, e.basename, ".DS_Store") or
            std.mem.startsWith(u8, e.basename, "._")) continue;
        const path = try gpa.dupe(u8, e.path);
        switch (e.kind) {
            .directory => try dirs.append(gpa, path),
            .file => {
                const st = try e.dir.statFile(io, e.basename, .{ .follow_symlinks = false });
                const mode = st.permissions.toMode();
                if (mode & 0o6000 != 0)
                    return why.refuse("--app {s}: {s} is setuid or setgid", .{ src, path });
                try files.append(gpa, .{ .path = path, .exec = mode & 0o100 != 0 });
            },
            else => return why.refuse(
                "--app {s}: {s} is not a regular file or directory; an application is files",
                .{ src, path },
            ),
        }
    }
    if (files.items.len == 0) return why.refuse("--app {s}: no files", .{src});
    std.mem.sortUnstable(File, files.items, {}, struct {
        fn lt(_: void, a: File, b: File) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);

    Dir.cwd().deleteTree(io, root) catch {};
    const base = try std.fs.path.join(gpa, &.{ root, at[1..] });
    try Dir.cwd().createDirPath(io, base);
    var into = try Dir.cwd().openDir(io, base, .{});
    defer into.close(io);
    for (dirs.items) |d| try into.createDirPath(io, d);

    var h: Sha256 = .init(.{});
    var bytes: u64 = 0;
    var buf: [1 << 16]u8 = undefined;
    for (files.items) |f| {
        h.update(f.path);
        h.update(if (f.exec) "\x00x\x00" else "\x00-\x00");
        var in = try from.openFile(io, f.path, .{});
        defer in.close(io);
        var out = try into.createFile(
            io,
            f.path,
            .{ .permissions = .fromMode(if (f.exec) 0o755 else 0o644) },
        );
        defer out.close(io);
        while (true) {
            const n = in.readStreaming(io, &.{&buf}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            h.update(buf[0..n]);
            try out.writeStreamingAll(io, buf[0..n]);
            bytes += n;
        }
        h.update("\x00");
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return .{
        .files = files.items.len,
        .bytes = bytes,
        .digest = std.fmt.bytesToHex(digest, .lower),
    };
}

const testing = std.testing;

test example {
    try testing.expectEqual(Example.go, example("go-example").?);
    try testing.expectEqual(Example.aspnet, example("aspnet-example").?);
    try testing.expectEqual(null, example("python-example"));
    try testing.expectEqual(null, example("example-go"));
    try testing.expectEqual(null, example("rust"));
}

test stage {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "src/lib");
    try tmp.dir.writeFile(io, .{ .sub_path = "src/main.py", .data = "print('hi')\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "src/lib/util.py", .data = "x = 1\n" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const src = try std.fs.path.join(gpa, &.{ root, "src" });
    var why: howl.Why = .{};

    const a = try stage(
        io,
        gpa,
        src,
        try std.fs.path.join(gpa, &.{ root, "stage" }),
        "/usr/lib/app",
        &why,
    );
    try testing.expectEqual(@as(usize, 2), a.files);
    const copied = try tmp.dir.readFileAlloc(
        io,
        "stage/usr/lib/app/lib/util.py",
        gpa,
        .limited(64),
    );
    try testing.expectEqualStrings("x = 1\n", copied);
    // The same files give the same digest; one changed byte changes it.
    const b = try stage(
        io,
        gpa,
        src,
        try std.fs.path.join(gpa, &.{ root, "stage" }),
        "/usr/lib/app",
        &why,
    );
    try testing.expectEqualStrings(&a.digest, &b.digest);
    try tmp.dir.writeFile(io, .{ .sub_path = "src/main.py", .data = "print('hi!')\n" });
    const c = try stage(
        io,
        gpa,
        src,
        try std.fs.path.join(gpa, &.{ root, "stage" }),
        "/usr/lib/app",
        &why,
    );
    try testing.expect(!std.mem.eql(u8, &a.digest, &c.digest));

    try tmp.dir.symLink(io, "/etc/passwd", "src/link", .{});
    try testing.expectError(
        error.Refused,
        stage(io, gpa, src, try std.fs.path.join(gpa, &.{ root, "stage" }), "/usr/lib/app", &why),
    );
}
