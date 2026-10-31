//! Public, synthetic Plex-layout SQLite/media fixtures. This checks the data
//! contract; real Plex account/playback checks require separate credentials.
//! Production archives are installed only inside the isolated Linux helper.
const std = @import("std");
const host = @import("host");
const data = @import("data-transfer");
const Io = std.Io;
const Dir = Io.Dir;
const A = std.mem.Allocator;
const db = "svc/plex/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db";

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "plex-data") catch std.process.exit(1);
    c.finish(run(&c));
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const a = c.gpa;
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    try c.setWork(try a.print("build/check/plex-data/{s}", .{std.fmt.bytesToHex(nonce, .lower)}));
    try Dir.cwd().setFilePermissions(io, c.work, .fromMode(0o700), .{});
    try Dir.cwd().createDirPath(io, try c.path("source"));
    var source = try Dir.cwd().openDir(io, try c.path("source"), .{ .iterate = true });
    defer source.close(io);
    for ([_][]const u8{
        std.fs.path.dirname(db).?,
        "svc/plex-media/Movies",
        "svc/sshd",
        ".werewolf",
        "log",
    }) |path|
        try source.createDirPath(io, path);
    _ = try c.must(&.{ "sqlite3", try c.path(try a.print(
        "source/{s}",
        .{db},
    )), "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; " ++
        "CREATE TABLE metadata_items(id INTEGER PRIMARY KEY,title TEXT); " ++
        "CREATE TABLE watch_state(id INTEGER PRIMARY KEY,view_count INTEGER,view_offset " ++
        "INTEGER); " ++
        "INSERT INTO metadata_items VALUES(7,'Public fixture'); " ++
        "INSERT INTO watch_state VALUES(7,1,123000); PRAGMA wal_checkpoint(TRUNCATE)" ++
        ";" }, "seed-sqlite", .{});
    var media: [1 << 20]u8 = undefined;
    Io.random(io, &media);
    try source.writeFile(
        io,
        .{ .sub_path = "svc/plex-media/Movies/public-fixture.bin", .data = &media },
    );
    try source.writeFile(
        io,
        .{
            .sub_path = "svc/plex/Preferences.xml",
            .data = "<Preferences MachineIdentifier=\"public-fixture\"/>\n",
            .flags = .{ .permissions = .fromMode(0o600) },
        },
    );
    try source.writeFile(
        io,
        .{ .sub_path = "svc/plex/artwork.bin", .data = "\x00\xffpublic artwork\x00" },
    );
    try source.writeFile(io, .{ .sub_path = "notes", .data = "ordinary data outside services" });
    for ([_][]const u8{ ".werewolf/identity", "svc/sshd/host-key", "log/current" }) |path|
        try source.writeFile(io, .{ .sub_path = path, .data = "source machine state" });
    const owner = try ownership(
        null,
        .{ .handle = source.handle, .flags = .{ .nonblocking = false } },
    );
    const policy: data.Policy = .{
        .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .arch = switch (@import("builtin").cpu.arch) {
            .aarch64 => .aarch64,
            .x86_64 => .x86_64,
            else => return error.Architecture,
        },
        .services = &.{ "plex", "plex-media" },
        .users = &.{.{ .name = "fixture", .id = owner.uid }},
        .groups = &.{.{ .name = "fixture", .id = owner.gid }},
    };
    const owners: data.Ownership = .{ .get = ownership };
    const Case = struct { from: ?[]const u8 = null, to: ?[]const u8 = null };
    for ([_]Case{
        .{},
        .{ .from = "plex" },
        .{ .to = "plex" },
        .{ .from = "plex-media" },
        .{ .to = "plex-media" },
    }, 0..) |case, n| {
        const scope = case.to orelse case.from;
        const manifest = try data.scan(io, a, source, policy, case.from, owners);
        var tar: Io.Writer.Allocating = .init(a);
        defer tar.deinit();
        _ = try data.emit(io, a, source, manifest, policy, owners, &tar.writer);
        const tar_path = try c.path(try a.print("capture-{d}.tar", .{n}));
        try Dir.cwd().writeFile(
            io,
            .{
                .sub_path = tar_path,
                .data = tar.written(),
                .flags = .{ .permissions = .fromMode(0o600) },
            },
        );
        const compressed = try std.process.run(a, io, .{
            .argv = &.{
                "zstd",
                "-1",
                "-q",
                "--single-thread",
                "--no-asyncio",
                "-c",
                "--",
                tar_path,
            },
            .stdout_limit = .limited(4 << 20),
            .stderr_limit = .limited(4096),
        });
        if (!compressed.term.success()) return error.Compression;
        const target_path = try c.path(try a.print("target-{d}", .{n}));
        try Dir.cwd().createDirPath(io, target_path);
        var target = try Dir.cwd().openDir(io, target_path, .{ .iterate = true });
        defer target.close(io);
        for ([_][]const u8{
            ".werewolf",
            "svc/sshd",
            "log",
        }) |path| try target.createDirPath(io, path);
        try target.setFilePermissions(io, ".werewolf", .fromMode(0o700), .{});
        for ([_][]const u8{ ".werewolf/identity", "svc/sshd/host-key", "log/current" }) |path|
            try target.writeFile(io, .{ .sub_path = path, .data = "destination machine state" });
        const companion = if (scope) |s| if (std.mem.eql(u8, s, "plex"))
            "svc/plex-media"
        else
            "svc/plex" else null;
        if (companion) |path| {
            try target.createDirPath(io, path);
            try target.writeFile(
                io,
                .{ .sub_path = try a.print("{s}/sentinel", .{path}), .data = "keep companion" },
            );
        }
        var input: Io.Reader = .fixed(compressed.stdout);
        const restored = try data.install.apply(
            io,
            a,
            &input,
            target,
            policy,
            .{ .target = target_path, .service = case.to },
        );
        for (restored.manifest.entries) |entry| if (data.importSelected(entry.path, scope)) {
            const st = try target.statFile(io, entry.path, .{ .follow_symlinks = false });
            if (st.permissions.toMode() & 0o7777 != entry.mode or
                st.mtime.nanoseconds != entry.mtime_ns) return error.Metadata;
            if (entry.kind == .file and
                !std.mem.eql(
                    u8,
                    try source.readFileAlloc(io, entry.path, a, .limited(2 << 20)),
                    try target.readFileAlloc(io, entry.path, a, .limited(2 << 20)),
                )) return error.Bytes;
        };
        for ([_][]const u8{ ".werewolf/identity", "svc/sshd/host-key", "log/current" }) |path|
            if (!std.mem.eql(
                u8,
                "destination machine state",
                try target.readFileAlloc(io, path, a, .limited(128)),
            )) return error.Authority;
        if (companion) |path| if (!std.mem.eql(
            u8,
            "keep companion",
            try target.readFileAlloc(io, try a.print("{s}/sentinel", .{path}), a, .limited(128)),
        )) return error.Companion;
        if (scope == null or std.mem.eql(u8, scope.?, "plex")) {
            const result = try c.must(
                &.{
                    "sqlite3",
                    try a.print("{s}/{s}", .{ target_path, db }),
                    "PRAGMA integrity_check; SELECT title,view_count,view_offset FROM " ++
                        "metadata_items JOIN watch_state USING(id);",
                },
                try a.print("sqlite-{d}", .{n}),
                .{},
            );
            if (!std.mem.eql(
                u8,
                std.mem.trim(u8, result.stdout, "\r\n"),
                "ok\nPublic fixture|1|123000",
            )) return error.Database;
        }
    }
    c.say(
        "pass: synthetic Plex SQLite/media full and single-service round trips; metadata, " ++
            "companions and authority preserved",
        .{},
    );
}

fn ownership(_: ?*anyopaque, file: Io.File) !data.Owner {
    if (@import("builtin").os.tag == .linux) {
        const linux = std.os.linux;
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(
            file.handle,
            "",
            linux.AT.EMPTY_PATH,
            .{ .UID = true, .GID = true },
            &st,
        )) != .SUCCESS) return error.Owner;
        return .{ .uid = st.uid, .gid = st.gid };
    } else {
        var st: std.c.Stat = undefined;
        if (std.c.fstat(file.handle, &st) != 0) return error.Owner;
        return .{ .uid = st.uid, .gid = st.gid };
    }
}
