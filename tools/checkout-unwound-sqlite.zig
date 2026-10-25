//! checkout-unwound-sqlite fetches the pinned SQLite amalgamation that
//! unwound's static age worker links, refuses it unless it matches the
//! reviewed SHA3-256, and writes sqlite3.h and sqlite3.c into
//! out/third-party/sqlite-3540100, under the current directory.
//!
//!     checkout-unwound-sqlite [--archive FILE]
//!
//! --archive takes an archive downloaded by hand instead of the network.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha3 = std.crypto.hash.sha3.Sha3_256;

const version = "3540100";
const url = "https://www.sqlite.org/2026/sqlite-amalgamation-" ++ version ++ ".zip";
const pin = "92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30";
const output = "out/third-party/sqlite-" ++ version;
const max_archive = 4 << 20;
const fetch_seconds = 30;
const members = [_][]const u8{ "sqlite3.h", "sqlite3.c" };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    checkout(io, gpa, args[1..]) catch |err| {
        std.debug.print("checkout-unwound-sqlite: {s}\n", .{why(err)});
        std.process.exit(1);
    };
}

fn why(err: anyerror) []const u8 {
    return switch (err) {
        error.Usage => "usage: checkout-unwound-sqlite [--archive FILE]",
        error.TooLarge => "SQLite archive exceeds four MiB",
        error.Unpinned => "SQLite archive SHA3-256 does not match the reviewed pin",
        error.MissingMember => "SQLite archive lacks sqlite3.c or sqlite3.h",
        error.BadChecksum => "SQLite archive member fails its CRC-32",
        error.UnexpectedVersion => "unexpected SQLite version",
        error.FetchTimeout => "fetching " ++ url ++ " took more than 30 seconds",
        error.HttpStatus => "fetching " ++ url ++ ": not 200 OK",
        else => @errorName(err),
    };
}

fn checkout(io: Io, gpa: Allocator, args: []const []const u8) !void {
    const archive = switch (args.len) {
        0 => try fetch(io, gpa),
        2 => if (std.mem.eql(u8, args[0], "--archive"))
            Io.Dir.cwd().readFileAlloc(io, args[1], gpa, .limited(max_archive)) catch |err|
                return if (err == error.StreamTooLong) error.TooLarge else err
        else
            return error.Usage,
        else => return error.Usage,
    };
    var digest: [Sha3.digest_length]u8 = undefined;
    Sha3.hash(archive, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), pin)) return error.Unpinned;

    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(io, output);
    var dir = try cwd.openDir(io, output, .{});
    defer dir.close(io);
    // std.zip reads from a file; this one holds the verified bytes alone.
    const scratch = "archive.zip.tmp";
    try dir.writeFile(io, .{ .sub_path = scratch, .data = archive });
    defer dir.deleteFile(io, scratch) catch {};
    const zip = try dir.openFile(io, scratch, .{});
    defer zip.close(io);
    var buf: [4096]u8 = undefined;
    var reader = zip.reader(io, &buf);
    var bodies: [members.len]?[]const u8 = @splat(null);
    var entries = try std.zip.Iterator.init(&reader);
    var name_buf: [256]u8 = undefined;
    while (try entries.next()) |entry| {
        const name = try entry.getFilename(&reader, &name_buf, .{});
        for (members, &bodies) |member, *body| {
            const prefix = "sqlite-amalgamation-" ++ version ++ "/";
            if (!std.mem.startsWith(u8, name, prefix) or
                !std.mem.eql(u8, name[prefix.len..], member)) continue;
            var out: Io.Writer.Allocating = .init(gpa);
            try entry.extractTo(&reader, &out.writer);
            if (std.hash.Crc32.hash(out.written()) != entry.crc32) return error.BadChecksum;
            body.* = out.written();
        }
    }
    for (bodies) |body| if (body == null) return error.MissingMember;
    if (std.mem.find(u8, bodies[0].?, "#define SQLITE_VERSION        \"3.54.1\"") == null)
        return error.UnexpectedVersion;
    // sqlite3.c, make's target, is renamed into place last.
    for (members, bodies) |member, body| {
        const temporary = try gpa.print("{s}.tmp", .{member});
        try dir.writeFile(io, .{ .sub_path = temporary, .data = body.? });
        try dir.rename(temporary, dir, member, io);
    }
    std.debug.print("checkout-unwound-sqlite: SQLite 3.54.1: verified {s} into {s}\n", .{
        pin[0..12], output,
    });
}

/// fetch downloads the archive, giving up after fetch_seconds or past
/// max_archive bytes.
fn fetch(io: Io, gpa: Allocator) ![]const u8 {
    const Event = union(enum) {
        fetched: anyerror![]const u8,
        timeout: Io.Cancelable!void,
    };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.fetched, download, .{ io, gpa });
    try events.concurrent(.timeout, sleep, .{io});
    return switch (try events.await()) {
        .fetched => |result| result,
        .timeout => |result| {
            try result;
            return error.FetchTimeout;
        },
    };
}

fn sleep(io: Io) Io.Cancelable!void {
    try io.sleep(.fromSeconds(fetch_seconds), .awake);
}

fn download(io: Io, gpa: Allocator) anyerror![]const u8 {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    // A byte past the limit tells a long archive from one that fits.
    const buf = try gpa.alloc(u8, max_archive + 1);
    var body: Io.Writer = .fixed(buf);
    const response = client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &body,
    }) catch |err| return if (body.end == buf.len) error.TooLarge else err;
    if (response.status != .ok) return error.HttpStatus;
    if (body.end > max_archive) return error.TooLarge;
    return buf[0..body.end];
}
