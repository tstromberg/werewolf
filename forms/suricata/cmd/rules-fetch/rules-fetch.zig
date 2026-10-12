//! rules-fetch keeps Suricata's rules on the data partition.
//!
//!     rules-fetch        refresh the cache, as _rules
//!     rules-fetch wait   wait until that cache is in place
//!
//! The cache is _rules' directory, mode 0711, files mode 0644. Suricata
//! reads it and its pledge has no network, so a running engine cannot
//! fetch or replace the rules. Emerging Threats Open is refreshed when
//! the cached tarball is a day old. The engine's own protocol rules and
//! the marker are copied from the image on every pass, so a refresh
//! still loads them when the feed is unreachable. See
//! forms/suricata/cmd/rules-fetch/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const feed_url = "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz";
const rules_dir = "/data/svc/rules-fetch/rules";
const cache_dir = "/data/svc/rules-fetch/cache";
const image_rules = "/usr/share/suricata/rules";
const image_class = "/usr/share/suricata/classification.config";
const emerging = rules_dir ++ "/emerging.rules";
const class_path = rules_dir ++ "/classification.config";
const cache_gz = cache_dir ++ "/emerging.rules.tar.gz";
const cache_class = cache_dir ++ "/classification.config";
const ready = "/data/svc/rules-fetch/ready";
const et_ready = "/data/svc/rules-fetch/et-ready";
const stub =
    \\# rules-fetch: Emerging Threats Open is not in the cache yet.
    \\
;
/// A day. The tarball changes in place, so a pinned checksum would
/// refuse the refresh this program exists to do.
const fresh_ns: i128 = 24 * 60 * 60 * std.time.ns_per_s;
const max_gz = 32 << 20;
const max_rules: usize = 80 << 20;
const max_class = 1 << 20;
const max_one = 4 << 20;
const wait_seconds = 25;
const retry_seconds = 60;

const Kind = enum { rules, class };

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch std.process.exit(1);
    if (args.len == 2 and std.mem.eql(u8, args[1], "wait")) {
        wait(io);
        return;
    }
    if (args.len != 1) {
        say(io, "usage: rules-fetch [wait]", .{});
        std.process.exit(1);
    }
    // One arena per pass. The feed is several megabytes and the process
    // runs for the life of the machine.
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    while (true) {
        defer _ = arena.reset(.retain_capacity);
        const pass = arena.allocator();
        if (refresh(io, pass)) |_| {} else |err| {
            say(io, "refresh: {s}", .{@errorName(err)});
        }
        const pause: i64 = if (etReady(io)) 24 * 60 * 60 else retry_seconds;
        io.sleep(.fromSeconds(pause), .awake) catch {};
    }
}

/// wait returns once Emerging Threats is in the cache, or after
/// wait_seconds if only the image's rules are.
fn wait(io: Io) void {
    var left: usize = wait_seconds;
    while (left > 0) : (left -= 1) {
        if (etReady(io)) return;
        io.sleep(.fromSeconds(1), .awake) catch {};
    }
}

fn etReady(io: Io) bool {
    return if (Dir.cwd().access(io, et_ready, .{})) |_| true else |_| false;
}

/// refresh copies the image's rules, then the feed when the cache is
/// old or missing. ready is written before the download, so the engine
/// can start on the image's rules while the feed is fetched.
fn refresh(io: Io, gpa: Allocator) !void {
    _ = linux.syscall1(.umask, 0o022);
    try mkdir(io, cache_dir);
    try mkdir(io, rules_dir);
    try copyImageRules(io, gpa);
    if (!exists(io, emerging)) try writeFile(io, emerging, stub);
    const extra = Dir.cwd().readFileAlloc(io, cache_class, gpa, .limited(max_class)) catch |err| switch (err) {
        error.FileNotFound => "",
        else => return err,
    };
    try writeClass(io, gpa, extra);
    try writeFile(io, ready, "ok\n");

    const gz = cached(io) catch null;
    if (gz) |age| if (!due(age.now, age.then) and exists(io, et_ready)) {
        say(io, "cache is current", .{});
        return;
    };
    const body = fetch(io, gpa) catch |err| {
        say(io, "feed not fetched: {s}", .{@errorName(err)});
        return;
    };
    const class = try unpack(gpa, body, io);
    try writeFile(io, cache_gz, body);
    try writeFile(io, cache_class, class);
    try writeClass(io, gpa, class);
    try writeFile(io, et_ready, "ok\n");
    say(io, "cached Emerging Threats Open ({d} bytes)", .{body.len});
}

const Age = struct { now: i128, then: i128 };

fn cached(io: Io) !Age {
    const st = try Dir.cwd().statFile(io, cache_gz, .{});
    return .{ .now = Io.Clock.real.now(io).nanoseconds, .then = st.mtime.nanoseconds };
}

/// due reports that a cache from then should be fetched again at now.
fn due(now: i128, then: i128) bool {
    return now < then or now - then >= fresh_ns;
}

fn fetch(io: Io, gpa: Allocator) ![]u8 {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    const now = Io.Clock.real.now(io);
    try client.ca_bundle.rescan(gpa, io, now);
    client.now = now;
    var body: Io.Writer.Allocating = .init(gpa);
    const res = try client.fetch(.{
        .location = .{ .url = feed_url },
        .response_writer = &body.writer,
    });
    if (res.status != .ok) return error.HttpStatus;
    const gz = body.written();
    if (gz.len > max_gz) return error.TooBig;
    return gpa.dupe(u8, gz);
}

/// unpack writes rules/*.rules from the gzip tar to emerging.rules and
/// returns the feed's classification.config. A link, an absolute name
/// or a `..` component rejects the whole archive.
fn unpack(gpa: Allocator, gz: []const u8, io: Io) ![]u8 {
    var in: Io.Reader = .fixed(gz);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var dec: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var out = try Dir.cwd().createFile(io, emerging ++ ".part", .{
        .truncate = true,
        .permissions = .fromMode(0o644),
    });
    defer out.close(io);
    var buf: [64 << 10]u8 = undefined;
    var w = out.writerStreaming(io, &buf);
    try w.interface.writeAll("# rules-fetch: Emerging Threats Open\n");
    const class = try expand(gpa, &dec.reader, &w.interface);
    try w.interface.flush();
    try Dir.rename(Dir.cwd(), emerging ++ ".part", Dir.cwd(), emerging, io);
    return class;
}

fn expand(gpa: Allocator, reader: *Io.Reader, rules: *Io.Writer) ![]u8 {
    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(reader, .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
    });
    var class: Io.Writer.Allocating = .init(gpa);
    var total: usize = 0;
    var discard: Io.Writer.Discarding = .init(&.{});
    while (try it.next()) |file| {
        const which = try wanted(file.name);
        if (which == null or file.kind == .directory) {
            try it.streamRemaining(file, &discard.writer);
            continue;
        }
        if (file.kind != .file) return error.BadName;
        if (file.size > max_one) return error.TooBig;
        switch (which.?) {
            .rules => {
                total += @intCast(file.size);
                if (total > max_rules) return error.TooBig;
                try it.streamRemaining(file, rules);
                try rules.writeByte('\n');
            },
            .class => {
                if (file.size > max_class) return error.TooBig;
                if (class.written().len != 0) {
                    try it.streamRemaining(file, &discard.writer);
                } else {
                    try it.streamRemaining(file, &class.writer);
                }
            },
        }
    }
    if (class.written().len == 0) return error.NoClassification;
    return gpa.dupe(u8, class.written());
}

/// wanted classifies one tar name. null is a file the feed ships and
/// the engine does not load. BadName is a name that could leave rules/.
fn wanted(name: []const u8) !?Kind {
    if (name.len == 0 or name[0] == '/' or std.mem.indexOfScalar(u8, name, '\\') != null)
        return error.BadName;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return error.BadName;
    }
    const dir = std.fs.path.dirname(name) orelse return null;
    if (!std.mem.eql(u8, dir, "rules")) return null;
    const base = std.fs.path.basename(name);
    if (std.mem.eql(u8, base, "classification.config")) return .class;
    if (std.mem.endsWith(u8, base, ".rules")) return .rules;
    return null;
}

fn copyImageRules(io: Io, gpa: Allocator) !void {
    var dir = try Dir.cwd().openDir(io, image_rules, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file) continue;
        if (!std.mem.endsWith(u8, e.name, ".rules")) continue;
        if (std.mem.eql(u8, e.name, "emerging.rules")) continue;
        if (std.mem.indexOfScalar(u8, e.name, '/') != null) return error.BadName;
        const src = try gpa.print(image_rules ++ "/{s}", .{e.name});
        const data = try Dir.cwd().readFileAlloc(io, src, gpa, .limited(max_one));
        const dest = try gpa.print(rules_dir ++ "/{s}", .{e.name});
        try writeFile(io, dest, data);
    }
}

fn writeClass(io: Io, gpa: Allocator, extra: []const u8) !void {
    const image = try Dir.cwd().readFileAlloc(io, image_class, gpa, .limited(max_class));
    const merged = try mergeClass(gpa, image, extra);
    try writeFile(io, class_path, merged);
}

/// mergeClass returns the image's classifications followed by feed lines
/// whose short name the image does not already define.
fn mergeClass(gpa: Allocator, image: []const u8, extra: []const u8) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    try out.writer.writeAll(image);
    if (image.len > 0 and image[image.len - 1] != '\n') try out.writer.writeByte('\n');
    var lines = std.mem.splitScalar(u8, extra, '\n');
    while (lines.next()) |line| {
        const name = shortName(line) orelse continue;
        if (defines(image, name)) continue;
        try out.writer.writeAll(line);
        try out.writer.writeByte('\n');
    }
    return gpa.dupe(u8, out.written());
}

fn shortName(line: []const u8) ?[]const u8 {
    const prefix = "config classification:";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const rest = std.mem.trim(u8, line[prefix.len..], " \t");
    const comma = std.mem.indexOfScalar(u8, rest, ',') orelse return null;
    if (comma == 0) return null;
    return rest[0..comma];
}

fn defines(image: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, image, '\n');
    while (lines.next()) |line| {
        const have = shortName(line) orelse continue;
        if (std.mem.eql(u8, have, name)) return true;
    }
    return false;
}

fn mkdir(io: Io, path: []const u8) !void {
    Dir.cwd().createDirPath(io, path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

fn exists(io: Io, path: []const u8) bool {
    return if (Dir.cwd().access(io, path, .{})) |_| true else |_| false;
}

fn writeFile(io: Io, path: []const u8, data: []const u8) !void {
    var tmp_buf: [Dir.max_path_bytes]u8 = undefined;
    const tmp = std.mem.print(&tmp_buf, "{s}.part", .{path}) catch return error.NameTooLong;
    {
        var f = try Dir.cwd().createFile(io, tmp, .{
            .truncate = true,
            .permissions = .fromMode(0o644),
        });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
    }
    try Dir.rename(Dir.cwd(), tmp, Dir.cwd(), path, io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "rules-fetch: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "wanted keeps feed rules and rejects a name that leaves the directory" {
    try testing.expectEqual(.rules, (try wanted("rules/emerging-exploit.rules")).?);
    try testing.expectEqual(.class, (try wanted("rules/classification.config")).?);
    try testing.expectEqual(null, try wanted("rules/LICENSE"));
    try testing.expectEqual(null, try wanted("rules/a/b.rules"));
    try testing.expectError(error.BadName, wanted("rules/../x.rules"));
    try testing.expectError(error.BadName, wanted("/rules/a.rules"));
    try testing.expectError(error.BadName, wanted("rules//a.rules"));
}

test "due refreshes a cache a day old, and one from the future" {
    try testing.expect(!due(fresh_ns - 1, 0));
    try testing.expect(due(fresh_ns, 0));
    try testing.expect(due(0, 1));
}

test "mergeClass keeps the image's short name and adds the feed's" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const image = "config classification: misc-activity,Misc,3\n";
    const extra =
        \\config classification: misc-activity,Other,1
        \\config classification: et-only,ET,2
        \\not a classification
        \\
    ;
    const got = try mergeClass(gpa, image, extra);
    try testing.expectEqualStrings(
        image ++ "config classification: et-only,ET,2\n",
        got,
    );
}

test "expand concatenates rules and refuses a link" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tar: Io.Writer.Allocating = .init(gpa);
    var tw: std.tar.Writer = .{ .underlying_writer = &tar.writer };
    try tw.writeFileBytes("rules/a.rules", "alert a", .{});
    try tw.writeFileBytes("rules/classification.config", "config classification: et-only,ET,1\n", .{});
    try tw.writeFileBytes("rules/LICENSE", "no", .{});

    var rules: Io.Writer.Allocating = .init(gpa);
    var reader: Io.Reader = .fixed(tar.written());
    const class = try expand(gpa, &reader, &rules.writer);
    try testing.expectEqualStrings("alert a\n", rules.written());
    try testing.expectEqualStrings("config classification: et-only,ET,1\n", class);

    var bad: Io.Writer.Allocating = .init(gpa);
    var link: std.tar.Writer = .{ .underlying_writer = &bad.writer };
    try link.writeLink("rules/a.rules", "elsewhere", .{});
    var sink: Io.Writer.Allocating = .init(gpa);
    var bad_reader: Io.Reader = .fixed(bad.written());
    try testing.expectError(error.BadName, expand(gpa, &bad_reader, &sink.writer));
}
