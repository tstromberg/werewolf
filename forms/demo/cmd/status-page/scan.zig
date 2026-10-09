//! scan runs grype over the image as the grype user, hourly, and keeps a
//! summary for the page. See README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const main = @import("status-page.zig");
const Package = main.Package;
const exists = main.exists;
const grype_dir = main.grype_dir;
const keepScan = main.keepScan;
const meta_dir = main.meta_dir;
const mountType = main.mountType;
const nowSecs = main.nowSecs;
const readAll = main.readAll;
const readOr = main.readOr;
const record = main.record;
const rfc3339 = main.rfc3339;
const scan_error_path = main.scan_error_path;
const summary_path = main.summary_path;
const writeAtomic = main.writeAtomic;

const grype_bin = "/usr/bin/grype";
const grype_out = grype_dir ++ "/grype.json";
const scan_every = 3600;

/// grype_seconds bounds a whole grype run. The database download and the
/// scan normally take minutes.
const grype_seconds = 30 * 60;

/// max_grype_said caps what is kept of grype's stdout and stderr.
const max_grype_said = 1 << 20;

/// grype_args exclude the kernel's trees, RAM-backed directories, and
/// /data, which holds grype's database and is not part of the image.
const grype_args = [_][]const u8{
    grype_bin,     "dir:/",
    "--output",    "json",
    "--file",      grype_out,
    "--quiet",     "--exclude",
    "./proc/**",   "--exclude",
    "./sys/**",    "--exclude",
    "./dev/**",    "--exclude",
    "./run/**",    "--exclude",
    "./tmp/**",    "--exclude",
    "./data/**",   "--exclude",
    "./victim/**",
};

/// scanLoop is the scan service: it scans at start and then hourly, and
/// writes the error to scan_error_path when a scan fails.
pub fn scanLoop(io: Io) !void {
    record(io, .{ .event = "start" });

    while (true) {
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        var step: []const u8 = "start";
        scan(io, arena.allocator(), &step) catch |err| {
            record(
                io,
                .{ .event = "error", .step = "scan", .at = step, .@"error" = @errorName(err) },
            );
            var time: [32]u8 = undefined;
            const msg = arena.allocator().print(
                "{s}, while {s}, at {s}\n",
                .{ @errorName(err), step, rfc3339(&time, nowSecs(io)) },
            ) catch "";
            writeAtomic(io, arena.allocator(), scan_error_path, msg) catch {};
        };
        arena.deinit();
        io.sleep(.fromSeconds(scan_every), .awake) catch return;
    }
}

/// scan runs grype once. It sets step to what it is doing, for the error
/// if it fails.
fn scan(io: Io, gpa: Allocator, step: *[]const u8) !void {
    step.* = "checking /data";
    if (exists(io, "/run/werewolf/nodata")) return error.DataUnavailable;
    const kind = mountType(
        readOr(io, gpa, "/proc/self/mounts", ""),
        "/data",
    ) orelse return error.DataNotMounted;
    // grype's database is a 190 MB download that unpacks to several times
    // that, too big for RAM.
    if (std.mem.eql(u8, kind, "tmpfs")) return error.DataInRam;
    if (!exists(io, grype_bin)) return error.NoGrype;

    step.* = "preparing grype's directories";
    Dir.cwd().deleteTree(io, grype_dir ++ "/tmp") catch {};
    for ([_][]const u8{
        grype_dir ++ "/db",
        grype_dir ++ "/tmp",
    }) |path| try Dir.cwd().createDirPath(io, path);
    Dir.cwd().deleteFile(io, grype_out) catch {};

    var env: std.process.Environ.Map = .init(gpa);
    try env.put("PATH", "/usr/bin:/bin");
    try env.put("HOME", grype_dir);
    try env.put("TMPDIR", grype_dir ++ "/tmp");
    try env.put("XDG_CACHE_HOME", grype_dir);
    try env.put("XDG_CONFIG_HOME", grype_dir);
    try env.put("GRYPE_DB_CACHE_DIR", grype_dir ++ "/db");
    try env.put("GRYPE_CHECK_FOR_APP_UPDATE", "false");

    step.* = "running grype";
    record(io, .{ .event = "scan", .result = "started" });
    // Bound the run: grype fetches its database, and a fetch that hangs
    // would block every later scan.
    const run = std.process.run(gpa, io, .{
        .argv = &grype_args,
        .environ_map = &env,
        .stdout_limit = .limited(max_grype_said),
        .stderr_limit = .limited(max_grype_said),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(grype_seconds), .clock = .awake } },
    }) catch |err| return if (err == error.Timeout) error.GrypeTimedOut else err;
    relay(io, run.stderr);
    switch (run.term) {
        .exited => |code| if (code != 0) return error.GrypeFailed,
        else => return error.GrypeKilled,
    }

    step.* = "reading grype's findings";
    const text = try readAll(io, gpa, grype_out);
    const owners = try parseOwners(
        gpa,
        readOr(io, gpa, "/lib/apk/db/installed", ""),
        readOr(io, gpa, meta_dir ++ "/overlay", ""),
    );
    var time: [32]u8 = undefined;
    const summary = try summarize(gpa, text, rfc3339(&time, nowSecs(io)), owners);
    var out: Io.Writer.Allocating = .init(gpa);
    try std.json.Stringify.value(summary, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeByte('\n');
    try writeAtomic(io, gpa, summary_path, out.written());
    keepScan(io, gpa, out.written());
    Dir.cwd().deleteFile(io, scan_error_path) catch {};
    Dir.cwd().deleteFile(io, grype_out) catch {};
    record(io, .{
        .event = "scan",
        .result = "done",
        .findings = summary.findings.len,
        .critical = summary.counts.critical,
        .high = summary.counts.high,
        .db_built = summary.db_built,
    });
}

/// relay copies grype's stderr to the console a line at a time, with each
/// control character but tab shown as "?". grype reads a database from the
/// network, and its output must not drive the terminal.
fn relay(io: Io, said: []const u8) void {
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, said, "\n"), '\n');
    while (lines.next()) |whole| {
        if (whole.len == 0) continue;
        // Split a line longer than the buffer.
        var rest = whole;
        while (rest.len > 0) {
            const line = rest[0..@min(rest.len, 4096)];
            rest = rest[line.len..];
            var out: [4097]u8 = undefined;
            for (line, out[0..line.len]) |c, *o|
                o.* = if ((c < 0x20 and c != '\t') or c == 0x7f) '?' else c;
            out[line.len] = '\n';
            Io.File.stderr().writeStreamingAll(io, out[0 .. line.len + 1]) catch {};
        }
    }
}

/// Summary is what the page keeps of a grype run.
pub const Summary = struct {
    time: []const u8,
    grype: []const u8,
    db_built: []const u8,
    counts: Counts,
    findings: []const Finding,
};

pub const Counts = struct {
    critical: usize = 0,
    high: usize = 0,
    medium: usize = 0,
    low: usize = 0,
    negligible: usize = 0,
    unknown: usize = 0,
};

const Finding = struct {
    severity: []const u8,
    id: []const u8,
    /// package, version and kind describe the component grype matched.
    package: []const u8,
    version: []const u8,
    kind: []const u8,
    fixed_in: []const u8,
    /// in_package and in_version name the image's package that holds the
    /// component: grype for a Go module inside /usr/bin/grype, werewolf_owner
    /// for werewolf's programs, or empty when no package claims the file.
    in_package: []const u8 = "",
    in_version: []const u8 = "",
};

pub const werewolf_owner = "(werewolf)";

/// Owners maps each file to the apk package that installed it, and lists
/// werewolf's own files from the build record.
const Owners = struct {
    files: std.StringHashMapUnmanaged(Package) = .empty,
    werewolf: std.StringHashMapUnmanaged(void) = .empty,

    /// of returns the package that owns path, as grype reports it
    /// (/usr/bin/grype). /bin, /sbin and /lib link into /usr, so it also
    /// looks the path up under /usr.
    fn of(o: Owners, path: []const u8) ?Package {
        const rel = std.mem.trimStart(u8, path, "/");
        if (o.files.get(rel)) |p| return p;
        var buf: [1024]u8 = undefined;
        const usr = std.mem.print(&buf, "usr/{s}", .{rel}) catch return null;
        if (o.files.get(usr)) |p| return p;
        if (o.werewolf.contains(rel) or
            o.werewolf.contains(usr)) return .{
            .name = werewolf_owner,
            .version = "",
            .origin = "",
        };
        return null;
    }
};

/// parseOwners reads the files of an apk installed database (F: is a
/// directory, R: a file in it, after their package's P: and V:) and the
/// build record's list of werewolf's files, one path per line.
fn parseOwners(gpa: Allocator, installed: []const u8, overlay: []const u8) !Owners {
    var o: Owners = .{};
    var pkg: Package = .{ .name = "", .version = "", .origin = "" };
    var dir: []const u8 = "";
    var it = std.mem.splitScalar(u8, installed, '\n');
    while (it.next()) |line| {
        if (line.len == 0) {
            pkg = .{ .name = "", .version = "", .origin = "" };
        } else if (std.mem.startsWith(u8, line, "P:")) {
            pkg.name = line[2..];
        } else if (std.mem.startsWith(u8, line, "V:")) {
            pkg.version = line[2..];
        } else if (std.mem.startsWith(u8, line, "F:")) {
            dir = line[2..];
        } else if (std.mem.startsWith(u8, line, "R:") and pkg.name.len > 0) {
            try o.files.put(gpa, try gpa.print("{s}/{s}", .{ dir, line[2..] }), pkg);
        }
    }
    var lines = std.mem.tokenizeScalar(u8, overlay, '\n');
    while (lines.next()) |l| try o.werewolf.put(gpa, l, {});
    return o;
}

/// GrypeOutput holds the parts of grype's JSON the page uses.
const GrypeOutput = struct {
    matches: []const Match = &.{},
    descriptor: struct { version: []const u8 = "", db: ?std.json.Value = null } = .{},

    const Match = struct {
        vulnerability: struct {
            id: []const u8,
            severity: []const u8 = "Unknown",
            fix: struct { versions: []const []const u8 = &.{} } = .{},
        },
        artifact: struct {
            name: []const u8,
            version: []const u8 = "",
            type: []const u8 = "",
            locations: []const struct { path: []const u8 = "" } = &.{},
        },
    };
};

/// summarize returns grype's findings, one per vulnerability and component,
/// worst first, each with the image package that holds it.
fn summarize(gpa: Allocator, text: []const u8, time: []const u8, owners: Owners) !Summary {
    const g = try std.json.parseFromSliceLeaky(
        GrypeOutput,
        gpa,
        text,
        .{ .ignore_unknown_fields = true },
    );
    var findings: std.ArrayList(Finding) = .empty;
    var counts: Counts = .{};
    outer: for (g.matches) |m| {
        var f: Finding = .{
            .severity = severities[rank(m.vulnerability.severity)],
            .id = m.vulnerability.id,
            .package = m.artifact.name,
            .version = m.artifact.version,
            .kind = m.artifact.type,
            .fixed_in = try std.mem.join(gpa, ", ", m.vulnerability.fix.versions),
        };
        // An apk package is its own owner. Anything else belongs to the
        // package whose file grype found it in.
        if (std.mem.eql(u8, f.kind, "apk")) {
            f.in_package = f.package;
            f.in_version = f.version;
        } else for (m.artifact.locations) |l| {
            const p = owners.of(l.path) orelse continue;
            f.in_package = p.name;
            f.in_version = p.version;
            break;
        }
        // grype matches one vulnerability several ways (by CPE, by package
        // name, in two locations). List it once.
        for (findings.items) |x| {
            if (std.mem.eql(u8, x.id, f.id) and std.mem.eql(u8, x.package, f.package) and
                std.mem.eql(u8, x.version, f.version) and
                std.mem.eql(u8, x.in_package, f.in_package)) continue :outer;
        }
        try findings.append(gpa, f);
        switch (rank(f.severity)) {
            0 => counts.critical += 1,
            1 => counts.high += 1,
            2 => counts.medium += 1,
            3 => counts.low += 1,
            4 => counts.negligible += 1,
            else => counts.unknown += 1,
        }
    }
    std.mem.sort(Finding, findings.items, {}, worseFirst);
    const db_built = if (g.descriptor.db) |db| findString(db, "built") orelse "" else "";
    return .{
        .time = time,
        .grype = g.descriptor.version,
        .db_built = db_built,
        .counts = counts,
        .findings = findings.items,
    };
}

pub const severities = [_][]const u8{
    "Critical",
    "High",
    "Medium",
    "Low",
    "Negligible",
    "Unknown",
};

pub fn rank(severity: []const u8) usize {
    for (severities, 0..) |s, i| if (std.ascii.eqlIgnoreCase(s, severity)) return i;
    return severities.len - 1;
}

fn worseFirst(_: void, a: Finding, b: Finding) bool {
    const ra = rank(a.severity);
    const rb = rank(b.severity);
    if (ra != rb) return ra < rb;
    const by_owner = std.mem.order(u8, a.in_package, b.in_package);
    if (by_owner != .eq) return by_owner == .lt;
    const by_package = std.mem.order(u8, a.package, b.package);
    if (by_package != .eq) return by_package == .lt;
    return std.mem.lessThan(u8, a.id, b.id);
}

/// findString returns the first string under key anywhere in v. grype has
/// moved the database's build time between schema versions.
fn findString(v: std.json.Value, key: []const u8) ?[]const u8 {
    switch (v) {
        .object => |o| {
            if (o.get(key)) |x| if (x == .string) return x.string;
            var it = o.iterator();
            while (it.next()) |e| if (findString(e.value_ptr.*, key)) |s| return s;
        },
        else => {},
    }
    return null;
}

test summarize {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{"matches":[
        \\ {"vulnerability":{"id":"CVE-2026-2","severity":"Medium","fix":{"versions":["1.2"],"state":"fixed"}},
        \\  "artifact":{"name":"zlib","version":"1.1","type":"apk","locations":[{"path":"/usr/lib/apk/db/installed"}]},"matchDetails":[]},
        \\ {"vulnerability":{"id":"GHSA-x","severity":"Critical","fix":{"versions":[],"state":"not-fixed"}},
        \\  "artifact":{"name":"stdlib","version":"go1.25","type":"go-module","locations":[{"path":"/usr/bin/grype","layerID":"x"}]}},
        \\ {"vulnerability":{"id":"CVE-2026-2","severity":"Medium","fix":{"versions":["1.2"]}},
        \\  "artifact":{"name":"zlib","version":"1.1","type":"apk"}},
        \\ {"vulnerability":{"id":"CVE-2026-4","severity":"Low"},"artifact":{"name":"zig","version":"0.17","type":"binary","locations":[{"path":"/usr/lib/werewolf/status-page"}]}},
        \\ {"vulnerability":{"id":"CVE-2026-3","severity":"weird"},"artifact":{"name":"a","version":"1","locations":[{"path":"/opt/x"}]}}
        \\],
        \\"descriptor":{"name":"grype","version":"0.120.0","db":{"status":{"built":"2026-10-06T06:32:14Z","schemaVersion":"v6.1.10"}}}}
    ;
    const owners = try parseOwners(
        a,
        "P:grype\nV:0.120.0-r0\nF:usr/bin\nR:grype\n\nP:zlib\nV:1.1\nF:usr/lib\nR:libz.so.1\n",
        "usr/lib/werewolf/status-page\n",
    );
    const s = try summarize(a, json, "2026-10-06T12:00:00Z", owners);
    try testing.expectEqual(4, s.findings.len);
    try testing.expectEqualStrings("GHSA-x", s.findings[0].id);
    try testing.expectEqualStrings("grype", s.findings[0].in_package);
    try testing.expectEqualStrings("0.120.0-r0", s.findings[0].in_version);
    try testing.expectEqualStrings("CVE-2026-2", s.findings[1].id);
    try testing.expectEqualStrings("zlib", s.findings[1].in_package);
    try testing.expectEqualStrings("1.2", s.findings[1].fixed_in);
    try testing.expectEqualStrings(werewolf_owner, s.findings[2].in_package);
    try testing.expectEqualStrings("Unknown", s.findings[3].severity);
    try testing.expectEqualStrings("", s.findings[3].in_package);
    try testing.expectEqual(1, s.counts.critical);
    try testing.expectEqual(1, s.counts.medium);
    try testing.expectEqual(1, s.counts.unknown);
    try testing.expectEqualStrings("0.120.0", s.grype);
    try testing.expectEqualStrings("2026-10-06T06:32:14Z", s.db_built);
    // /bin is a link into /usr.
    try testing.expectEqualStrings("grype", owners.of("/bin/grype").?.name);
    try testing.expectEqual(null, owners.of("/etc/passwd"));
}
