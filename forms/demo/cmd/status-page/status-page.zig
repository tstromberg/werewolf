//! status-page: the demo form's one web page, about the machine it runs on, and
//! the grype scan the page reports. Two services run it, each leashed
//! (cmd/leash/leash.zig) as a user of its own:
//!
//!     status        as the status user: every minute it writes
//!                   /data/svc/status/www/index.html, which nginx serves:
//!                   the kernel and uptime, the last update check, the
//!                   last 25 patches autoupdate applied with the CVEs each
//!                   fixed, what grype finds in the image, and the
//!                   packages the image holds. It may reach nothing on
//!                   the network.
//!     status scan   as the grype user: once an hour, and at start, it runs
//!                   grype over the root, with its database in
//!                   /data/svc/scan, and keeps a summary there for the
//!                   page, so the page survives a reboot with its last
//!                   scan. grype is the one that fetches, so only this
//!                   user may (forms/demo/form.yaml).
//!
//! It never runs as root: leash has made its directories its user's and
//! given root up before it starts. grype's database comes from the
//! network, and package metadata and grype's findings are other people's
//! text; everything written into the page is HTML-escaped.
//!
//! Each pass allocates from its own arena, freed when the pass ends, so a
//! process that runs for months uses what one pass needs.

const std = @import("std");

const Io = std.Io;

const Dir = Io.Dir;

const Allocator = std.mem.Allocator;
const page = @import("page.zig");
const scan = @import("scan.zig");
const pg = @import("pg.zig");
const describeEvent = page.describeEvent;
const isAdvisoryId = page.isAdvisoryId;
const plural = page.plural;
const writePage = page.writePage;
const Pg = pg.Pg;
const dbWhy = pg.dbWhy;
const Summary = scan.Summary;
const scanLoop = scan.scanLoop;

const state_dir = "/data/svc/status";

const www_dir = state_dir ++ "/www";

const page_path = www_dir ++ "/index.html";

pub const grype_dir = "/data/svc/scan";

pub const summary_path = grype_dir ++ "/scan.json";

pub const scan_error_path = grype_dir ++ "/scan-error";

pub const grype_out = grype_dir ++ "/grype.json";

pub const grype_bin = "/usr/bin/grype";

const autoupdate_dir = "/data/svc/autoupdate";

pub const meta_dir = "/usr/share/werewolf";

const render_every = 60;

pub const scan_every = 3600;

const max_patches = 25;

const max_read = 256 << 20;

/// The most read of what the scan, as grype's user, leaves for the page:
/// a scan taken over cannot make the page hold more.
const max_summary = 4 << 20;

const max_scan_error = 4 << 10;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    if (std.os.linux.getuid() == 0) return error.RunMeUnderLeash;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2 and std.mem.eql(u8, args[1], "scan")) {
        return scanLoop(io);
    }
    if (args.len != 1) return error.Usage;
    Dir.cwd().createDirPath(
        io,
        www_dir,
    ) catch |err| record(io, .{ .event = "error", .step = "setup", .@"error" = @errorName(err) });
    record(io, .{ .event = "start" });
    timeBoot(io);

    var failing = false;
    while (true) {
        if (render(io)) |_| {
            if (failing) record(io, .{ .event = "page", .result = "written again" });
            failing = false;
        } else |err| {
            // Once per failure, not once a minute.
            if (!failing) record(
                io,
                .{ .event = "error", .step = "page", .@"error" = @errorName(err) },
            );
            failing = true;
        }
        try io.sleep(.fromSeconds(render_every), .awake);
    }
}

fn render(io: Io) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    try writePage(&out.writer, try gather(io, gpa));
    try writeAtomic(io, gpa, page_path, out.written());
}

/// Everything the page says, read from the machine. A part that cannot be
/// read is shown as missing rather than failing the page.
fn gather(io: Io, gpa: Allocator) !Facts {
    const now_secs = nowSecs(io);
    const uts = std.posix.uname();
    const uptime = parseUptime(readOr(io, gpa, "/proc/uptime", ""));
    const installed = try parseInstalled(gpa, readOr(io, gpa, "/lib/apk/db/installed", ""));

    var f: Facts = .{
        .now_secs = now_secs,
        .host = try gpa.dupe(u8, std.mem.sliceTo(&uts.nodename, 0)),
        .uname = try gpa.print("{s} {s} {s} {s} {s}", .{
            std.mem.sliceTo(&uts.sysname, 0), std.mem.sliceTo(&uts.nodename, 0),
            std.mem.sliceTo(&uts.release, 0), std.mem.sliceTo(&uts.version, 0),
            std.mem.sliceTo(&uts.machine, 0),
        }),
        .uptime = try formatUptime(gpa, uptime),
        .booted = now_secs -| uptime,
        .load = firstWords(readOr(io, gpa, "/proc/loadavg", ""), 3),
        .release = trimLine(readOr(io, gpa, meta_dir ++ "/release", "")),
        .slot = parseSlot(readOr(io, gpa, "/proc/cmdline", "")),
        .shell = exists(io, "/bin/sh"),
        .data = describeData(io, gpa),
        .packages = installed,
    };

    const log = readOr(io, gpa, autoupdate_dir ++ "/log", "");
    const events = try parseLog(gpa, log);
    f.last_check = lastCheck(events);
    f.patches = try patchHistory(gpa, try readReports(io, gpa), events, installed, max_patches);
    // From PostgreSQL where the form runs it; from the files otherwise.
    const kept = fromDatabase(io, gpa);
    f.database = kept.said;
    f.database_warn = kept.warn;
    f.boot = boot_said;
    f.posture = kept.posture orelse posture(io, gpa);
    f.scan = kept.scan;
    if (f.scan == null) if (readUpTo(io, gpa, summary_path, max_summary)) |text| {
        f.scan = std.json.parseFromSliceLeaky(
            Summary,
            gpa,
            text,
            .{ .ignore_unknown_fields = true },
        ) catch null;
    } else |_| {};
    if (readUpTo(io, gpa, scan_error_path, max_scan_error)) |text| {
        f.scan_error = trimLine(text);
    } else |_| {}
    return f;
}

/// The newest reports first, read only as far as the page needs: each
/// changes at least one package, so max_patches reports are enough.
fn readReports(io: Io, gpa: Allocator) ![]const Report {
    var d = Dir.cwd().openDir(
        io,
        autoupdate_dir ++ "/reports",
        .{ .iterate = true },
    ) catch return &.{};
    defer d.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (std.mem.endsWith(u8, e.name, ".json")) try names.append(gpa, try gpa.dupe(u8, e.name));
    }
    // Named TIME-BUILD.json, with RFC 3339 times: newest sorts last.
    std.mem.sort([]const u8, names.items, {}, moreString);
    var reports: std.ArrayList(Report) = .empty;
    for (names.items[0..@min(names.items.len, max_patches)]) |name| {
        const text = readAll(
            io,
            gpa,
            try gpa.print("{s}/reports/{s}", .{ autoupdate_dir, name }),
        ) catch continue;
        const r = std.json.parseFromSliceLeaky(
            Report,
            gpa,
            text,
            .{ .ignore_unknown_fields = true },
        ) catch continue;
        try reports.append(gpa, r);
    }
    return reports.items;
}

fn describeData(io: Io, gpa: Allocator) []const u8 {
    if (exists(io, "/run/werewolf/nodata")) return "unavailable (see the console)";
    const kind = mountType(
        readOr(io, gpa, "/proc/self/mounts", ""),
        "/data",
    ) orelse return "not mounted";
    if (std.mem.eql(u8, kind, "tmpfs")) return "RAM: nothing here outlives a reboot";
    return gpa.print("{s}, kept across reboots and updates", .{kind}) catch kind;
}

pub const Facts = struct {
    now_secs: u64,
    host: []const u8,
    uname: []const u8,
    uptime: []const u8,
    booted: u64,
    load: []const u8,
    release: []const u8,
    slot: []const u8,
    shell: bool,
    data: []const u8,
    /// What PostgreSQL keeps, or why the page reads files instead.
    database: []const u8 = "",
    /// Whether the database row needs a warning: no answer, or lost data.
    database_warn: bool = false,
    /// How long the boot took, when the page started.
    boot: []const u8 = "",
    packages: []const Package,
    last_check: ?Event = null,
    patches: []const Patch = &.{},
    scan: ?Summary = null,
    scan_error: ?[]const u8 = null,
    posture: ?Posture = null,
};

// /usr/lib/werewolf/posture (cmd/posture) checks how the machine protects
// itself. Its service runs it once per boot, when the other services have
// settled, and keeps the JSON in /run until the next boot.
const posture_path = "/run/werewolf/posture.json";

/// What posture prints; see posture.zig.
const Posture = struct {
    time: []const u8,
    summary: struct { pass: usize = 0, fail: usize = 0, skip: usize = 0 },
    checks: []const Check,
};

const Check = struct {
    id: []const u8 = "",
    area: []const u8 = "",
    name: []const u8,
    why: []const u8 = "",
    how: []const u8 = "",
    result: []const u8,
    detail: []const u8 = "",
};

/// This boot's posture, once the posture service has checked.
fn posture(io: Io, gpa: Allocator) ?Posture {
    const text = readAll(io, gpa, posture_path) catch return null;
    return std.json.parseFromSliceLeaky(
        Posture,
        gpa,
        text,
        .{ .ignore_unknown_fields = true },
    ) catch null;
}

// Where the form runs PostgreSQL (forms/postgresql), the scan keeps each
// summary there, and the page this boot's posture, and the page shows the
// newest of each from there. A small client of the server's own protocol
// (version 3), over its UNIX socket, as the service's own role, which peer
// authentication takes from its user: no password, no TCP, no libpq.
// Values go as parameters, never into the SQL. When the server is not
// there, or says no, the page reads the files in /data/svc as before.

pub const pg_socket = "/run/svc/postgres/.s.PGSQL.5432";

// The kernel's part and userland's (stage0 and init), which init leaves in
// /run/werewolf/boot, and when nginx and PostgreSQL first answered: nginx
// listening on :80, and PostgreSQL's socket taking a connection, as the page
// sees them, looking every 25 ms from its own start for up to 30 seconds.
// Each is time since the kernel started its clock.

/// The Boot row, worked out once, as the page starts.
var boot_said: []const u8 = "";

var boot_buf: [256]u8 = undefined;

fn timeBoot(io: Io) void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const Times = struct { kernel_ms: u64 = 0, userland_ms: u64 = 0 };
    const t = std.json.parseFromSliceLeaky(
        Times,
        gpa,
        readOr(io, gpa, "/run/werewolf/boot", "{}"),
        .{ .ignore_unknown_fields = true },
    ) catch Times{};
    const want_nginx = exists(io, "/etc/sv/nginx");
    const want_pg = exists(io, "/etc/sv/postgres");
    var nginx_ms: ?u64 = null;
    var pg_ms: ?u64 = null;
    var tries: u32 = 0;
    while (tries < 30_000 / 25) : (tries += 1) {
        _ = arena.reset(.retain_capacity);
        if (want_nginx and nginx_ms == null and
            listening(io, arena.allocator(), 80)) nginx_ms = bootMs();
        // Answering is a login that completes: the socket takes connections
        // while the server is still starting, and refuses them all.
        if (want_pg and pg_ms == null) if (Pg.connect(arena.allocator(), "status")) |db| {
            var d = db;
            d.close();
            pg_ms = bootMs();
        } else |_| {};
        if ((!want_nginx or nginx_ms != null) and (!want_pg or pg_ms != null)) break;
        io.sleep(.fromMilliseconds(25), .awake) catch break;
    }
    record(
        io,
        .{
            .event = "boot",
            .kernel_ms = t.kernel_ms,
            .userland_ms = t.userland_ms,
            .nginx_ms = nginx_ms,
            .postgresql_ms = pg_ms,
        },
    );
    var w: Io.Writer = .fixed(&boot_buf);
    w.print(
        "the kernel {d}.{d:0>2} s, userland {d}.{d:0>2} s",
        .{
            t.kernel_ms / 1000,
            t.kernel_ms % 1000 / 10,
            t.userland_ms / 1000,
            t.userland_ms % 1000 / 10,
        },
    ) catch return;
    if (want_nginx) if (nginx_ms) |ms|
        w.print("; nginx answering at {d}.{d:0>2} s", .{ ms / 1000, ms % 1000 / 10 }) catch return
    else
        w.writeAll("; nginx not answering after 30 s") catch return;
    if (want_pg) if (pg_ms) |ms|
        w.print("; PostgreSQL at {d}.{d:0>2} s", .{ ms / 1000, ms % 1000 / 10 }) catch return
    else
        w.writeAll("; PostgreSQL not answering after 30 s") catch return;
    boot_said = w.buffered();
}

/// Whether something listens on TCP port, by /proc/net/tcp and tcp6.
fn listening(io: Io, gpa: Allocator, port: u16) bool {
    return listensOn(readOr(io, gpa, "/proc/net/tcp", ""), port) or
        listensOn(readOr(io, gpa, "/proc/net/tcp6", ""), port);
}

/// Whether a /proc/net/tcp table has a socket listening (state 0A) on port.
fn listensOn(table: []const u8, port: u16) bool {
    var hex: [5]u8 = undefined;
    const want = std.mem.print(&hex, ":{X:0>4}", .{port}) catch return false;
    var lines = std.mem.tokenizeScalar(u8, table, '\n');
    _ = lines.next(); // the header
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        _ = f.next() orelse continue;
        const local = f.next() orelse continue;
        _ = f.next() orelse continue;
        const state = f.next() orelse continue;
        if (std.mem.endsWith(u8, local, want) and std.mem.eql(u8, state, "0A")) return true;
    }
    return false;
}

/// Milliseconds since the kernel started its clock.
fn bootMs() u64 {
    const linux = std.os.linux;
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

/// This boot's posture, once in the database, is not sent again.
var posture_kept = false;

/// Said on the console, with what the database holds, once it is kept.
var posture_just_kept = false;

/// Lost data is said on the console once, not once a minute.
var data_lost = false;

const Kept = struct {
    posture: ?Posture = null,
    scan: ?Summary = null,
    said: []const u8,
    warn: bool = false,
};

/// The most the database has held, as the page last saw it: a database
/// that holds less has lost what it was given.
const kept_path = state_dir ++ "/kept";

/// Whether the last pass could not use the database: a failure is said
/// on the console once, as it begins, not once a minute.
var db_failing = false;

fn fromDatabase(io: Io, gpa: Allocator) Kept {
    if (!exists(io, "/etc/sv/postgres")) return .{ .said = "none; the page reads its files" };
    if (!exists(
        io,
        pg_socket,
    )) return .{ .said = "PostgreSQL is not answering; the page reads its files", .warn = true };
    const kept = readDatabase(io, gpa) catch |err| {
        if (!db_failing) record(
            io,
            .{
                .event = "error",
                .step = "database",
                .@"error" = @errorName(err),
                .why = dbWhy(err),
            },
        );
        db_failing = true;
        return .{ .said = whyNot(gpa, err), .warn = true };
    };
    db_failing = false;
    return kept;
}

fn readDatabase(io: Io, gpa: Allocator) !Kept {
    var db = try Pg.connect(gpa, "status");
    defer db.close();
    if (!posture_kept) if (readAll(io, gpa, posture_path)) |text| {
        const boot = trimLine(readOr(io, gpa, "/proc/sys/kernel/random/boot_id", ""));
        _ = try db.query(
            gpa,
            "INSERT INTO status.posture (boot, report) VALUES ($1, $2::jsonb) " ++
                "ON CONFLICT (boot) DO NOTHING",
            &.{ boot, text },
        );
        posture_kept = true;
        posture_just_kept = true;
    } else |_| {};
    const rows = try db.query(gpa,
        \\SELECT current_setting('server_version'),
        \\       (SELECT report::text FROM status.posture ORDER BY at DESC LIMIT 1),
        \\       (SELECT summary::text FROM status.scans ORDER BY at DESC LIMIT 1),
        \\       (SELECT count(*) FROM status.posture)::text,
        \\       (SELECT count(*) FROM status.scans)::text
    , &.{});
    if (rows.len != 1 or rows[0].len != 5) return error.UnexpectedAnswer;
    const r = rows[0];
    const opts: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const boots = r[3] orelse "0";
    const scans = r[4] orelse "0";
    const nb = std.fmt.parseInt(u64, boots, 10) catch 0;
    const ns = std.fmt.parseInt(u64, scans, 10) catch 0;
    if (posture_just_kept) {
        posture_just_kept = false;
        record(io, .{ .event = "database", .kept = "posture", .boots = nb, .scans = ns });
    }
    // What the page saw before, against what is there now.
    var before = std.mem.tokenizeAny(u8, readOr(io, gpa, kept_path, ""), " \n");
    const had_boots = std.fmt.parseInt(u64, before.next() orelse "0", 10) catch 0;
    const had_scans = std.fmt.parseInt(u64, before.next() orelse "0", 10) catch 0;
    if (nb < had_boots or ns < had_scans) {
        if (!data_lost) record(
            io,
            .{
                .event = "error",
                .step = "database",
                .@"error" = "DataLost",
                .boots = nb,
                .scans = ns,
                .had_boots = had_boots,
                .had_scans = had_scans,
            },
        );
        data_lost = true;
        return .{ .said = try gpa.print("PostgreSQL has lost data: it held the checks of {d} " ++
            "boots and {d} scans, " ++
            "and now holds {d} and {d}", .{ had_boots, had_scans, nb, ns }), .warn = true };
    }
    if (nb != had_boots or
        ns != had_scans) writeAtomic(
        io,
        gpa,
        kept_path,
        try gpa.print("{d} {d}\n", .{ nb, ns }),
    ) catch {};
    return .{
        .posture = if (r[1]) |t|
            std.json.parseFromSliceLeaky(Posture, gpa, t, opts) catch null
        else
            null,
        .scan = if (r[2]) |t|
            std.json.parseFromSliceLeaky(Summary, gpa, t, opts) catch null
        else
            null,
        .said = try gpa.print("PostgreSQL {s}: the checks of {s} boot{s} and {s} scan{s} kept, " ++
            "the newest shown here", .{
            r[0] orelse "?",
            boots,
            plural(std.fmt.parseInt(usize, boots, 10) catch 0),
            scans,
            plural(std.fmt.parseInt(usize, scans, 10) catch 0),
        }),
    };
}

fn whyNot(gpa: Allocator, err: anyerror) []const u8 {
    return gpa.print(
        "unreachable ({s}); the page reads its files",
        .{@errorName(err)},
    ) catch "unreachable";
}

/// The scan's summary into the database, where there is one. The file is
/// written either way, so a failure here is said and nothing more.
pub fn keepScan(io: Io, gpa: Allocator, summary: []const u8) void {
    if (!exists(io, pg_socket)) return;
    var db = Pg.connect(
        gpa,
        "grype",
    ) catch |err| return record(
        io,
        .{ .event = "error", .step = "database", .@"error" = @errorName(err) },
    );
    defer db.close();
    _ = db.query(
        gpa,
        "INSERT INTO status.scans (summary) VALUES ($1::jsonb)",
        &.{summary},
    ) catch |err| return record(
        io,
        .{ .event = "error", .step = "database", .@"error" = @errorName(err), .why = dbWhy(err) },
    );
    record(io, .{ .event = "database", .kept = "scan" });
}

/// The parts of an update report (docs/updater.md) the page uses.
const Report = struct {
    time: []const u8,
    build: []const u8 = "",
    from: struct { kernel: []const u8 = "" } = .{},
    to: struct { kernel: []const u8 = "" } = .{},
    packages: []const Change = &.{},
    package_cves: []const OriginFix = &.{},
    kernel_cves: struct { cves: []const struct { id: []const u8 } = &.{} } = .{},
};

const Change = struct { name: []const u8, from: ?[]const u8 = null, to: ?[]const u8 = null };

const OriginFix = struct { origin: []const u8, cves: []const []const u8 = &.{} };

/// One package changing version in an update.
const Patch = struct {
    time: []const u8,
    name: []const u8,
    from: ?[]const u8,
    to: ?[]const u8,
    cves: []const []const u8,
    outcome: []const u8,
};

/// The newest `limit` patches in reports, newest first. Within an update,
/// the kernel comes first, then packages that fixed CVEs, then the rest.
fn patchHistory(
    gpa: Allocator,
    reports: []const Report,
    events: []const Event,
    installed: []const Package,
    limit: usize,
) ![]const Patch {
    var out: std.ArrayList(Patch) = .empty;
    for (reports, 0..) |r, i| {
        if (out.items.len >= limit) break;
        const outcome = outcomeOf(events, r.build, i == 0);
        var batch: std.ArrayList(Patch) = .empty;
        if (r.from.kernel.len > 0 and !std.mem.eql(u8, r.from.kernel, r.to.kernel)) {
            var ids: std.ArrayList([]const u8) = .empty;
            for (r.kernel_cves.cves) |c| try ids.append(gpa, c.id);
            try out.append(gpa, .{
                .time = r.time,
                .name = "linux-virt",
                .from = kernelVersion(r.from.kernel),
                .to = kernelVersion(r.to.kernel),
                .cves = ids.items,
                .outcome = outcome,
            });
        }
        for (r.packages) |c| {
            const origin = originOf(installed, c.name);
            var cves: []const []const u8 = &.{};
            for (r.package_cves) |fix| {
                if (std.mem.eql(u8, fix.origin, origin) or
                    isSubpackage(c.name, fix.origin)) cves = fix.cves;
            }
            try batch.append(
                gpa,
                .{
                    .time = r.time,
                    .name = c.name,
                    .from = c.from,
                    .to = c.to,
                    .cves = cves,
                    .outcome = outcome,
                },
            );
        }
        std.mem.sort(Patch, batch.items, {}, cvesFirst);
        try out.appendSlice(gpa, batch.items);
    }
    return out.items[0..@min(out.items.len, limit)];
}

fn cvesFirst(_: void, a: Patch, b: Patch) bool {
    if ((a.cves.len > 0) != (b.cves.len > 0)) return a.cves.len > 0;
    return std.mem.lessThan(u8, a.name, b.name);
}

/// A package's origin, from the installed database while it is installed.
/// A package since removed is matched by name instead (isSubpackage).
fn originOf(installed: []const Package, name: []const u8) []const u8 {
    for (installed) |p| if (std.mem.eql(u8, p.name, name)) return p.origin;
    return name;
}

/// Whether name is origin itself or one of its subpackages: openssl-4.0 and
/// openssl-4.0-libcrypto, not openssl-4.0 and openssl-4.01.
fn isSubpackage(name: []const u8, origin: []const u8) bool {
    if (!std.mem.startsWith(u8, name, origin)) return false;
    return name.len == origin.len or name[origin.len] == '-';
}

fn kernelVersion(pkg: []const u8) []const u8 {
    const prefix = "linux-virt-";
    return if (std.mem.startsWith(u8, pkg, prefix)) pkg[prefix.len..] else pkg;
}

/// What became of the update that built `build`: the updater logs `commit`
/// or `rollback` for it after the reboot. The newest, unresolved, is still
/// on probation.
fn outcomeOf(events: []const Event, build: []const u8, newest: bool) []const u8 {
    var i = events.len;
    while (i > 0) {
        i -= 1;
        const e = events[i];
        if (!std.mem.eql(u8, e.build, build)) continue;
        if (std.mem.eql(u8, e.event, "commit")) return "applied";
        if (std.mem.eql(u8, e.event, "rollback")) return "rolled back";
    }
    return if (newest) "verifying" else "not recorded";
}

/// One line of the updater's log (docs/updater.md, "Events").
pub const Event = struct {
    time: []const u8 = "",
    event: []const u8 = "",
    build: []const u8 = "",
    result: []const u8 = "",
    reason: []const u8 = "",
    @"error": []const u8 = "",
};

fn parseLog(gpa: Allocator, text: []const u8) ![]const Event {
    var out: std.ArrayList(Event) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        const e = std.json.parseFromSliceLeaky(
            Event,
            gpa,
            line,
            .{ .ignore_unknown_fields = true },
        ) catch continue;
        try out.append(gpa, e);
    }
    return out.items;
}

/// The last thing an update check did.
fn lastCheck(events: []const Event) ?Event {
    var i = events.len;
    while (i > 0) {
        i -= 1;
        const e = events[i].event;
        for ([_][]const u8{ "check", "stage", "update", "skip", "error" }) |name| {
            if (std.mem.eql(u8, e, name)) return events[i];
        }
    }
    return null;
}

pub const Package = struct { name: []const u8, version: []const u8, origin: []const u8 };

/// The packages in an apk installed database, by name: P (name), V (version)
/// and o (origin) of each record; records end at a blank line.
fn parseInstalled(gpa: Allocator, text: []const u8) ![]const Package {
    var out: std.ArrayList(Package) = .empty;
    var p: Package = .{ .name = "", .version = "", .origin = "" };
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) {
            if (p.name.len > 0) try out.append(gpa, withOrigin(p));
            p = .{ .name = "", .version = "", .origin = "" };
        } else if (std.mem.startsWith(u8, line, "P:")) {
            p.name = line[2..];
        } else if (std.mem.startsWith(u8, line, "V:")) {
            p.version = line[2..];
        } else if (std.mem.startsWith(u8, line, "o:")) {
            p.origin = line[2..];
        }
    }
    if (p.name.len > 0) try out.append(gpa, withOrigin(p));
    std.mem.sort(Package, out.items, {}, byName);
    return out.items;
}

fn withOrigin(p: Package) Package {
    return .{
        .name = p.name,
        .version = p.version,
        .origin = if (p.origin.len > 0) p.origin else p.name,
    };
}

fn byName(_: void, a: Package, b: Package) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

/// The filesystem type mounted at point, from /proc/self/mounts; the last
/// mount there is the one that shows.
pub fn mountType(mounts: []const u8, point: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (it.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        _ = f.next() orelse continue;
        const dir = f.next() orelse continue;
        const kind = f.next() orelse continue;
        if (std.mem.eql(u8, dir, point)) found = kind;
    }
    return found;
}

fn parseSlot(cmdline: []const u8) []const u8 {
    var it = std.mem.tokenizeAny(u8, cmdline, " \n");
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "werewolf.slot=")) return arg["werewolf.slot=".len..];
    }
    return "";
}

/// Whole seconds since boot, from /proc/uptime.
fn parseUptime(text: []const u8) u64 {
    const end = std.mem.indexOfAny(u8, text, ". \n") orelse text.len;
    return std.fmt.parseInt(u64, text[0..end], 10) catch 0;
}

/// The two largest units: "3 days, 4 hours", "1 hour, 5 min", "12 min".
fn formatUptime(gpa: Allocator, secs: u64) ![]const u8 {
    const days = secs / 86400;
    const hours = secs % 86400 / 3600;
    const mins = secs % 3600 / 60;
    if (days > 0) return gpa.print(
        "{d} day{s}, {d} hour{s}",
        .{ days, plural(days), hours, plural(hours) },
    );
    if (hours > 0) return gpa.print(
        "{d} hour{s}, {d} min",
        .{ hours, plural(hours), mins },
    );
    return gpa.print("{d} min", .{mins});
}

fn firstWords(text: []const u8, n: usize) []const u8 {
    const t = std.mem.trim(u8, text, " \n");
    var spaces: usize = 0;
    for (t, 0..) |c, i| {
        if (c != ' ') continue;
        spaces += 1;
        if (spaces == n) return t[0..i];
    }
    return t;
}

fn trimLine(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, " \r\n");
}

/// An RFC 3339 time in UTC, as the updater writes them, as seconds; null
/// for anything else.
pub fn parseRfc3339(s: []const u8) ?u64 {
    if (s.len != 20 or s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':' or
        s[19] != 'Z') return null;
    const n = struct {
        fn f(t: []const u8) ?u32 {
            return std.fmt.parseInt(u32, t, 10) catch null;
        }
    }.f;
    const year = n(s[0..4]) orelse return null;
    const month = n(s[5..7]) orelse return null;
    const day = n(s[8..10]) orelse return null;
    if (year < 1970 or month < 1 or month > 12 or day < 1 or day > 31) return null;
    // Days from the civil date (Howard Hinnant's algorithm), from 1970.
    const y: i64 = @as(i64, year) - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = @mod(@as(i64, month) + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    const secs = days * 86400 + @as(i64, n(s[11..13]) orelse return null) * 3600 +
        @as(i64, n(s[14..16]) orelse return null) * 60 + (n(s[17..19]) orelse return null);
    return @intCast(secs);
}

pub fn rfc3339Buf(buf: *[32]u8, secs: u64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.mem.print(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

pub fn rfc3339(gpa: Allocator, secs: u64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return gpa.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

fn moreString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, b, a);
}

pub fn nowSecs(io: Io) u64 {
    const ns = Io.Timestamp.now(io, .real).nanoseconds;
    return @intCast(@max(0, @divFloor(ns, std.time.ns_per_s)));
}

pub fn readOr(io: Io, gpa: Allocator, path: []const u8, fallback: []const u8) []const u8 {
    return readAll(io, gpa, path) catch fallback;
}

/// path, read to its end. Not Dir.readFileAlloc, which reads only as much
/// as stat reports, and procfs reports 0 for /proc/uptime, /proc/loadavg
/// and /proc/self/mounts.
pub fn readAll(io: Io, gpa: Allocator, path: []const u8) ![]u8 {
    return readUpTo(io, gpa, path, max_read);
}

fn readUpTo(io: Io, gpa: Allocator, path: []const u8, limit: usize) ![]u8 {
    var f = try Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.readerStreaming(io, &buf);
    return r.interface.allocRemaining(gpa, .limited(limit));
}

pub fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// Write path whole or not at all: nginx may be reading the old one.
pub fn writeAtomic(io: Io, gpa: Allocator, path: []const u8, data: []const u8) !void {
    const tmp = try gpa.print("{s}.tmp", .{path});
    try Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = data });
    try Dir.rename(Dir.cwd(), tmp, Dir.cwd(), path, io);
}

/// One JSON line on the console, as the updater logs.
pub fn record(io: Io, fields: anytype) void {
    var buf: [4096]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const gpa = fba.allocator();
    var rest: Io.Writer.Allocating = .init(gpa);
    const line = if (std.json.Stringify.value(fields, .{}, &rest.writer)) |_|
        if (rfc3339(gpa, nowSecs(io))) |time|
            gpa.print("status-page: {{\"time\":\"{s}\",{s}\n", .{ time, rest.written()[1..] }) catch
                null
        else |_|
            null
    else |_|
        null;
    // Never nothing: a line too long to say is said to be.
    Io.File.stdout().writeStreamingAll(
        io,
        line orelse "status-page: {\"event\":\"error\",\"error\":\"a log line too long to say\"}\n",
    ) catch {};
}

const testing = std.testing;

test formatUptime {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("0 min", try formatUptime(a, 59));
    try testing.expectEqualStrings("12 min", try formatUptime(a, 12 * 60 + 5));
    try testing.expectEqualStrings("4 hours, 5 min", try formatUptime(a, 4 * 3600 + 5 * 60));
    try testing.expectEqualStrings("1 hour, 0 min", try formatUptime(a, 3600));
    try testing.expectEqualStrings("1 day, 0 hours", try formatUptime(a, 86400));
    try testing.expectEqualStrings(
        "3 days, 4 hours",
        try formatUptime(a, 3 * 86400 + 4 * 3600 + 5 * 60 + 9),
    );
    try testing.expectEqual(1234, parseUptime("1234.56 4567.89\n"));
    try testing.expectEqual(0, parseUptime(""));
}

test "small parsers" {
    try testing.expectEqualStrings("0.00 0.01 0.05", firstWords("0.00 0.01 0.05 1/80 1234\n", 3));
    try testing.expectEqualStrings(
        "b",
        parseSlot("console=hvc0 werewolf.slot=b werewolf.victim=x:/y\n"),
    );
    try testing.expectEqualStrings("", parseSlot("console=ttyS0\n"));
    const mounts =
        \\proc /proc proc rw 0 0
        \\tmpfs /data tmpfs rw 0 0
        \\/dev/vda1 /data ext4 rw,nosuid 0 0
    ;
    try testing.expectEqualStrings("ext4", mountType(mounts, "/data").?);
    try testing.expectEqual(null, mountType(mounts, "/victim"));
    try testing.expect(isAdvisoryId("GHSA-abcd-1234-efgh"));
    try testing.expect(!isAdvisoryId("CVE-1/../x"));
    try testing.expect(isSubpackage("openssl-4.0-libcrypto", "openssl-4.0"));
    try testing.expect(isSubpackage("openssl-4.0", "openssl-4.0"));
    try testing.expect(!isSubpackage("openssl-4.01", "openssl-4.0"));
}

test listensOn {
    const table =
        \\  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        \\   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000   200        0 1234
        \\   1: 0100007F:1F90 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 0
    ;
    try testing.expect(listensOn(table, 80));
    try testing.expect(!listensOn(table, 8080)); // connected, not listening
    try testing.expect(!listensOn(table, 443));
    try testing.expect(!listensOn("", 80));
}

test parseInstalled {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const pkgs = try parseInstalled(
        arena.allocator(),
        "P:zlib\nV:1.3-r0\n\nP:openssl-4.0-libcrypto\nV:4.0.2-r0\no:openssl-4.0\n",
    );
    try testing.expectEqual(2, pkgs.len);
    try testing.expectEqualStrings("openssl-4.0-libcrypto", pkgs[0].name);
    try testing.expectEqualStrings("openssl-4.0", pkgs[0].origin);
    try testing.expectEqualStrings("zlib", pkgs[1].origin);
}

test parseRfc3339 {
    try testing.expectEqual(0, parseRfc3339("1970-01-01T00:00:00Z"));
    try testing.expectEqual(1791288000, parseRfc3339("2026-10-06T12:00:00Z"));
    try testing.expectEqual(951782400, parseRfc3339("2000-02-29T00:00:00Z"));
    try testing.expectEqual(null, parseRfc3339("2026-10-06 12:00:00"));
    try testing.expectEqual(null, parseRfc3339("2026-13-06T12:00:00Z"));
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("2026-10-06T12:00:00Z", rfc3339Buf(&buf, 1791288000));
}

test patchHistory {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const newer = try std.json.parseFromSliceLeaky(Report, a,
        \\{"time":"2026-10-06T13:00:00Z","build":"bbbb","from":{"slot":"a","kernel":"linux-virt-6.18.54-r0"},
        \\ "to":{"slot":"b","kernel":"linux-virt-6.18.55-r0"},
        \\ "packages":[{"name":"zlib","from":"1.1","to":"1.2"},{"name":"openssl-4.0-libcrypto","from":"4.0.1","to":"4.0.2"},{"name":"new","from":null,"to":"1"}],
        \\ "package_cves":[{"origin":"openssl-4.0","from":"4.0.1","to":"4.0.2","cves":["CVE-2026-9"]}],
        \\ "kernel_cves":{"cves":[{"id":"CVE-2026-7","fixed_in":"6.18.55","title":"x"}]},"sources":[]}
    , .{ .ignore_unknown_fields = true });
    const older = try std.json.parseFromSliceLeaky(Report, a,
        \\{"time":"2026-10-05T13:00:00Z","build":"aaaa","from":{"kernel":"linux-virt-6.18.54-r0"},"to":{"kernel":"linux-virt-6.18.54-r0"},
        \\ "packages":[{"name":"busybox","from":"1","to":"2"}],"package_cves":[],"kernel_cves":{}}
    , .{ .ignore_unknown_fields = true });
    const events = try parseLog(a,
        \\{"time":"2026-10-05T13:00:00Z","host":"h","event":"update","build":"aaaa"}
        \\{"time":"2026-10-05T13:02:00Z","host":"h","event":"commit","slot":"b","build":"aaaa"}
        \\not json
        \\{"time":"2026-10-06T13:00:00Z","host":"h","event":"update","build":"bbbb"}
        \\{"time":"2026-10-06T14:00:00Z","host":"h","event":"check","result":"current"}
    );
    const installed = try parseInstalled(
        a,
        "P:openssl-4.0-libcrypto\nV:4.0.2\no:openssl-4.0\n\nP:zlib\nV:1.2\n",
    );

    const p = try patchHistory(a, &.{ newer, older }, events, installed, 25);
    try testing.expectEqual(5, p.len);
    try testing.expectEqualStrings("linux-virt", p[0].name);
    try testing.expectEqualStrings("6.18.54-r0", p[0].from.?);
    try testing.expectEqualStrings("CVE-2026-7", p[0].cves[0]);
    try testing.expectEqualStrings("openssl-4.0-libcrypto", p[1].name);
    try testing.expectEqualStrings("CVE-2026-9", p[1].cves[0]);
    try testing.expectEqualStrings("new", p[2].name);
    try testing.expectEqual(null, p[2].from);
    try testing.expectEqualStrings("verifying", p[0].outcome);
    try testing.expectEqualStrings("busybox", p[4].name);
    try testing.expectEqualStrings("applied", p[4].outcome);

    try testing.expectEqual(2, (try patchHistory(a, &.{ newer, older }, events, installed, 2)).len);
    try testing.expectEqualStrings("check", lastCheck(events).?.event);
    try testing.expectEqualStrings("up to date", describeEvent(lastCheck(events).?));
}

// Each part's tests, with these.
test {
    _ = page;
    _ = scan;
    _ = pg;
}
