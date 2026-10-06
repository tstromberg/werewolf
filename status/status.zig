//! status: the demo form's one web page, about the machine it runs on, and
//! the grype scan the page reports. Two services run it, each as a user of
//! its own, which it tells apart by the service directory runsv starts it
//! in, since runsv runs both as ./run:
//!
//!     /etc/sv/status   as the status user: every minute it writes
//!                      /data/svc/status/www/index.html, which nginx
//!                      serves: the kernel and uptime, the last update
//!                      check, the last 25 patches autoupdate applied with
//!                      the CVEs each fixed, what grype finds in the image,
//!                      and the packages the image holds. It may reach
//!                      nothing on the network.
//!     /etc/sv/scan     as the grype user: once an hour, and at start, it
//!                      runs grype over the root, with its database in
//!                      /data/svc/grype, and keeps a summary there for the
//!                      page, so the page survives a reboot with its last
//!                      scan. grype is the one that fetches, so only this
//!                      user may (forms/demo.net).
//!
//! runsv starts both as root, with no arguments and no shell. Each makes
//! its directories its user's, then becomes that user for good, with no
//! capabilities and no way back, before it reads anything: grype's database
//! comes from the network, and package metadata and grype's findings are
//! other people's text. Everything written into the page is HTML-escaped.
//!
//! Each pass allocates from its own arena, freed when the pass ends, so a
//! process that runs for months uses what one pass needs.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const state_dir = "/data/svc/status";
const www_dir = state_dir ++ "/www";
const page_path = www_dir ++ "/index.html";
const grype_dir = "/data/svc/grype";
const summary_path = grype_dir ++ "/scan.json";
const scan_error_path = grype_dir ++ "/scan-error";
const grype_out = grype_dir ++ "/grype.json";
const grype_bin = "/usr/bin/grype";
const autoupdate_dir = "/data/svc/autoupdate";
const meta_dir = "/usr/share/werewolf";
const render_every = 60;
const scan_every = 3600;
const max_patches = 25;
const max_read = 256 << 20;

/// What grype must not walk: the kernel's own trees, RAM, and /data, which
/// holds grype's database and is not part of the image.
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

/// What the console's lines start with: the service's name.
var role: []const u8 = "status";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var cwd: [Dir.max_path_bytes]u8 = undefined;
    const n = std.process.currentPath(io, &cwd) catch 0;
    if (std.mem.eql(u8, std.fs.path.basename(cwd[0..n]), "scan")) {
        role = "scan";
        return scanLoop(io);
    }

    // Root's last acts: the page's directory, and whatever an older status,
    // which ran as root, left in it, made the status user's.
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const user = lookupUser(readOr(io, arena.allocator(), "/etc/passwd", ""), "status") orelse return error.NoStatusUser;
    arena.deinit();
    Dir.cwd().createDirPath(io, www_dir) catch |err| record(io, .{ .event = "error", .step = "setup", .@"error" = @errorName(err) });
    for ([_][]const u8{ state_dir ++ "/scan.json", state_dir ++ "/scan-error", page_path ++ ".tmp" }) |old| Dir.cwd().deleteFile(io, old) catch {};
    for ([_][:0]const u8{ state_dir, www_dir, page_path }) |path| _ = std.os.linux.fchownat(std.os.linux.AT.FDCWD, path, user.uid, user.gid, std.os.linux.AT.SYMLINK_NOFOLLOW);
    try dropTo(user);
    record(io, .{ .event = "start" });

    var failing = false;
    while (true) {
        if (render(io)) |_| {
            if (failing) record(io, .{ .event = "page", .result = "written again" });
            failing = false;
        } else |err| {
            // Once per failure, not once a minute.
            if (!failing) record(io, .{ .event = "error", .step = "page", .@"error" = @errorName(err) });
            failing = true;
        }
        try io.sleep(.fromSeconds(render_every), .awake);
    }
}

// --- the page ----------------------------------------------------------------

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
        .uname = try std.fmt.allocPrint(gpa, "{s} {s} {s} {s} {s}", .{
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
    f.posture = posture(io, gpa);

    if (readAll(io, gpa, summary_path)) |text| {
        f.scan = std.json.parseFromSliceLeaky(Summary, gpa, text, .{ .ignore_unknown_fields = true }) catch null;
    } else |_| {}
    if (readAll(io, gpa, scan_error_path)) |text| {
        f.scan_error = trimLine(text);
    } else |_| {}
    return f;
}

/// The newest reports first, read only as far as the page needs: each
/// changes at least one package, so max_patches reports are enough.
fn readReports(io: Io, gpa: Allocator) ![]const Report {
    var d = Dir.cwd().openDir(io, autoupdate_dir ++ "/reports", .{ .iterate = true }) catch return &.{};
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
        const text = readAll(io, gpa, try std.fmt.allocPrint(gpa, "{s}/reports/{s}", .{ autoupdate_dir, name })) catch continue;
        const r = std.json.parseFromSliceLeaky(Report, gpa, text, .{ .ignore_unknown_fields = true }) catch continue;
        try reports.append(gpa, r);
    }
    return reports.items;
}

fn describeData(io: Io, gpa: Allocator) []const u8 {
    if (exists(io, "/run/werewolf/nodata")) return "unavailable (see the console)";
    const kind = mountType(readOr(io, gpa, "/proc/self/mounts", ""), "/data") orelse return "not mounted";
    if (std.mem.eql(u8, kind, "tmpfs")) return "RAM: nothing here outlives a reboot";
    return std.fmt.allocPrint(gpa, "{s}, kept across reboots and updates", .{kind}) catch kind;
}

const Facts = struct {
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
    packages: []const Package,
    last_check: ?Event = null,
    patches: []const Patch = &.{},
    scan: ?Summary = null,
    scan_error: ?[]const u8 = null,
    posture: ?Posture = null,
};

/// Plain and quick, as a page of text should be: no script, no fonts to
/// fetch, the browser's light or dark, and tables that scroll sideways on a
/// phone rather than squeeze.
const style =
    \\:root{color-scheme:light dark;--fg:#1b1b1b;--muted:#5f6368;--line:#e3e3e0;--bg:#fff;--card:#f5f5f2;
    \\--link:#0b57d0;--critical:#a50e0e;--high:#b93c00;--medium:#7a5600;--low:#1d4ed8;--none:#5f6368;--ok:#137333;--bad:#a50e0e}
    \\@media (prefers-color-scheme:dark){:root{--fg:#e8e6e3;--muted:#a0a4a8;--line:#323538;--bg:#121314;--card:#1c1e20;
    \\--link:#8ab4f8;--critical:#ff7b72;--high:#ffa657;--medium:#e3b341;--low:#79c0ff;--none:#a0a4a8;--ok:#7ee787;--bad:#ff7b72}
    \\.logo{filter:invert(1)}}
    \\*{box-sizing:border-box}
    \\body{margin:0 auto;max-width:64rem;padding:1.5rem 1rem 3rem;color:var(--fg);background:var(--bg);
    \\font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
    \\a{color:var(--link)}
    \\header{display:flex;gap:1rem;align-items:center}
    \\.logo{border-radius:50%;flex:none}
    \\h1{margin:0;font-size:1.7rem;line-height:1.2;overflow-wrap:anywhere}
    \\.sub{margin:.15rem 0 0;color:var(--muted)}
    \\nav{display:flex;gap:1.25rem;flex-wrap:wrap;margin:1.2rem 0 1.5rem;padding-bottom:.6rem;border-bottom:1px solid var(--line)}
    \\.glance{display:grid;grid-template-columns:repeat(auto-fit,minmax(13.5rem,1fr));gap:.75rem;margin:0}
    \\.tile{background:var(--card);border-radius:.6rem;padding:.8rem 1rem}
    \\.tile dt{color:var(--muted);font-size:.85rem}
    \\.tile dd{margin:0}
    \\.tile strong{display:block;font-size:1.3rem;line-height:1.3}
    \\.tile dd>span:not(.chips){color:var(--muted);font-size:.85rem}
    \\h2{font-size:1.2rem;margin:2.4rem 0 .2rem}
    \\.note{color:var(--muted);margin:.1rem 0 .8rem}
    \\.scroll{overflow-x:auto}
    \\table{border-collapse:collapse;width:100%;font-size:.95rem}
    \\th,td{text-align:left;vertical-align:top;padding:.4rem 1rem .4rem 0;border-bottom:1px solid var(--line)}
    \\thead th{color:var(--muted);font-weight:600;font-size:.85rem}
    \\tbody th{font-weight:600}
    \\tr.group th{padding-top:1.1rem;border-bottom:2px solid var(--line)}
    \\code,pre,.v{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em}
    \\pre{background:var(--card);padding:.7rem 1rem;border-radius:.5rem;white-space:pre-wrap;overflow-wrap:anywhere;margin:.6rem 0}
    \\.sev{font-weight:600;white-space:nowrap}
    \\.sev::before{content:"";display:inline-block;width:.55em;height:.55em;border-radius:50%;margin-right:.4em;background:currentColor}
    \\.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}
    \\.negligible,.unknown{color:var(--none)}.ok{color:var(--ok)}.bad{color:var(--bad)}.muted{color:var(--muted)}
    \\.chips{display:flex;gap:.25rem .8rem;flex-wrap:wrap;font-size:.85rem}.chips .zero{color:var(--muted);font-weight:400}
    \\time,.adv,.v{white-space:nowrap}
    \\.why{font-weight:400;color:var(--muted);font-size:.88rem}.how{font-size:.88rem}
    \\summary{cursor:pointer;color:var(--link);margin:.3rem 0}
    \\footer{margin-top:3rem;padding-top:.8rem;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}
;

fn writePage(w: *Io.Writer, f: Facts) !void {
    try w.writeAll("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" ++
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" ++
        "<link rel=\"icon\" href=\"/logo.png\">\n<title>");
    try esc(w, f.host);
    try w.writeAll(" · werewolf</title>\n<style>\n" ++ style ++ "</style>\n</head>\n<body>\n" ++
        "<header><img class=\"logo\" src=\"/logo.png\" alt=\"\" width=\"64\" height=\"64\">\n<div><h1>");
    try esc(w, f.host);
    try w.writeAll("</h1><p class=\"sub\">A self-patching Linux machine: updated hourly from Wolfi and Alpine, " ++
        "scanned for known vulnerabilities by grype.</p></div></header>\n" ++
        "<nav><a href=\"#system\">System</a><a href=\"#security\">Security</a><a href=\"#patches\">Patches</a>" ++
        "<a href=\"#vulnerabilities\">Vulnerabilities</a><a href=\"#packages\">Packages</a></nav>\n");
    try writeGlance(w, f);
    try writeSystem(w, f);
    try writeSecurity(w, f);
    try writePatches(w, f);
    try writeVulnerabilities(w, f);
    try writePackages(w, f);
    try w.writeAll("<footer>Updated ");
    try writeTime(w, f.now_secs, f.now_secs);
    try w.writeAll(" · rewritten every minute</footer>\n</body>\n</html>\n");
}

/// Four answers before any table: is it up, is it patched, how exposed is
/// it, and is it still looking.
fn writeGlance(w: *Io.Writer, f: Facts) !void {
    var buf: [32]u8 = undefined;
    const booted = rfc3339Buf(&buf, f.booted);
    try w.print("<dl class=\"glance\">\n<div class=\"tile\"><dt>Up</dt><dd><strong><time datetime=\"{s}\" title=\"booted {s} {s} UTC\">", .{ booted, booted[0..10], booted[11..16] });
    try esc(w, f.uptime);
    try w.writeAll("</time></strong><span>load ");
    try esc(w, f.load);
    try w.writeAll("</span></dd></div>\n<div class=\"tile\"><dt>Security checks</dt><dd>");
    if (f.posture) |p| {
        const run = p.summary.pass + p.summary.fail;
        try w.print("<strong class=\"{s}\">{d} of {d} pass</strong>", .{ if (p.summary.fail == 0) "ok" else "bad", p.summary.pass, run });
        if (p.summary.fail > 0) try w.print("<span>{d} failing</span>", .{p.summary.fail});
    } else try w.writeAll("<strong>Checking</strong><span>once the services start</span>");
    try w.writeAll("</dd></div>\n<div class=\"tile\"><dt>Last patched</dt><dd>");
    if (f.patches.len > 0) {
        const newest = f.patches[0];
        var packages: usize = 0;
        var cves: usize = 0;
        for (f.patches) |p| {
            if (!std.mem.eql(u8, p.time, newest.time)) break;
            packages += 1;
            cves += p.cves.len;
        }
        try w.writeAll("<strong>");
        try writeTime(w, parseRfc3339(newest.time) orelse 0, f.now_secs);
        try w.print("</strong><span>{d} package{s}, {d} CVE{s} fixed</span>", .{ packages, plural(packages), cves, plural(cves) });
    } else {
        try w.writeAll("<strong>Not yet</strong>");
    }
    try w.writeAll("</dd></div>\n<div class=\"tile\"><dt>Vulnerabilities</dt><dd>");
    if (f.scan) |s| {
        var fixable: usize = 0;
        for (s.findings) |x| fixable += @intFromBool(x.fixed_in.len > 0);
        try w.print("<strong>{d}</strong>", .{s.findings.len});
        try chips(w, s.counts);
        if (s.findings.len > 0) {
            if (fixable == 0) try w.writeAll("<span>none has a fix yet</span>") else try w.print("<span>{d} with a fix available</span>", .{fixable});
        }
    } else {
        try w.writeAll("<strong>Not scanned yet</strong>");
    }
    try w.writeAll("</dd></div>\n<div class=\"tile\"><dt>Checked for updates</dt><dd>");
    if (f.last_check) |e| {
        try w.writeAll("<strong>");
        try writeTime(w, parseRfc3339(e.time) orelse 0, f.now_secs);
        try w.writeAll("</strong><span>");
        try esc(w, describeEvent(e));
        try w.writeAll("</span>");
    } else {
        try w.writeAll("<strong>Not yet</strong>");
    }
    try w.writeAll("</dd></div>\n</dl>\n");
}

fn writeSystem(w: *Io.Writer, f: Facts) !void {
    try w.writeAll("<h2 id=\"system\">System</h2>\n<pre><span class=\"muted\">$ uname -a</span>\n");
    try esc(w, f.uname);
    try w.writeAll("</pre>\n<div class=\"scroll\"><table><tbody>\n");
    try row(w, "Release", &.{f.release});
    if (f.slot.len > 0) {
        try row(w, "Boot slot", &.{ f.slot, " · the other slot holds the previous release, for rollback" });
    } else try row(w, "Boot slot", &.{"none: booted directly, so it cannot update itself"});
    try row(w, "Shell", &.{if (f.shell) "/bin/sh: built in for debugging; no service uses it" else "none"});
    try row(w, "/data", &.{f.data});
    try w.writeAll("</tbody></table></div>\n");
}

fn writeSecurity(w: *Io.Writer, f: Facts) !void {
    try w.writeAll("<h2 id=\"security\">Security</h2>\n");
    const p = f.posture orelse return w.writeAll("<p class=\"note\">Checked once the services have started.</p>\n");
    try w.print("<p class=\"note\">How this machine protects itself, tested at boot, ", .{});
    try writeTime(w, parseRfc3339(p.time) orelse 0, f.now_secs);
    try w.print(": {d} of {d} pass. The checks are <code>/usr/lib/werewolf/posture</code>, " ++
        "which runs on any Linux.</p>\n", .{ p.summary.pass, p.summary.pass + p.summary.fail });
    try w.writeAll("<div class=\"scroll\"><table class=\"sec\">\n<colgroup><col style=\"width:44%\"><col style=\"width:38%\"><col></colgroup>\n" ++
        "<thead><tr><th>Protection</th><th>Checked by</th><th>Result</th></tr></thead>\n<tbody>\n");
    const areas = [_][2][]const u8{ .{ "kernel", "Kernel" }, .{ "processes", "Processes" }, .{ "programs", "Programs" }, .{ "files", "Files" }, .{ "network", "Network" } };
    for (areas) |area| {
        var any = false;
        for (p.checks) |c| any = any or std.mem.eql(u8, c.area, area[0]);
        if (!any) continue;
        try w.print("<tr class=\"group\"><th colspan=\"3\">{s}</th></tr>\n", .{area[1]});
        for (p.checks) |c| {
            if (!std.mem.eql(u8, c.area, area[0])) continue;
            try w.writeAll("<tr><th scope=\"row\">");
            try esc(w, c.name);
            try w.writeAll("<br><span class=\"why\">");
            try esc(w, c.why);
            try w.writeAll("</span></th><td class=\"how\">");
            try esc(w, c.how);
            try w.writeAll("</td><td>");
            try w.writeAll(if (std.mem.eql(u8, c.result, "pass"))
                "<span class=\"ok\">✓&nbsp;Pass</span>"
            else if (std.mem.eql(u8, c.result, "fail"))
                "<span class=\"bad\">✗&nbsp;Fail</span>"
            else
                "<span class=\"muted\">–&nbsp;n/a</span>");
            if (c.detail.len > 0) {
                try w.writeAll("<br><span class=\"muted\">");
                try esc(w, c.detail);
                try w.writeAll("</span>");
            }
            try w.writeAll("</td></tr>\n");
        }
    }
    try w.writeAll("</tbody></table></div>\n");
}

fn writePatches(w: *Io.Writer, f: Facts) !void {
    try w.writeAll("<h2 id=\"patches\">Patches</h2>\n");
    if (f.patches.len == 0) {
        return w.writeAll("<p class=\"note\">None yet.</p>\n");
    }
    try w.writeAll("<p class=\"note\">Updates it applied to itself, newest first.</p>\n");
    try w.writeAll("<div class=\"scroll\"><table>\n<thead><tr><th>When</th><th>Package</th><th>Change</th>" ++
        "<th>CVEs fixed</th><th>Outcome</th></tr></thead>\n<tbody>\n");
    for (f.patches) |p| {
        try w.writeAll("<tr><td>");
        try writeTime(w, parseRfc3339(p.time) orelse 0, f.now_secs);
        try w.writeAll("</td><th scope=\"row\">");
        try esc(w, p.name);
        try w.writeAll("</th><td>");
        if (p.from) |from| {
            try w.writeAll("<span class=\"v\">");
            try esc(w, from);
            try w.writeAll("</span> → ");
        } else try w.writeAll("added ");
        if (p.to) |to| {
            try w.writeAll("<span class=\"v\">");
            try esc(w, to);
            try w.writeAll("</span>");
        } else try w.writeAll("removed");
        try w.writeAll("</td><td>");
        if (p.cves.len == 0) try w.writeAll("<span class=\"muted\">—</span>");
        for (p.cves, 0..) |id, i| {
            if (i > 0) try w.writeAll(", ");
            try advisory(w, id);
        }
        const class = if (std.mem.eql(u8, p.outcome, "applied")) "ok" else if (std.mem.eql(u8, p.outcome, "rolled back")) "bad" else "muted";
        try w.print("</td><td class=\"{s}\">", .{class});
        try esc(w, p.outcome);
        try w.writeAll("</td></tr>\n");
    }
    try w.writeAll("</tbody></table></div>\n");
}

fn writeVulnerabilities(w: *Io.Writer, f: Facts) !void {
    try w.writeAll("<h2 id=\"vulnerabilities\">Vulnerabilities</h2>\n");
    const s = f.scan orelse {
        try w.writeAll("<p class=\"note\">No scan yet.</p>\n");
        return scanError(w, f.scan_error);
    };
    try w.writeAll("<p class=\"note\">grype ");
    try esc(w, s.grype);
    try w.writeAll(" · database built ");
    try writeTime(w, parseRfc3339(s.db_built) orelse 0, f.now_secs);
    try w.writeAll(" · scanned ");
    try writeTime(w, parseRfc3339(s.time) orelse 0, f.now_secs);
    try w.writeAll("</p>\n");
    try scanError(w, f.scan_error);
    if (s.findings.len == 0) {
        return w.writeAll("<p class=\"ok\">No known vulnerabilities in this image.</p>\n");
    }
    try w.writeAll("<div class=\"scroll\"><table>\n<thead><tr><th>Severity</th><th>Advisory</th><th>Component</th>" ++
        "<th>Fixed in</th></tr></thead>\n<tbody>\n");
    // Findings are worst first, so a package's group starts at its worst
    // finding: the first with that owner.
    for (s.findings, 0..) |first, i| {
        const owner = first.in_package;
        const seen = for (s.findings[0..i]) |x| {
            if (std.mem.eql(u8, x.in_package, owner)) break true;
        } else false;
        if (seen) continue;
        var n: usize = 0;
        for (s.findings) |x| n += @intFromBool(std.mem.eql(u8, x.in_package, owner));
        try w.writeAll("<tr class=\"group\" id=\"in-");
        try anchor(w, owner);
        try w.writeAll("\"><th colspan=\"4\">");
        try esc(w, ownerName(owner));
        if (first.in_version.len > 0) {
            try w.writeAll(" <span class=\"v muted\">");
            try esc(w, first.in_version);
            try w.writeAll("</span>");
        }
        try w.print(" <span class=\"muted\">· {d} finding{s}</span></th></tr>\n", .{ n, plural(n) });
        for (s.findings) |x| {
            if (!std.mem.eql(u8, x.in_package, owner)) continue;
            try w.writeAll("<tr><td>");
            try writeSeverity(w, x.severity);
            try w.writeAll("</td><td>");
            try advisory(w, x.id);
            // The component, where it is not the package itself: a Go
            // module inside a program, say.
            try w.writeAll("</td><td>");
            if (std.mem.eql(u8, x.package, x.in_package) and std.mem.eql(u8, x.version, x.in_version)) {
                try w.writeAll("<span class=\"muted\">—</span>");
            } else {
                try esc(w, x.package);
                try w.writeAll(" <span class=\"v\">");
                try esc(w, x.version);
                try w.writeAll("</span> <span class=\"muted\">");
                try esc(w, kindName(x.kind));
                try w.writeAll("</span>");
            }
            try w.writeAll("</td><td>");
            if (x.fixed_in.len > 0) {
                try w.writeAll("<span class=\"v\">");
                try esc(w, x.fixed_in);
                try w.writeAll("</span>");
            } else try w.writeAll("<span class=\"muted\">—</span>");
            try w.writeAll("</td></tr>\n");
        }
    }
    try w.writeAll("</tbody></table></div>\n");
}

fn scanError(w: *Io.Writer, e: ?[]const u8) !void {
    const msg = e orelse return;
    try w.writeAll("<p class=\"bad\">The last scan did not finish: ");
    try esc(w, msg);
    try w.writeAll("</p>\n");
}

fn writePackages(w: *Io.Writer, f: Facts) !void {
    try w.print("<h2 id=\"packages\">Packages</h2>\n" ++
        "<details><summary>{d} packages from Wolfi</summary>\n<div class=\"scroll\"><table>\n" ++
        "<thead><tr><th>Package</th><th>Version</th><th>Findings</th></tr></thead>\n<tbody>\n", .{f.packages.len});
    for (f.packages) |p| {
        try w.writeAll("<tr><th scope=\"row\">");
        try esc(w, p.name);
        try w.writeAll("</th><td class=\"v\">");
        try esc(w, p.version);
        try w.writeAll("</td><td>");
        var n: usize = 0;
        if (f.scan) |s| for (s.findings) |x| {
            n += @intFromBool(std.mem.eql(u8, x.in_package, p.name));
        };
        if (n > 0) {
            try w.writeAll("<a href=\"#in-");
            try anchor(w, p.name);
            try w.print("\">{d}</a>", .{n});
        }
        try w.writeAll("</td></tr>\n");
    }
    try w.writeAll("</tbody></table></div>\n</details>\n");
}

fn chips(w: *Io.Writer, c: Counts) !void {
    const counts = [_]usize{ c.critical, c.high, c.medium, c.low, c.negligible, c.unknown };
    try w.writeAll("<span class=\"chips\">");
    var any = false;
    for (counts, 0..) |n, i| {
        if (n == 0 and i > 1) continue; // critical and high always show, as zero is news
        any = true;
        try w.print("<span class=\"sev {s}\">{d} {s}</span>", .{ if (n == 0) "zero" else severityClass(i), n, severityClass(i) });
    }
    if (!any) try w.writeAll("none");
    try w.writeAll("</span>");
}

fn writeSeverity(w: *Io.Writer, name: []const u8) !void {
    const i = rank(name);
    try w.print("<span class=\"sev {s}\">{s}</span>", .{ severityClass(i), severities[i] });
}

fn severityClass(i: usize) []const u8 {
    return ([_][]const u8{ "critical", "high", "medium", "low", "negligible", "unknown" })[i];
}

/// What grype calls an artifact's type, as a reader would.
fn kindName(kind: []const u8) []const u8 {
    const names = [_][2][]const u8{
        .{ "apk", "package" },           .{ "go-module", "Go module" }, .{ "binary", "program" },
        .{ "java-archive", "Java" },     .{ "python", "Python" },       .{ "npm", "npm" },
        .{ "rust-crate", "Rust crate" },
    };
    for (names) |n| if (std.mem.eql(u8, n[0], kind)) return n[1];
    return kind;
}

/// The package a finding was found in, as a reader would.
fn ownerName(owner: []const u8) []const u8 {
    if (owner.len == 0) return "Not from a package";
    if (std.mem.eql(u8, owner, werewolf_owner)) return "werewolf's own programs";
    return owner;
}

fn row(w: *Io.Writer, name: []const u8, parts: []const []const u8) !void {
    try w.writeAll("<tr><th scope=\"row\">");
    try esc(w, name);
    try w.writeAll("</th><td>");
    for (parts) |p| try esc(w, p);
    try w.writeAll("</td></tr>\n");
}

/// A time, as how long ago, with the moment itself on hover and for
/// machines.
fn writeTime(w: *Io.Writer, secs: u64, now: u64) !void {
    var buf: [32]u8 = undefined;
    const stamp = rfc3339Buf(&buf, secs);
    try w.print("<time datetime=\"{s}\" title=\"{s} {s} UTC\">", .{ stamp, stamp[0..10], stamp[11..16] });
    try writeAgo(w, secs, now);
    try w.writeAll("</time>");
}

fn writeAgo(w: *Io.Writer, secs: u64, now: u64) !void {
    if (secs == 0) return w.writeAll("at an unknown time");
    const d = now -| secs;
    if (d < 60) return w.writeAll("just now");
    if (d < 3600) return w.print("{d} min ago", .{d / 60});
    if (d < 2 * 86400) return w.print("{d} hour{s} ago", .{ d / 3600, plural(d / 3600) });
    return w.print("{d} days ago", .{d / 86400});
}

fn plural(n: usize) []const u8 {
    return if (n == 1) "" else "s";
}

/// An id for package, from characters ids can hold.
fn anchor(w: *Io.Writer, name: []const u8) !void {
    for (name) |c| try w.writeByte(if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.') c else '-');
}

/// An advisory ID, linked to OSV, which knows CVE, GHSA, GO and the rest.
/// Only an ID made of the characters IDs use becomes part of a URL.
fn advisory(w: *Io.Writer, id: []const u8) !void {
    if (!isAdvisoryId(id)) return esc(w, id);
    try w.print("<a class=\"adv\" href=\"https://osv.dev/vulnerability/{s}\">{s}</a>", .{ id, id });
}

fn esc(w: *Io.Writer, s: []const u8) !void {
    var start: usize = 0;
    for (s, 0..) |c, i| {
        const rep: []const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            else => continue,
        };
        try w.writeAll(s[start..i]);
        try w.writeAll(rep);
        start = i + 1;
    }
    try w.writeAll(s[start..]);
}

fn isAdvisoryId(id: []const u8) bool {
    if (id.len == 0 or id.len > 64) return false;
    for (id) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.' and c != ':') return false;
    }
    return true;
}

fn describeEvent(e: Event) []const u8 {
    if (std.mem.eql(u8, e.event, "check")) return if (std.mem.eql(u8, e.result, "current")) "up to date" else e.result;
    if (std.mem.eql(u8, e.event, "update")) return "updated, and rebooted into it";
    if (std.mem.eql(u8, e.event, "skip")) return e.reason;
    if (std.mem.eql(u8, e.event, "error")) return e.@"error";
    return e.event;
}

// --- the scan ----------------------------------------------------------------

/// The scan service: grype's directories made its user's, then that user
/// for good, then a scan an hour.
fn scanLoop(io: Io) !void {
    var setup: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const user = lookupUser(readOr(io, setup.allocator(), "/etc/passwd", ""), "grype") orelse return error.NoGrypeUser;
    setup.deinit();
    for ([_][:0]const u8{ grype_dir, grype_dir ++ "/db" }) |path| {
        Dir.cwd().createDirPath(io, path) catch |err| {
            record(io, .{ .event = "error", .step = "setup", .@"error" = @errorName(err) });
            break;
        };
        _ = std.os.linux.fchownat(std.os.linux.AT.FDCWD, path, user.uid, user.gid, std.os.linux.AT.SYMLINK_NOFOLLOW);
    }
    try dropTo(user);
    record(io, .{ .event = "start" });

    while (true) {
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        var step: []const u8 = "start";
        scan(io, arena.allocator(), &step) catch |err| {
            record(io, .{ .event = "error", .step = "scan", .at = step, .@"error" = @errorName(err) });
            const msg = std.fmt.allocPrint(arena.allocator(), "{s}, while {s}, at {s}\n", .{ @errorName(err), step, rfc3339(arena.allocator(), nowSecs(io)) catch "" }) catch "";
            writeAtomic(io, arena.allocator(), scan_error_path, msg) catch {};
        };
        arena.deinit();
        io.sleep(.fromSeconds(scan_every), .awake) catch return;
    }
}

/// One grype run. step says what it was doing, for the error if it fails.
fn scan(io: Io, gpa: Allocator, step: *[]const u8) !void {
    step.* = "checking /data";
    if (exists(io, "/run/werewolf/nodata")) return error.DataUnavailable;
    const kind = mountType(readOr(io, gpa, "/proc/self/mounts", ""), "/data") orelse return error.DataNotMounted;
    // grype's database is a 190 MB download that unpacks to several times
    // that; it does not belong in RAM.
    if (std.mem.eql(u8, kind, "tmpfs")) return error.DataInRam;
    if (!exists(io, grype_bin)) return error.NoGrype;

    step.* = "preparing grype's directories";
    Dir.cwd().deleteTree(io, grype_dir ++ "/tmp") catch {};
    for ([_][]const u8{ grype_dir ++ "/db", grype_dir ++ "/tmp" }) |path| try Dir.cwd().createDirPath(io, path);
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
    var child = try std.process.spawn(io, .{
        .argv = &grype_args,
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) return error.GrypeFailed,
        else => return error.GrypeKilled,
    }

    step.* = "reading grype's findings";
    const text = try readAll(io, gpa, grype_out);
    const owners = try parseOwners(gpa, readOr(io, gpa, "/lib/apk/db/installed", ""), readOr(io, gpa, meta_dir ++ "/overlay", ""));
    const summary = try summarize(gpa, text, try rfc3339(gpa, nowSecs(io)), owners);
    var out: Io.Writer.Allocating = .init(gpa);
    try std.json.Stringify.value(summary, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeByte('\n');
    try writeAtomic(io, gpa, summary_path, out.written());
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

/// What the page keeps of a grype run.
const Summary = struct {
    time: []const u8,
    grype: []const u8,
    db_built: []const u8,
    counts: Counts,
    findings: []const Finding,
};

const Counts = struct {
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
    /// The component grype matched, and its version and type.
    package: []const u8,
    version: []const u8,
    kind: []const u8,
    fixed_in: []const u8,
    /// The image's package that put the component here, and its version:
    /// grype itself for a Go module inside /usr/bin/grype. werewolf_owner
    /// for werewolf's own programs; empty when no package claims the file.
    in_package: []const u8 = "",
    in_version: []const u8 = "",
};

const werewolf_owner = "(werewolf)";

/// Which package installed each file, from the apk database, and which
/// files are werewolf's own, from the build record.
const Owners = struct {
    files: std.StringHashMapUnmanaged(Package) = .empty,
    werewolf: std.StringHashMapUnmanaged(void) = .empty,

    /// The package that owns path, as grype reports it (/usr/bin/grype).
    /// The image's /bin, /sbin and /lib are links into /usr, so a path
    /// under them is also looked up there.
    fn of(o: Owners, path: []const u8) ?Package {
        const rel = std.mem.trimStart(u8, path, "/");
        if (o.files.get(rel)) |p| return p;
        var buf: [1024]u8 = undefined;
        const usr = std.fmt.bufPrint(&buf, "usr/{s}", .{rel}) catch return null;
        if (o.files.get(usr)) |p| return p;
        if (o.werewolf.contains(rel) or o.werewolf.contains(usr)) return .{ .name = werewolf_owner, .version = "", .origin = "" };
        return null;
    }
};

/// The files of an apk installed database (F: directory, R: file within
/// it, after the P: and V: of their package), and the build record's list
/// of werewolf's own files, one path a line.
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
            try o.files.put(gpa, try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, line[2..] }), pkg);
        }
    }
    var lines = std.mem.tokenizeScalar(u8, overlay, '\n');
    while (lines.next()) |l| try o.werewolf.put(gpa, l, {});
    return o;
}

/// The parts of grype's JSON the page uses.
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

/// grype's findings, one per vulnerability and component, worst first, each
/// with the package that put it in the image.
fn summarize(gpa: Allocator, text: []const u8, time: []const u8, owners: Owners) !Summary {
    const g = try std.json.parseFromSliceLeaky(GrypeOutput, gpa, text, .{ .ignore_unknown_fields = true });
    var findings: std.ArrayList(Finding) = .empty;
    var counts: Counts = .{};
    outer: for (g.matches) |m| {
        var f: Finding = .{
            .severity = severityName(m.vulnerability.severity),
            .id = m.vulnerability.id,
            .package = m.artifact.name,
            .version = m.artifact.version,
            .kind = m.artifact.type,
            .fixed_in = try std.mem.join(gpa, ", ", m.vulnerability.fix.versions),
        };
        // An apk package is its own; anything else belongs to the package
        // whose file grype found it in.
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
        // name, in two locations); the page lists it once.
        for (findings.items) |x| {
            if (std.mem.eql(u8, x.id, f.id) and std.mem.eql(u8, x.package, f.package) and
                std.mem.eql(u8, x.version, f.version) and std.mem.eql(u8, x.in_package, f.in_package)) continue :outer;
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
    return .{ .time = time, .grype = g.descriptor.version, .db_built = db_built, .counts = counts, .findings = findings.items };
}

const severities = [_][]const u8{ "Critical", "High", "Medium", "Low", "Negligible", "Unknown" };

fn rank(severity: []const u8) usize {
    for (severities, 0..) |s, i| if (std.ascii.eqlIgnoreCase(s, severity)) return i;
    return severities.len - 1;
}

fn severityName(severity: []const u8) []const u8 {
    return severities[rank(severity)];
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

/// The first string under key, anywhere in v: grype's descriptor has moved
/// the database's build time between schema versions.
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

// --- security posture ---------------------------------------------------------
//
// /usr/lib/werewolf/posture (posture/posture.zig) checks how the machine
// protects itself. Its service runs it once per boot, when the other
// services have settled, and keeps the JSON in /run until the next boot.

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
    return std.json.parseFromSliceLeaky(Posture, gpa, text, .{ .ignore_unknown_fields = true }) catch null;
}

// --- patches -----------------------------------------------------------------

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
fn patchHistory(gpa: Allocator, reports: []const Report, events: []const Event, installed: []const Package, limit: usize) ![]const Patch {
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
                if (std.mem.eql(u8, fix.origin, origin) or isSubpackage(c.name, fix.origin)) cves = fix.cves;
            }
            try batch.append(gpa, .{ .time = r.time, .name = c.name, .from = c.from, .to = c.to, .cves = cves, .outcome = outcome });
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
const Event = struct {
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
        const e = std.json.parseFromSliceLeaky(Event, gpa, line, .{ .ignore_unknown_fields = true }) catch continue;
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
        for ([_][]const u8{ "check", "update", "skip", "error" }) |name| {
            if (std.mem.eql(u8, e, name)) return events[i];
        }
    }
    return null;
}

// --- small parsers -----------------------------------------------------------

const Package = struct { name: []const u8, version: []const u8, origin: []const u8 };

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
    return .{ .name = p.name, .version = p.version, .origin = if (p.origin.len > 0) p.origin else p.name };
}

fn byName(_: void, a: Package, b: Package) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

/// The filesystem type mounted at point, from /proc/self/mounts; the last
/// mount there is the one that shows.
fn mountType(mounts: []const u8, point: []const u8) ?[]const u8 {
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

const User = struct { uid: std.posix.uid_t, gid: std.posix.gid_t };

/// name's uid and gid in an /etc/passwd: name:password:uid:gid:...
fn lookupUser(passwd: []const u8, name: []const u8) ?User {
    var lines = std.mem.tokenizeScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, f.next() orelse continue, name)) continue;
        _ = f.next() orelse return null;
        const uid = std.fmt.parseInt(std.posix.uid_t, f.next() orelse return null, 10) catch return null;
        const gid = std.fmt.parseInt(std.posix.gid_t, f.next() orelse return null, 10) catch return null;
        return .{ .uid = uid, .gid = gid };
    }
    return null;
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
    if (days > 0) return std.fmt.allocPrint(gpa, "{d} day{s}, {d} hour{s}", .{ days, plural(days), hours, plural(hours) });
    if (hours > 0) return std.fmt.allocPrint(gpa, "{d} hour{s}, {d} min", .{ hours, plural(hours), mins });
    return std.fmt.allocPrint(gpa, "{d} min", .{mins});
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
fn parseRfc3339(s: []const u8) ?u64 {
    if (s.len != 20 or s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':' or s[19] != 'Z') return null;
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

fn rfc3339Buf(buf: *[32]u8, secs: u64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

fn rfc3339(gpa: Allocator, secs: u64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(gpa, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

fn moreString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, b, a);
}

// --- I/O helpers ---------------------------------------------------------------

fn nowSecs(io: Io) u64 {
    const ns = Io.Timestamp.now(io, .real).nanoseconds;
    return @intCast(@max(0, @divFloor(ns, std.time.ns_per_s)));
}

fn readOr(io: Io, gpa: Allocator, path: []const u8, fallback: []const u8) []const u8 {
    return readAll(io, gpa, path) catch fallback;
}

/// path, read to its end. Not Dir.readFileAlloc, which reads only as much
/// as stat reports, and procfs reports 0 for /proc/uptime, /proc/loadavg
/// and /proc/self/mounts.
fn readAll(io: Io, gpa: Allocator, path: []const u8) ![]u8 {
    var f = try Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.readerStreaming(io, &buf);
    return r.interface.allocRemaining(gpa, .limited(max_read));
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// Write path whole or not at all: nginx may be reading the old one.
fn writeAtomic(io: Io, gpa: Allocator, path: []const u8, data: []const u8) !void {
    const tmp = try std.fmt.allocPrint(gpa, "{s}.tmp", .{path});
    try Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = data });
    try Dir.rename(Dir.cwd(), tmp, Dir.cwd(), path, io);
}

/// Become user for good: no capabilities, now or from anything it runs,
/// no groups but the user's own, and no way back to root.
fn dropTo(user: User) !void {
    const linux = std.os.linux;
    var cap: usize = 0;
    while (cap < 64) : (cap += 1) _ = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
    if (linux.errno(linux.setgroups(0, &[_]linux.gid_t{})) != .SUCCESS) return error.SetGroupsFailed;
    if (linux.errno(linux.setresgid(user.gid, user.gid, user.gid)) != .SUCCESS) return error.SetGidFailed;
    if (linux.errno(linux.setresuid(user.uid, user.uid, user.uid)) != .SUCCESS) return error.SetUidFailed;
    if (linux.errno(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) != .SUCCESS) return error.NoNewPrivsFailed;
    if (linux.errno(linux.setresuid(0, 0, 0)) == .SUCCESS) return error.StillRoot;
}

/// One JSON line on the console, as the updater logs.
fn record(io: Io, fields: anytype) void {
    var buf: [4096]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const gpa = fba.allocator();
    var rest: Io.Writer.Allocating = .init(gpa);
    std.json.Stringify.value(fields, .{}, &rest.writer) catch return;
    const time = rfc3339(gpa, nowSecs(io)) catch return;
    const line = std.fmt.allocPrint(gpa, "{s}: {{\"time\":\"{s}\",{s}\n", .{ role, time, rest.written()[1..] }) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test esc {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try esc(&out.writer, "a<b>&\"c'd");
    try testing.expectEqualStrings("a&lt;b&gt;&amp;&quot;c&#39;d", out.written());
}

test advisory {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try advisory(&out.writer, "CVE-2026-1234");
    try advisory(&out.writer, " GHSA\"><x");
    try testing.expectEqualStrings("<a class=\"adv\" href=\"https://osv.dev/vulnerability/CVE-2026-1234\">CVE-2026-1234</a> GHSA&quot;&gt;&lt;x", out.written());
}

test formatUptime {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("0 min", try formatUptime(a, 59));
    try testing.expectEqualStrings("12 min", try formatUptime(a, 12 * 60 + 5));
    try testing.expectEqualStrings("4 hours, 5 min", try formatUptime(a, 4 * 3600 + 5 * 60));
    try testing.expectEqualStrings("1 hour, 0 min", try formatUptime(a, 3600));
    try testing.expectEqualStrings("1 day, 0 hours", try formatUptime(a, 86400));
    try testing.expectEqualStrings("3 days, 4 hours", try formatUptime(a, 3 * 86400 + 4 * 3600 + 5 * 60 + 9));
    try testing.expectEqual(1234, parseUptime("1234.56 4567.89\n"));
    try testing.expectEqual(0, parseUptime(""));
}

test "small parsers" {
    try testing.expectEqualStrings("0.00 0.01 0.05", firstWords("0.00 0.01 0.05 1/80 1234\n", 3));
    try testing.expectEqualStrings("b", parseSlot("console=hvc0 werewolf.slot=b werewolf.victim=x:/y\n"));
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
    const passwd = "root:x:0:0:root:/root:/bin/sh\ngrype:x:201:202::/var/empty:/sbin/nologin\nbad:x:nope:1::/:/x\n";
    try testing.expectEqual(User{ .uid = 201, .gid = 202 }, lookupUser(passwd, "grype").?);
    try testing.expectEqual(null, lookupUser(passwd, "gry"));
    try testing.expectEqual(null, lookupUser(passwd, "bad"));
}

test parseInstalled {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const pkgs = try parseInstalled(arena.allocator(), "P:zlib\nV:1.3-r0\n\nP:openssl-4.0-libcrypto\nV:4.0.2-r0\no:openssl-4.0\n");
    try testing.expectEqual(2, pkgs.len);
    try testing.expectEqualStrings("openssl-4.0-libcrypto", pkgs[0].name);
    try testing.expectEqualStrings("openssl-4.0", pkgs[0].origin);
    try testing.expectEqualStrings("zlib", pkgs[1].origin);
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
        \\ {"vulnerability":{"id":"CVE-2026-4","severity":"Low"},"artifact":{"name":"zig","version":"0.17","type":"binary","locations":[{"path":"/usr/lib/werewolf/status"}]}},
        \\ {"vulnerability":{"id":"CVE-2026-3","severity":"weird"},"artifact":{"name":"a","version":"1","locations":[{"path":"/opt/x"}]}}
        \\],
        \\"descriptor":{"name":"grype","version":"0.120.0","db":{"status":{"built":"2026-10-06T06:32:14Z","schemaVersion":"v6.1.10"}}}}
    ;
    const owners = try parseOwners(a, "P:grype\nV:0.120.0-r0\nF:usr/bin\nR:grype\n\nP:zlib\nV:1.1\nF:usr/lib\nR:libz.so.1\n", "usr/lib/werewolf/status\n");
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
    const installed = try parseInstalled(a, "P:openssl-4.0-libcrypto\nV:4.0.2\no:openssl-4.0\n\nP:zlib\nV:1.2\n");

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

test writePage {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const now = 1791288000; // 2026-10-06T12:00:00Z
    const facts: Facts = .{
        .now_secs = now,
        .host = "<demo>",
        .uname = "Linux demo 6.18.55-0-virt #1 SMP aarch64",
        .uptime = "4:05",
        .booted = now - (4 * 3600 + 5 * 60),
        .load = "0.00 0.01 0.05",
        .release = "demo",
        .slot = "a",
        .shell = false,
        .data = "ext4",
        .packages = &.{ .{ .name = "glibc", .version = "2.44-r7", .origin = "glibc" }, .{ .name = "grype", .version = "0.120.0-r0", .origin = "grype" } },
    };
    var out: Io.Writer.Allocating = .init(arena.allocator());
    try writePage(&out.writer, facts);
    var page = out.written();
    try testing.expect(std.mem.indexOf(u8, page, "<h1>&lt;demo&gt;</h1>") != null);
    try testing.expect(std.mem.indexOf(u8, page, "<demo>") == null);
    try testing.expect(std.mem.indexOf(u8, page, "src=\"/logo.png\"") != null);
    try testing.expect(std.mem.indexOf(u8, page, "None yet") != null);
    try testing.expect(std.mem.indexOf(u8, page, "No scan yet.") != null);
    try testing.expect(std.mem.indexOf(u8, page, "<script") == null);
    try testing.expect(std.mem.endsWith(u8, page, "</html>\n"));

    // With findings: grouped under the package that brought them, worst
    // group first, each package's count linked from the package list.
    var with = facts;
    with.scan = .{
        .time = "2026-10-06T11:58:00Z",
        .grype = "0.120.0",
        .db_built = "2026-10-06T06:32:14Z",
        .counts = .{ .high = 1, .medium = 2 },
        .findings = &.{
            .{ .severity = "High", .id = "GO-2026-4887", .package = "github.com/docker/docker", .version = "v28.5.2", .kind = "go-module", .fixed_in = "", .in_package = "grype", .in_version = "0.120.0-r0" },
            .{ .severity = "Medium", .id = "CVE-2026-8674", .package = "glibc", .version = "2.44-r7", .kind = "apk", .fixed_in = "2.44-r8", .in_package = "glibc", .in_version = "2.44-r7" },
            .{ .severity = "Medium", .id = "GHSA-pxq6", .package = "github.com/docker/docker", .version = "v28.5.2", .kind = "go-module", .fixed_in = "", .in_package = "grype", .in_version = "0.120.0-r0" },
        },
    };
    out = .init(arena.allocator());
    try writePage(&out.writer, with);
    page = out.written();
    const grype_group = std.mem.indexOf(u8, page, "id=\"in-grype\"").?;
    const glibc_group = std.mem.indexOf(u8, page, "id=\"in-glibc\"").?;
    try testing.expect(grype_group < glibc_group);
    try testing.expect(std.mem.indexOf(u8, page, "· 2 findings") != null);
    try testing.expect(std.mem.count(u8, page, "id=\"in-grype\"") == 1);
    try testing.expect(std.mem.indexOf(u8, page, "Go module") != null);
    try testing.expect(std.mem.indexOf(u8, page, "<a href=\"#in-grype\">2</a>") != null);
    try testing.expect(std.mem.indexOf(u8, page, "2 min ago") != null);
}
