//! status-page's page: the HTML it writes, everything from outside escaped.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const main = @import("status-page.zig");
const scan = @import("scan.zig");
const Counts = scan.Counts;
const rank = scan.rank;
const severities = scan.severities;
const werewolf_owner = scan.werewolf_owner;
const Event = main.Event;
const Facts = main.Facts;
const parseRfc3339 = main.parseRfc3339;
const rfc3339 = main.rfc3339;

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

pub fn writePage(w: *Io.Writer, f: Facts) !void {
    try w.writeAll("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" ++
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" ++
        "<link rel=\"icon\" href=\"/logo.png\">\n<title>");
    try esc(w, f.host);
    try w.writeAll(" · werewolf</title>\n<style>\n" ++ style ++ "</style>\n</head>\n<body>\n" ++
        "<header><img class=\"logo\" src=\"/logo.png\" alt=\"\" width=\"64\" " ++
        "height=\"64\">\n<div><h1>");
    try esc(w, f.host);
    try w.writeAll("</h1><p class=\"sub\">A self-patching Linux machine: updated hourly from " ++
        "Wolfi and Alpine, scanned for known vulnerabilities by grype.</p></div></header>\n" ++
        "<nav><a href=\"#system\">System</a><a href=\"#security\">Security</a>" ++
        "<a href=\"#patches\">Patches</a>" ++
        "<a href=\"#vulnerabilities\">Vulnerabilities</a><a href=\"#packages\">Packages</a>" ++
        "</nav>\n");
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
    const booted = rfc3339(&buf, f.booted);
    try w.print(
        "<dl class=\"glance\">\n<div class=\"tile\"><dt>Up</dt><dd><strong><time " ++
            "datetime=\"{s}\" title=\"booted {s} {s} UTC\">",
        .{ booted, booted[0..10], booted[11..16] },
    );
    try esc(w, f.uptime);
    try w.writeAll("</time></strong><span>load ");
    try esc(w, f.load);
    try w.writeAll("</span></dd></div>\n<div class=\"tile\"><dt>Security checks</dt><dd>");
    if (f.posture) |p| {
        const run = p.summary.pass + p.summary.fail;
        try w.print(
            "<strong class=\"{s}\">{d} of {d} pass</strong>",
            .{ if (p.summary.fail == 0) "ok" else "bad", p.summary.pass, run },
        );
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
        try w.print(
            "</strong><span>{d} package{s}, {d} CVE{s} fixed</span>",
            .{ packages, plural(packages), cves, plural(cves) },
        );
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
            if (fixable == 0)
                try w.writeAll("<span>none has a fix yet</span>")
            else
                try w.print("<span>{d} with a fix available</span>", .{fixable});
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
        try row(
            w,
            "Boot slot",
            &.{ f.slot, " · the other slot holds the previous release, for rollback" },
        );
    } else try row(w, "Boot slot", &.{"none: booted directly, so it cannot update itself"});
    try row(
        w,
        "Shell",
        &.{if (f.shell) "/bin/sh: built in for debugging; no service uses it" else "none"},
    );
    try row(w, "/data", &.{f.data});
    try row(w, "Database", &.{ if (f.database_warn) "⚠️ " else "", f.database });
    if (f.boot.len > 0) try row(w, "Boot", &.{f.boot});
    try w.writeAll("</tbody></table></div>\n");
}

fn writeSecurity(w: *Io.Writer, f: Facts) !void {
    try w.writeAll("<h2 id=\"security\">Security</h2>\n");
    const p = f.posture orelse return w.writeAll(
        "<p class=\"note\">Checked once the services have started.</p>\n",
    );
    try w.writeAll("<p class=\"note\">How this machine protects itself, tested at boot, ");
    try writeTime(w, parseRfc3339(p.time) orelse 0, f.now_secs);
    try w.print(": {d} of {d} pass. The checks are <code>/usr/lib/werewolf/posture</code>, " ++
        "which runs on any Linux.</p>\n", .{ p.summary.pass, p.summary.pass + p.summary.fail });
    try w.writeAll("<div class=\"scroll\"><table class=\"sec\">\n<colgroup><col " ++
        "style=\"width:44%\"><col style=\"width:38%\"><col></colgroup>\n" ++
        "<thead><tr><th>Protection</th><th>Checked by</th><th>Result</th></tr></thead>\n<tbody>\n");
    const areas = [_][2][]const u8{
        .{ "kernel", "Kernel" },
        .{ "processes", "Processes" },
        .{ "programs", "Programs" },
        .{ "files", "Files" },
        .{ "network", "Network" },
    };
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
    try w.writeAll("<div class=\"scroll\"><table>\n<thead><tr><th>When</th><th>Package</th>" ++
        "<th>Change</th><th>CVEs fixed</th><th>Outcome</th></tr></thead>\n<tbody>\n");
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
        const class = if (std.mem.eql(u8, p.outcome, "applied"))
            "ok"
        else if (std.mem.eql(u8, p.outcome, "rolled back"))
            "bad"
        else
            "muted";
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
    try w.writeAll("<div class=\"scroll\"><table>\n<thead><tr><th>Severity</th><th>Advisory</th>" ++
        "<th>Component</th><th>Fixed in</th></tr></thead>\n<tbody>\n");
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
        try w.print(
            " <span class=\"muted\">· {d} finding{s}</span></th></tr>\n",
            .{ n, plural(n) },
        );
        for (s.findings) |x| {
            if (!std.mem.eql(u8, x.in_package, owner)) continue;
            const r = rank(x.severity);
            try w.print(
                "<tr><td><span class=\"sev {s}\">{s}</span>",
                .{ severityClass(r), severities[r] },
            );
            try w.writeAll("</td><td>");
            try advisory(w, x.id);
            // The component, where it is not the package itself: a Go
            // module inside a program, say.
            try w.writeAll("</td><td>");
            if (std.mem.eql(u8, x.package, x.in_package) and
                std.mem.eql(u8, x.version, x.in_version))
            {
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
        "<thead><tr><th>Package</th><th>Version</th><th>Findings</th></tr></thead>\n<tbody>\n", .{
        f.packages.len,
    });
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
        try w.print(
            "<span class=\"sev {s}\">{d} {s}</span>",
            .{ if (n == 0) "zero" else severityClass(i), n, severityClass(i) },
        );
    }
    if (!any) try w.writeAll("none");
    try w.writeAll("</span>");
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
    const stamp = rfc3339(&buf, secs);
    try w.print(
        "<time datetime=\"{s}\" title=\"{s} {s} UTC\">",
        .{ stamp, stamp[0..10], stamp[11..16] },
    );
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

pub fn plural(n: usize) []const u8 {
    return if (n == 1) "" else "s";
}

/// An id for package, from characters ids can hold.
fn anchor(w: *Io.Writer, name: []const u8) !void {
    for (name) |c| try w.writeByte(
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.') c else '-',
    );
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

pub fn isAdvisoryId(id: []const u8) bool {
    if (id.len == 0 or id.len > 64) return false;
    for (id) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.' and
            c != ':') return false;
    }
    return true;
}

pub fn describeEvent(e: Event) []const u8 {
    if (std.mem.eql(u8, e.event, "check"))
        return if (std.mem.eql(u8, e.result, "current")) "up to date" else e.result;
    // "update" is the event before staging (docs/design/update-policy.md).
    if (std.mem.eql(u8, e.event, "update")) return "updated, and rebooted into it";
    if (std.mem.eql(u8, e.event, "stage")) return "staged, to boot when due";
    if (std.mem.eql(u8, e.event, "skip")) return e.reason;
    if (std.mem.eql(u8, e.event, "error")) return e.@"error";
    return e.event;
}

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
    try testing.expectEqualStrings(
        "<a class=\"adv\" href=\"https://osv.dev/vulnerability/CVE-2026-1234\">CVE-2026-1234</a>" ++
            " GHSA&quot;&gt;&lt;x",
        out.written(),
    );
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
        .packages = &.{
            .{ .name = "glibc", .version = "2.44-r7", .origin = "glibc" },
            .{ .name = "grype", .version = "0.120.0-r0", .origin = "grype" },
        },
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
            .{
                .severity = "High",
                .id = "GO-2026-4887",
                .package = "github.com/docker/docker",
                .version = "v28.5.2",
                .kind = "go-module",
                .fixed_in = "",
                .in_package = "grype",
                .in_version = "0.120.0-r0",
            },
            .{
                .severity = "Medium",
                .id = "CVE-2026-8674",
                .package = "glibc",
                .version = "2.44-r7",
                .kind = "apk",
                .fixed_in = "2.44-r8",
                .in_package = "glibc",
                .in_version = "2.44-r7",
            },
            .{
                .severity = "Medium",
                .id = "GHSA-pxq6",
                .package = "github.com/docker/docker",
                .version = "v28.5.2",
                .kind = "go-module",
                .fixed_in = "",
                .in_package = "grype",
                .in_version = "0.120.0-r0",
            },
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
