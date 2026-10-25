//! health keeps one issue open per failing main-branch publishing
//! workflow: a failure opens or updates it, a later success closes it,
//! and a delayed event never reopens what a newer run recovered.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;

const workflows = [_][]const u8{ "check", "packages", "form-images" };

/// report acts on one completed workflow_run event through gh. A run takes
/// its workflow's run-name ("Form images (all)") when it has one, so the
/// workflow is known by its file.
pub fn report(s: *Sys, run: Json) !void {
    const file = try json.text(run, "path");
    const workflow = inline for (workflows) |w| {
        if (mem.eql(u8, file, ".github/workflows/" ++ w ++ ".yml")) break w;
    } else return s.refuse("unexpected publishing workflow {s}", .{file});
    const repo = s.getenv("GH_REPO") orelse return s.refuse("GH_REPO is required", .{});
    const title = try s.gpa.print("Publishing blocked: {s}", .{workflow});
    const listed = try json.parse(s.gpa, try sys.output(s, &.{
        "gh",       "issue",                                       "list",   "--state",      "open",
        "--search", try s.gpa.print("\"{s}\" in:title", .{title}), "--json", "number,title",
    }));
    var issue: ?[]const u8 = null;
    for (try json.items(listed)) |item| if (mem.eql(u8, json.text(item, "title") catch "", title)) {
        issue = try s.gpa.print("{d}", .{try json.int(item, "number")});
        break;
    };
    // A delayed event must not reopen a failure after a newer successful run.
    const api = try s.gpa.print("repos/{s}/actions/workflows/{f}/runs?branch=main&status=complet" ++
        "ed&per_page=30", .{
        repo, Integer{ .v = try json.field(run, "workflow_id") },
    });
    const runs = try json.items(try json.field(
        try json.parse(s.gpa, try sys.output(s, &.{ "gh", "api", api })),
        "workflow_runs",
    ));
    for (runs) |item| {
        if (mem.eql(u8, try json.text(item, "event"), "pull_request")) continue;
        if (!mem.eql(
            u8,
            try json.text(try json.field(item, "head_repository"), "full_name"),
            repo,
        )) continue;
        if (try json.int(item, "run_number") > try json.int(run, "run_number")) return;
        break;
    }
    const url = try json.text(run, "html_url");
    if (mem.eql(u8, json.text(run, "conclusion") catch "", "success")) {
        if (issue) |n| try sys.run(
            s,
            &.{ "gh", "issue", "close", n, "--comment", try s.gpa.print("Recovered: {s}", .{url}) },
            .{},
        );
        return;
    }
    const body = try s.gpa.print(
        "The main-branch **{s}** workflow failed. Image publication needs this pipeline to " ++
            "recover.\n\n" ++
            "[Inspect the latest failure]({s})\n\n" ++
            "Commit: `{s}`\n\n" ++
            "This issue is updated on retries and closed automatically after a successful run.\n",
        .{ workflow, url, try json.text(run, "head_sha") },
    );
    const work = try sys.scratch(s, null, "ww-publishing-health-");
    defer sys.remove(s, work);
    const path = try sys.join(s, &.{ work, "body.md" });
    try sys.write(s, path, body);
    if (issue) |n| {
        try sys.run(s, &.{ "gh", "issue", "edit", n, "--body-file", path }, .{});
    } else {
        try sys.run(s, &.{ "gh", "issue", "create", "--title", title, "--body-file", path }, .{});
    }
}

/// Integer prints a JSON number as Python's str() does.
const Integer = struct {
    v: Json,

    pub fn format(i: Integer, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (i.v) {
            .integer => |n| try w.print("{d}", .{n}),
            .number_string => |n| try w.writeAll(n),
            .string => |n| try w.writeAll(n),
            else => try w.writeAll("None"),
        }
    }
};

const testing = std.testing;
const fixture = @import("fixture.zig");

fn gh(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
    if (!mem.eql(u8, argv[0], "gh")) return null;
    if (mem.eql(u8, argv[1], "issue") and mem.eql(u8, argv[2], "list"))
        return .{ .term = .{ .exited = 0 }, .stdout = f.text };
    if (mem.eql(
        u8,
        argv[1],
        "api",
    )) return .{ .term = .{ .exited = 0 }, .stdout = try f.gpa().print(
        "{{\"workflow_runs\":[{{\"run_number\":{d},\"event\":\"push\",\"head_repository\":{{\"fu" ++
            "ll_name\":\"org/repo\"}}}}]}}",
        .{f.state},
    ) };
    if (mem.eql(
        u8,
        argv[1],
        "issue",
    ) and argv.len > 2 and (mem.eql(u8, argv[2], "edit") or mem.eql(u8, argv[2], "create")))
        f.text = try sys.read(&f.s, argv[argv.len - 1], 4096);
    return sys.Result.passed;
}

fn healthRun(f: *fixture.Fixture, conclusion: []const u8, issues: []const u8, latest: usize) !void {
    f.calls.clearRetainingCapacity();
    f.answer = gh;
    f.text = issues;
    f.state = latest;
    try f.env.put("GH_REPO", "org/repo");
    const run = try json.from(f.gpa(), .{
        .name = "Form images (all)",
        .path = ".github/workflows/form-images.yml",
        .workflow_id = 42,
        .run_number = 7,
        .conclusion = conclusion,
        .html_url = "https://github.com/org/repo/actions/runs/7",
        .head_sha = fixture.rep('a', 40),
    });
    try report(&f.s, run);
}

const tracked = "[{\"number\":12,\"title\":\"Publishing blocked: form-images\"}]";

test "a failure opens one issue, and a retry updates that same issue" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    try healthRun(&f, "failure", "[]", 7);
    try testing.expectEqual(@as(usize, 1), f.called(&.{ "gh", "issue", "create" }));
    try testing.expect(mem.find(u8, f.text, "**form-images** workflow failed") != null);
    try healthRun(&f, "failure", tracked, 7);
    try testing.expectEqual(@as(usize, 1), f.called(&.{ "gh", "issue", "edit", "12" }));
    try testing.expectEqual(@as(usize, 0), f.called(&.{ "gh", "issue", "create" }));
}

test "recovery closes the issue, and a healthy run opens none" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    try healthRun(&f, "success", "[]", 7);
    try testing.expectEqual(@as(usize, 0), f.called(&.{ "gh", "issue", "create" }));
    try healthRun(&f, "success", tracked, 7);
    try testing.expectEqual(@as(usize, 1), f.called(&.{ "gh", "issue", "close", "12" }));
}

test "a delayed failure does not reopen a recovered issue" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    try healthRun(&f, "failure", "[]", 8);
    try testing.expectEqual(
        @as(usize, 0),
        f.called(&.{ "gh", "issue", "create" }) + f.called(&.{ "gh", "issue", "edit" }),
    );
}

test "an issue with another title is never edited" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    try healthRun(&f, "failure", "[{\"number\":12,\"title\":\"form-images user question\"}]", 7);
    try testing.expectEqual(@as(usize, 1), f.called(&.{ "gh", "issue", "create" }));
    try testing.expectEqual(@as(usize, 0), f.called(&.{ "gh", "issue", "edit" }));
}

test "only the three publishing workflows are tracked" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    f.answer = gh;
    try testing.expectError(
        error.Refused,
        report(
            &f.s,
            try json.from(f.gpa(), .{ .name = "check", .path = ".github/workflows/lint.yml" }),
        ),
    );
    try testing.expectEqual(@as(usize, 0), f.calls.items.len);
}
