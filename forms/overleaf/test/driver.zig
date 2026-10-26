//! A document cannot read another project's files, though it is given their
//! path. Overleaf compiles every project as clsi's one user; clsi-confine
//! keeps each compile to its own directory. The driver compiles a project
//! that holds a secret, finds the secret in that compile's directory, then
//! compiles a second project whose document reads it there.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;
const text = driver.system.text;

const secret = "werewolf-secret-kept-apart";
/// compiles holds each compile's directory, as clsi and TeX see it; the
/// host sees it beneath clsi's /data/svc/clsi.
const compiles = "/var/lib/overleaf/data/compiles/";

/// probe.tex reads 64 bytes of the path between probe_head and probe_tail
/// with \pdffiledump, which yields nothing when the open is refused, where
/// \input and \openin stop TeX; and 16 of its own, to show it reads at all:
/// latexmk -cd runs TeX in the document's folder.
/// \found writes the log's markers, so a line TeX quotes is never one.
const probe_head =
    \\\documentclass{article}
    \\\newcommand\found[1]{\typeout{werewolf-#1}}
    \\\begin{document}
    \\\edef\own{\pdffiledump length 16 {probe.tex}}
    \\\ifx\own\empty\else\found{own-read}\fi
    \\\edef\leak{\pdffiledump length 64 {
;
const probe_tail =
    \\}}
    \\\ifx\leak\empty\found{apart}\else\found{leaked=\leak}\fi
    \\werewolf
    \\\end{document}
    \\
;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "cross-project")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    var random: [8]u8 = undefined;
    io.random(&random);
    const dir = try a.print("/run/test-overleaf-{s}-{x}", .{ ctx.run, &random });
    try Io.Dir.cwd().createDir(io, dir, .fromMode(0o700));
    defer Io.Dir.cwd().deleteTree(io, dir) catch {};
    var web: Web = .{ .a = a, .io = io, .client = try driver.fetch.Client.init(a), .dir = dir };
    defer web.client.deinit();
    try web.signIn();

    const kept = try web.project("werewolf-kept");
    _ = try web.upload(kept, "secret.tex", secret ++ "\n");
    const user = try owner(try logUrl(try web.compile(kept.id, null)));
    const path = try a.print("{s}{s}-{s}/werewolf/secret.tex", .{ compiles, kept.id, user });
    const stored = try driver.system.read(io, a, try a.print("/data/svc/clsi{s}", .{path}));
    if (std.mem.find(u8, stored, secret) == null) return error.SecretNotCompiled;

    const probe = try web.project("werewolf-probe");
    const doc = try web.upload(probe, "probe.tex", try std.mem.concat(a, u8, &.{
        probe_head, path, probe_tail,
    }));
    const compiled = try web.compile(probe.id, .{ doc, "werewolf/probe.tex" });
    const log = try web.get(try logUrl(compiled));
    try logged(log, "werewolf-own-read", true);
    try logged(log, "werewolf-apart", true);
    try logged(log, "werewolf-leaked", false);
    try ctx.result(io, args[1], "overleaf-cross-project", true);
}

/// Project is a project and the folder its files go in: Overleaf takes a
/// file only into a folder named by its id, and tells the root folder's to
/// its editor alone.
const Project = struct { id: []const u8, folder: []const u8 };

const Web = struct {
    a: Allocator,
    io: Io,
    client: driver.fetch.Client,
    /// dir holds the files upload sends.
    dir: []const u8,
    csrf: []const u8 = "",

    fn request(w: *Web, path: []const u8) !Json {
        var req = driver.system.object(w.a);
        try req.object.put(w.a, "url", text(try w.a.print("https://localhost{s}", .{path})));
        try req.object.put(w.a, "ca", text("/data/svc/caddy/pki/authorities/local/root.crt"));
        try req.object.put(w.a, "session", text("cross-project"));
        return req;
    }

    fn get(w: *Web, path: []const u8) ![]const u8 {
        return answer(path, try w.client.request(try w.request(path), 30000, w.a));
    }

    /// post sends value as the request's field, json or multipart, and
    /// returns the JSON Overleaf answers.
    fn post(w: *Web, path: []const u8, field: []const u8, value: Json, seconds: i64) !Json {
        var req = try w.request(path);
        try req.object.put(w.a, "method", text("POST"));
        var headers = driver.system.object(w.a);
        try headers.object.put(w.a, "Accept", text("application/json"));
        try headers.object.put(w.a, "X-Csrf-Token", text(w.csrf));
        try req.object.put(w.a, "headers", headers);
        try req.object.put(w.a, field, value);
        const body = try answer(path, try w.client.request(req, seconds * 1000, w.a));
        return std.json.parseFromSliceLeaky(Json, w.a, body, .{});
    }

    fn signIn(w: *Web) !void {
        w.csrf = try token(try w.get("/login"));
        var login = driver.system.object(w.a);
        try login.object.put(w.a, "email", text("admin@example.com"));
        try login.object.put(w.a, "password", text(try driver.system.read(
            w.io,
            w.a,
            "/run/config/overleaf/admin-password",
        )));
        _ = try w.post("/login", "json", login, 30);
        // Signing in starts a session of its own, with a token of its own.
        w.csrf = try token(try w.get("/project"));
    }

    fn project(w: *Web, name: []const u8) !Project {
        var fields = driver.system.object(w.a);
        try fields.object.put(w.a, "projectName", text(name));
        const made = try w.post("/project/new", "json", fields, 30);
        const id = try objectId(try string(made, "project_id"));
        var folder = driver.system.object(w.a);
        try folder.object.put(w.a, "name", text("werewolf"));
        const path = try w.a.print("/project/{s}/folder", .{id});
        return .{ .id = id, .folder = try objectId(try string(
            try w.post(path, "json", folder, 30),
            "_id",
        )) };
    }

    /// upload adds a file to a project's werewolf folder and returns its id.
    fn upload(w: *Web, p: Project, name: []const u8, data: []const u8) ![]const u8 {
        const local = try w.a.print("{s}/{s}", .{ w.dir, name });
        try Io.Dir.cwd().writeFile(w.io, .{ .sub_path = local, .data = data });
        var file = driver.system.object(w.a);
        try file.object.put(w.a, "file", text(local));
        try file.object.put(w.a, "filename", text(name));
        try file.object.put(w.a, "type", text("text/x-tex"));
        var parts = driver.system.object(w.a);
        try parts.object.put(w.a, "name", text(name));
        try parts.object.put(w.a, "qqfile", file);
        const path = try w.a.print("/Project/{s}/upload?folder_id={s}", .{ p.id, p.folder });
        return objectId(try string(try w.post(path, "multipart", parts, 30), "entity_id"));
    }

    /// compile compiles a project from its main document, or from root, a
    /// document's id and path: Overleaf takes the id only beside a path.
    fn compile(w: *Web, id: []const u8, root: ?[2][]const u8) !Json {
        var options = driver.system.object(w.a);
        try options.object.put(w.a, "draft", .{ .bool = false });
        try options.object.put(w.a, "check", text("silent"));
        try options.object.put(w.a, "incrementalCompilesEnabled", .{ .bool = false });
        if (root) |r| {
            try options.object.put(w.a, "rootDoc_id", text(r[0]));
            try options.object.put(w.a, "rootResourcePath", text(r[1]));
        }
        const path = try w.a.print("/project/{s}/compile", .{id});
        const compiled = try w.post(path, "json", options, 240);
        const status = try string(compiled, "status");
        if (std.mem.eql(u8, status, "success")) return compiled;
        std.debug.print("test-overleaf: {s} compiled with status {s}\n", .{ path, status });
        return error.CompileFailed;
    }
};

fn answer(path: []const u8, response: Json) ![]const u8 {
    const status = response.object.get("status").?.integer;
    const body = response.object.get("body").?.string;
    if (status == 200) return body;
    std.debug.print("test-overleaf: {s} answered {d}: {s}\n", .{
        path, status, body[0..@min(body.len, 512)],
    });
    return error.Status;
}

fn string(value: Json, key: []const u8) ![]const u8 {
    if (value != .object) return error.Answer;
    const v = value.object.get(key) orelse return error.Answer;
    return if (v == .string) v.string else error.Answer;
}

/// objectId is an id as Overleaf names projects, users and files: 24 hex digits.
fn objectId(id: []const u8) ![]const u8 {
    if (id.len != 24) return error.ObjectId;
    for (id) |c| if (!std.ascii.isHex(c)) return error.ObjectId;
    return id;
}

fn token(page: []const u8) ![]const u8 {
    _, const rest = std.mem.cut(u8, page, "name=\"ol-csrfToken\" content=\"") orelse
        return error.CsrfToken;
    const value, _ = std.mem.cutScalar(u8, rest, '"') orelse return error.CsrfToken;
    return if (value.len > 0) value else error.CsrfToken;
}

/// logUrl is where Overleaf serves a compile's log.
fn logUrl(compiled: Json) ![]const u8 {
    const files = compiled.object.get("outputFiles") orelse return error.NoLog;
    if (files != .array) return error.NoLog;
    for (files.array.items) |file| {
        const path = string(file, "path") catch continue;
        if (std.mem.eql(u8, path, "output.log")) return string(file, "url");
    }
    return error.NoLog;
}

/// owner is the user whose compile a log is, which names its directory:
/// Overleaf serves it at /project/P/user/U/build/B/output/output.log.
fn owner(log_url: []const u8) ![]const u8 {
    _, const rest = std.mem.cut(u8, log_url, "/user/") orelse return error.LogUrl;
    const user, _ = std.mem.cutScalar(u8, rest, '/') orelse return error.LogUrl;
    return objectId(user);
}

fn logged(log: []const u8, word: []const u8, want: bool) !void {
    if ((std.mem.find(u8, log, word) != null) == want) return;
    std.debug.print("test-overleaf: the probe's log {s} {s}:\n{s}\n", .{
        if (want) "lacks" else "has", word, log[log.len - @min(log.len, 4096) ..],
    });
    return error.ProbeLog;
}

test "the log's URL names the compile's owner" {
    const t = std.testing;
    const compiled = try std.json.parseFromSlice(Json, t.allocator,
        \\{"status":"success","outputFiles":[
        \\{"path":"output.pdf","url":"/project/1/user/2/build/3/output/output.pdf"},
        \\{"path":"output.log","url":"/project/6a1f00000000000000000001/user/6a1f00000000000000000002/build/19a-7b/output/output.log"}]}
    , .{});
    defer compiled.deinit();
    const url = try logUrl(compiled.value);
    try t.expect(std.mem.endsWith(u8, url, "/output/output.log"));
    try t.expectEqualStrings("6a1f00000000000000000002", try owner(url));
    try t.expectError(error.LogUrl, owner("/project/6a1f00000000000000000001/output.log"));
    try t.expectError(error.ObjectId, owner("/project/x/user/../build/b/output/output.log"));
}

test "the CSRF token is the page's ol-csrfToken" {
    const t = std.testing;
    try t.expectEqualStrings("a-b_c", try token(
        \\<meta name="ol-csrfToken" content="a-b_c"><meta name="ol-user_id" content="x">
    ));
    try t.expectError(error.CsrfToken, token("<meta name=\"ol-csrfToken\" content=\"\">"));
    try t.expectError(error.CsrfToken, token("<html></html>"));
}
