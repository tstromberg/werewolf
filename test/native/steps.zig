//! steps checks a YAML suite's steps: each probe's request, the captures
//! and fixtures it selects, and the assertions its response must meet, as
//! probes.zig will run them. plan.zig checks the plan around them.

const std = @import("std");
const plan = @import("plan.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Json = std.json.Value;
const Check = plan.Check;
const Error = plan.Error;
const Driver = plan.Driver;
const Fixture = plan.Fixture;

const actions = [_][]const u8{
    "fetch", "file", "exec", "service", "listeners", "mount", "tree", "write", "tcp", "squat",
};
/// conversations are the probes that carry their expectations themselves.
const conversations = [_][]const u8{ "tcp", "squat" };
const refusals = [_][]const u8{ "EACCES", "EPERM", "EROFS" };
const read_only = [_][]const u8{ "GET", "HEAD", "OPTIONS" };
const methods = [_][]const u8{
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "PROPFIND",
};
const matchers = [_][]const u8{
    "equals", "not_equals", "contains", "contains_all", "contains_none", "absent",      "one_of",
    "min",    "max",        "matches",  "not_matches",  "count",         "occurrences", "type",
};
const types = [_][]const u8{ "null", "bool", "integer", "float", "string", "array", "object" };

/// capabilities are the kernel's, in bit order.
pub const capabilities = [_][]const u8{
    "chown",              "dac_override",   "dac_read_search", "fowner",     "fsetid",
    "kill",               "setgid",         "setuid",          "setpcap",    "linux_immutable",
    "net_bind_service",   "net_broadcast",  "net_admin",       "net_raw",    "ipc_lock",
    "ipc_owner",          "sys_module",     "sys_rawio",       "sys_chroot", "sys_ptrace",
    "sys_pacct",          "sys_admin",      "sys_boot",        "sys_nice",   "sys_resource",
    "sys_time",           "sys_tty_config", "mknod",           "lease",      "audit_write",
    "audit_control",      "setfcap",        "mac_override",    "mac_admin",  "syslog",
    "wake_alarm",         "block_suspend",  "audit_read",      "perfmon",    "bpf",
    "checkpoint_restore",
};

const expected = std.StaticStringMap([]const []const u8).initComptime(.{
    .{ "fetch", &[_][]const u8{ "status", "headers", "cookies", "body", "json" } },
    .{ "exec", &[_][]const u8{ "exit", "stdout", "stderr", "json" } },
    .{ "file", &[_][]const u8{
        "exists", "type", "uid",     "gid",      "mode", "size", "body",
        "json",   "link", "entries", "readable",
    } },
    .{ "service", &[_][]const u8{
        "user",    "uid",       "groups",   "capabilities",          "no_new_privileges",
        "seccomp", "processes", "pids_max", "bounding_capabilities", "connect_rules",
        "comm",    "cmdline",
    } },
    .{ "listeners", &[_][]const u8{ "contains", "absent", "equals" } },
    .{ "mount", &[_][]const u8{ "type", "source", "flags", "absent_flags" } },
    .{ "tree", &[_][]const u8{ "entries", "files", "type", "path", "name", "mode", "content" } },
    .{ "write", &[_][]const u8{"errno"} },
    .{ "tcp", &[_][]const u8{} },
    .{ "squat", &[_][]const u8{} },
});

/// sources are the probes whose responses a capture selector may take.
const sources = std.StaticStringMap([]const []const u8).initComptime(.{
    .{ "json", &[_][]const u8{ "fetch", "file", "exec" } },
    .{ "body", &[_][]const u8{ "fetch", "file" } },
    .{ "header", &[_][]const u8{"fetch"} },
    .{ "cookie", &[_][]const u8{"fetch"} },
    .{ "regex", &[_][]const u8{ "fetch", "file", "exec" } },
});

pub fn step(
    c: *Check,
    data: Json,
    d: Driver,
    phase_seconds: u16,
    index: usize,
    previous: *std.array_hash_map.String([]const u8),
    packages: *std.ArrayList([]const u8),
) Error!Json {
    try c.fields(data, &(actions ++ [_][]const u8{ "name", "expect", "await", "timeout" }), &.{});
    const s = data.object;
    var action: ?[]const u8 = null;
    for (actions) |a| if (s.contains(a)) {
        if (action != null) return c.fail("step needs exactly one probe", .{});
        action = a;
    };
    const probe = action orelse return c.fail("step needs exactly one probe", .{});
    if (plan.has(&conversations, probe)) {
        if (s.contains("expect")) return c.fail("{s} carries its expectations itself", .{probe});
    } else if (!s.contains("expect")) return c.fail("missing field expect", .{});
    const name = if (s.get("name")) |given| try c.identity(given) else try c.gpa.print(
        "step-{d}",
        .{index},
    );
    if (previous.contains(name)) return c.fail("duplicate step {s}", .{name});
    var request = s.get(probe).?;
    try references(c, &request, previous, d.config);
    const wait = if (s.get("await")) |given|
        plan.seconds(given, 0, phase_seconds) orelse
            return c.fail("await must fit within the phase timeout", .{})
    else
        0;
    const timeout = if (s.get("timeout")) |given|
        plan.seconds(given, 1, 300) orelse return c.fail("timeout must be 1s..300s", .{})
    else
        10;
    if (s.contains("timeout") and !plan.has(&.{ "fetch", "exec", "tree", "tcp" }, probe))
        return c.fail("timeout applies to fetch, exec, tree and tcp", .{});
    if (mem.eql(u8, probe, "fetch")) {
        try c.fields(request, &.{
            "url",       "path",    "method",        "headers", "json",    "body",
            "bearer",    "session", "authorization", "ca",      "resolve", "form",
            "multipart",
        }, &.{"url"});
        const r = request.object;
        const url = r.get("url").?;
        if (url != .string or !(mem.startsWith(u8, url.string, "http://") or
            mem.startsWith(u8, url.string, "https://")))
            return c.fail("fetch requires a literal HTTP(S) URL", .{});
        const method = r.get("method") orelse Json{ .string = "GET" };
        if (method != .string or !plan.has(&methods, method.string))
            return c.fail("invalid HTTP method", .{});
        var bodies: usize = 0;
        for ([_][]const u8{ "body", "json", "form", "multipart" }) |key| {
            if (r.contains(key)) bodies += 1;
        }
        if (bodies > 1) return c.fail("choose one request body", .{});
        const mutation = !plan.has(&read_only, method.string);
        // curl reads no body for HEAD, so an assertion on one holds whatever came.
        if (mem.eql(u8, method.string, "HEAD")) if (s.get("expect")) |e|
            if (e == .object and (e.object.contains("body") or e.object.contains("json")))
                return c.fail("HEAD reads no body: test its framing with tcp", .{});
        if (wait > 0 and mutation) return c.fail("await cannot repeat an HTTP mutation", .{});
        if (d.readiness and mutation)
            return c.fail("readiness requires read-only HTTP probes", .{});
        if (r.get("ca")) |ca| if (ca != .string or !plan.absolute(ca.string))
            return c.fail("expected explicit absolute path for ca", .{});
        try packages.append(c.gpa, "libcurl-openssl4");
        try fetch(c, r);
    } else if (mem.eql(u8, probe, "exec")) {
        try c.fields(request, &.{ "argv", "stdin", "env", "readonly" }, &.{"argv"});
        const r = request.object;
        const argv = r.get("argv").?;
        if (argv != .array or
            argv.array.items.len == 0) return c.fail("exec requires argv", .{});
        const client = argv.array.items[0];
        if (client != .string or !plan.absolute(client.string))
            return c.fail("exec requires an explicit absolute client path", .{});
        if (!plan.has(d.run, client.string))
            return c.fail("exec client must be declared in policy.run", .{});
        const readonly = r.get("readonly");
        if (readonly) |ro| if (ro != .bool) return c.fail("readonly must be boolean", .{});
        const declared = readonly != null and readonly.?.bool;
        if (wait > 0 and !declared)
            return c.fail("await requires a declared read-only client operation", .{});
        if (d.readiness and !declared)
            return c.fail("readiness requires a declared read-only client operation", .{});
        for (argv.array.items) |arg| try textInput(c, arg);
        if (r.get("stdin")) |stdin| try textInput(c, stdin);
        if (r.get("env")) |env| {
            try textMap(c, env, false);
            for (env.object.keys()) |key| if (key.len == 0 or
                !(std.ascii.isAlphabetic(key[0]) or key[0] == '_') or
                !plan.allIn(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"))
                return c.fail("invalid environment name {s}", .{key});
        }
    } else if (mem.eql(u8, probe, "file") or mem.eql(u8, probe, "mount")) {
        if (request != .string or !plan.absolute(request.string))
            return c.fail("expected explicit absolute path", .{});
    } else if (mem.eql(u8, probe, "service")) {
        _ = try c.identity(request);
    } else if (mem.eql(u8, probe, "tree")) {
        try tree(c, request);
    } else if (mem.eql(u8, probe, "write")) {
        if (wait > 0 or d.readiness)
            return c.fail("write attempts a mutation; it cannot repeat", .{});
        try write(c, request, d);
    } else if (mem.eql(u8, probe, "tcp")) {
        try tcp(c, &request, d, wait);
    } else if (mem.eql(u8, probe, "squat")) {
        if (wait > 0 or d.readiness)
            return c.fail("squat restarts its service; it cannot repeat or be readiness", .{});
        _ = try c.identity(request);
        if (!mem.eql(u8, d.user, "root") or !plan.has(d.run, "/usr/bin/sv") or
            !plan.has(d.run, "/usr/bin/drill"))
            return c.fail(
                "squat runs as root, with /usr/bin/sv and /usr/bin/drill in policy.run",
                .{},
            );
    } else {
        const protocol = if (request == .string) request.string else blk: {
            try c.fields(request, &.{ "protocol", "port" }, &.{ "protocol", "port" });
            if (!port(request.object.get("port").?)) return c.fail(
                "invalid listener port",
                .{},
            );
            const p = request.object.get("protocol").?;
            break :blk if (p == .string) p.string else "";
        };
        if (!plan.has(&.{ "tcp", "udp", "all" }, protocol))
            return c.fail("invalid listener protocol", .{});
    }
    var expect = s.get("expect") orelse Json{ .object = .empty };
    if (!plan.has(&conversations, probe)) {
        try references(c, &expect, previous, d.config);
        if (expect != .object or expect.object.count() == 0)
            return c.fail("expect must be a nonempty mapping", .{});
        try c.fields(expect, expected.get(probe).?, &.{});
        try expectations(c, probe, &expect);
    }
    // A leashed suite's own Landlock grants its path no write, so it refuses
    // any create with EACCES before the machine is asked; only a read-only
    // mount's EROFS, which the kernel returns first, is the machine's.
    if (mem.eql(u8, probe, "write") and !mem.eql(u8, d.user, "root")) {
        const errno = expect.object.get("errno").?;
        if (errno != .string or !mem.eql(u8, errno.string, "EROFS"))
            return c.fail(
                "a leashed write proves only EROFS: its own sandbox refuses the rest",
                .{},
            );
    }
    var out: std.json.ObjectMap = .empty;
    try out.put(c.gpa, "name", .{ .string = name });
    try out.put(c.gpa, "probe", .{ .string = probe });
    try out.put(c.gpa, "request", request);
    try out.put(c.gpa, "expect", expect);
    try out.put(c.gpa, "await_seconds", .{ .integer = wait });
    try out.put(c.gpa, "timeout_seconds", .{ .integer = timeout });
    try out.put(c.gpa, "line", .{ .integer = @intCast(c.line) });
    try previous.put(c.gpa, name, probe);
    return .{ .object = out };
}

fn fetch(c: *Check, r: std.json.ObjectMap) Error!void {
    const url = r.get("url").?.string;
    const parts = splitUrl(url) orelse
        return c.fail("URL needs hostname, no userinfo/fragment/control characters", .{});
    if (parts.port) |text| {
        const n = std.fmt.parseInt(u32, text, 10) catch 0;
        if (!plan.allIn(text, "0123456789") or n == 0 or n > 65535)
            return c.fail("invalid URL port", .{});
    }
    if (r.get("path")) |path| {
        if (!(parts.path.len == 0 or mem.eql(u8, parts.path, "/")) or
            mem.findAny(u8, url, "?#") != null)
            return c.fail("path requires a literal origin without path or query", .{});
        if (path != .array or path.array.items.len == 0 or path.array.items.len > 32)
            return c.fail("path requires 1..32 segments", .{});
        for (path.array.items, 0..) |part, i| {
            try textInput(c, part);
            if (part == .string and (part.string.len > 1024 or mem.eql(u8, part.string, ".") or
                mem.eql(u8, part.string, "..") or
                (part.string.len == 0 and i + 1 != path.array.items.len)))
                return c.fail("invalid path segment", .{});
        }
    }
    for ([_][]const u8{ "body", "bearer" }) |key| if (r.get(key)) |v| try textInput(c, v);
    if (r.get("authorization")) |auth| {
        try c.fields(auth, &.{ "scheme", "credentials" }, &.{ "scheme", "credentials" });
        const scheme = auth.object.get("scheme").?;
        if (scheme != .string or !token(scheme.string))
            return c.fail("invalid authorization scheme", .{});
        try textInput(c, auth.object.get("credentials").?);
    }
    if (r.get("session")) |session| _ = try c.identity(session);
    if (r.get("resolve")) |resolve| _ = try c.strings(resolve);
    var named = false;
    if (r.get("headers")) |headers| {
        try textMap(c, headers, true);
        for (headers.object.keys()) |key| named = named or
            std.ascii.eqlIgnoreCase(key, "authorization");
    }
    const sources_ = @as(usize, @intFromBool(r.contains("bearer"))) +
        @intFromBool(r.contains("authorization"));
    if (sources_ > 1 or (sources_ == 1 and named))
        return c.fail("choose one authorization source", .{});
    if (r.get("form")) |f| try textMap(c, f, false);
    if (r.get("multipart")) |multipart| {
        if (multipart != .object) return c.fail("multipart requires mapping", .{});
        for (multipart.object.values()) |v| {
            if (v == .object and v.object.contains("file")) {
                try c.fields(v, &.{ "file", "type", "filename" }, &.{"file"});
                const file = v.object.get("file").?;
                if (file != .string or !plan.absolute(file.string))
                    return c.fail("expected explicit absolute path for multipart file", .{});
                for ([_][]const u8{ "type", "filename" }) |key| if (v.object.get(key)) |t|
                    if (t != .string) return c.fail("expected NUL-free string", .{});
            } else try textInput(c, v);
        }
    }
    const method = r.get("method") orelse Json{ .string = "GET" };
    if (mem.eql(
        u8,
        method.string,
        "HEAD",
    )) for ([_][]const u8{ "body", "json", "form", "multipart" }) |key|
        if (r.contains(key)) return c.fail("HEAD cannot have a body", .{});
}

/// tree checks a tree probe's roots and the paths it allows.
fn tree(c: *Check, request: Json) Error!void {
    if (request == .string) {
        if (!plan.absolute(request.string)) return c.fail("expected explicit absolute path", .{});
        return;
    }
    try c.fields(request, &.{ "roots", "allow" }, &.{"roots"});
    const roots = try c.strings(request.object.get("roots").?);
    if (roots.len == 0 or roots.len > 16) return c.fail("tree requires 1..16 roots", .{});
    for (roots) |root| if (!plan.absolute(root))
        return c.fail("expected explicit absolute path", .{});
    if (request.object.get("allow")) |allow| {
        const patterns = try c.strings(allow);
        if (patterns.len == 0 or patterns.len > 16)
            return c.fail("allow requires 1..16 patterns", .{});
        for (patterns) |p| if (p.len == 0 or p.len > 512)
            return c.fail("allow patterns require 1..512 bytes", .{});
    }
}

/// write checks a write probe's path. A leashed suite's own sandbox must
/// not be what refuses it: its pledge writes, and its path is not hidden.
fn write(c: *Check, request: Json, d: Driver) Error!void {
    const path = if (request == .string) request else blk: {
        try c.fields(request, &.{ "path", "existing" }, &.{ "path", "existing" });
        const existing = request.object.get("existing").?;
        if (existing != .bool or !existing.bool) return c.fail("existing must be true", .{});
        break :blk request.object.get("path").?;
    };
    if (path != .string or !plan.absolute(path.string))
        return c.fail("expected explicit absolute path", .{});
    if (mem.eql(u8, d.user, "root")) return;
    var words = mem.tokenizeAny(u8, d.pledge, " \t\n\r");
    const writes = while (words.next()) |word| {
        if (mem.eql(u8, word, "wpath")) break true;
    } else false;
    if (!writes) return c.fail("write requires wpath in the suite's pledge", .{});
    for (d.read) |grant| if (mem.startsWith(u8, path.string, grant) and
        (path.string.len == grant.len or path.string[grant.len] == '/' or
            mem.endsWith(u8, grant, "/"))) return;
    return c.fail("write requires its path under one of the suite's read grants", .{});
}

/// tcp checks a conversation, and writes its pauses as seconds and its
/// close as a list.
fn tcp(c: *Check, request: *Json, d: Driver, wait: u16) Error!void {
    try c.fields(request.*, &.{ "connect", "unix", "tls", "ca", "readonly", "exchange" }, &.{
        "exchange",
    });
    const r = &request.object;
    if (r.contains("connect") == r.contains("unix"))
        return c.fail("tcp requires connect or unix", .{});
    if (r.get("connect")) |target| if (target != .string or !hostPort(target.string))
        return c.fail("connect requires HOST:PORT", .{});
    if (r.get("unix")) |path| if (path != .string or !plan.absolute(path.string) or
        path.string.len > 107)
        return c.fail("unix requires an absolute socket path of at most 107 bytes", .{});
    const security = r.get("tls");
    if (security) |t| {
        if (t != .string or !plan.has(&.{ "verify", "insecure" }, t.string))
            return c.fail("tls must be verify or insecure", .{});
        if (!r.contains("connect")) return c.fail("tls requires connect", .{});
    }
    if (r.get("ca")) |ca| {
        if (security == null or !mem.eql(u8, security.?.string, "verify"))
            return c.fail("ca requires tls: verify", .{});
        if (ca != .string or !plan.absolute(ca.string))
            return c.fail("expected explicit absolute path for ca", .{});
    }
    const readonly = r.get("readonly");
    if (readonly) |ro| if (ro != .bool) return c.fail("readonly must be boolean", .{});
    const declared = readonly != null and readonly.?.bool;
    if (wait > 0 and !declared)
        return c.fail("await requires a declared read-only conversation", .{});
    if (d.readiness and !declared)
        return c.fail("readiness requires a declared read-only conversation", .{});
    const exchange = r.getPtr("exchange").?;
    if (exchange.* != .array or exchange.array.items.len == 0 or exchange.array.items.len > 64)
        return c.fail("exchange requires 1..64 items", .{});
    const items = exchange.array.items;
    for (items, 0..) |*item, i| {
        if (item.* != .object or item.object.count() != 1)
            return c.fail("an exchange item is one send, pause, expect or close", .{});
        const kind = item.object.keys()[0];
        const v = item.object.getPtr(kind).?;
        if (mem.eql(u8, kind, "send")) {
            try needleInput(c, v.*);
        } else if (mem.eql(u8, kind, "pause")) {
            const n = plan.seconds(v.*, 1, 60) orelse return c.fail("pause must be 1s..60s", .{});
            v.* = .{ .integer = n };
        } else if (mem.eql(u8, kind, "expect")) {
            try c.fields(v.*, &.{ "prefix", "contains", "matches" }, &.{});
            if (v.object.count() == 0)
                return c.fail("expect requires prefix, contains or matches", .{});
            for ([_][]const u8{ "prefix", "contains" }) |key| if (v.object.get(key)) |text|
                try needleInput(c, text);
            if (v.object.get("matches")) |m| if (m != .string or m.string.len == 0 or
                m.string.len > 512) return c.fail("regex requires 1..512 bytes", .{});
        } else if (mem.eql(u8, kind, "close")) {
            if (i + 1 != items.len) return c.fail("close ends the exchange", .{});
            var one = [_]Json{v.*};
            const names: []Json = if (v.* == .array) v.array.items else &one;
            if (names.len == 0 or names.len > 2) return c.fail("close is eof, reset or both", .{});
            var list: std.json.Array = .init(c.gpa);
            for (names) |name| {
                if (name != .string or !plan.has(&.{ "eof", "reset" }, name.string) or
                    (list.items.len == 1 and mem.eql(u8, list.items[0].string, name.string)))
                    return c.fail("close is eof, reset or both", .{});
                try list.append(name);
            }
            v.* = .{ .array = list };
        } else return c.fail("an exchange item is one send, pause, expect or close", .{});
    }
}

/// hostPort is a literal address or a lowercase name, then a port.
pub fn hostPort(text: []const u8) bool {
    const colon = mem.findScalarLast(u8, text, ':') orelse return false;
    const digits = text[colon + 1 ..];
    const n = std.fmt.parseInt(u32, digits, 10) catch return false;
    if (!plan.allIn(digits, "0123456789") or digits[0] == '0' or n > 65535) return false;
    const host = text[0..colon];
    if (mem.startsWith(u8, host, "[") and mem.endsWith(u8, host, "]")) {
        _ = Io.net.Ip6Address.parse(host[1 .. host.len - 1], 0) catch return false;
        return true;
    }
    if (Io.net.Ip4Address.parse(host, 0)) |_| return true else |_| {}
    return host.len > 0 and host.len <= 253 and std.ascii.isAlphanumeric(host[0]) and
        plan.allIn(host, "abcdefghijklmnopqrstuvwxyz0123456789.-");
}

/// needleInput is text that must say something: literal bytes or a reference.
fn needleInput(c: *Check, v: Json) Error!void {
    try textInput(c, v);
    if (v == .string and (v.string.len == 0 or v.string.len > 4096))
        return c.fail("literal text requires 1..4096 bytes", .{});
}

/// references checks the run, step and fixture selectors in value, which
/// probes.zig resolves at run time, against what came before them.
fn references(
    c: *Check,
    item: *Json,
    previous: *const std.array_hash_map.String([]const u8),
    fixtures: []const Fixture,
) Error!void {
    switch (item.*) {
        .array => |items| for (items.items) |*v| try references(c, v, previous, fixtures),
        .object => |*o| {
            if (o.get("run")) |run| {
                try c.fields(item.*, &.{"run"}, &.{"run"});
                if (run != .bool or !run.bool) return c.fail("run selector must be true", .{});
            } else if (o.get("step")) |selected| {
                try c.fields(item.*, &.{
                    "step",
                    "json",
                    "header",
                    "cookie",
                    "body",
                    "regex",
                }, &.{
                    "step",
                });
                if (selected != .string or !previous.contains(selected.string) or
                    o.count() != 2)
                    return c.fail("capture must select an earlier named step", .{});
                const selector = if (mem.eql(u8, o.keys()[0], "step"))
                    o.keys()[1]
                else
                    o.keys()[0];
                if (!plan.has(sources.get(selector).?, previous.get(selected.string).?))
                    return c.fail(
                        "capture selector is unavailable for the selected probe",
                        .{},
                    );
                const v = o.get(selector).?;
                if (mem.eql(u8, selector, "json")) {
                    try pointer(c, v);
                } else if (mem.eql(u8, selector, "body")) {
                    if (v != .bool or !v.bool) return c.fail("body selector must be true", .{});
                } else if (mem.eql(u8, selector, "regex")) {
                    if (v != .string or v.string.len == 0 or v.string.len > 512)
                        return c.fail("capture regex requires 1..512 bytes", .{});
                } else {
                    if (v != .string) return c.fail("expected NUL-free string", .{});
                    // Response header names are lowercase.
                    if (mem.eql(u8, selector, "header"))
                        try o.put(c.gpa, "header", .{ .string = try std.ascii.allocLowerString(
                            c.gpa,
                            v.string,
                        ) });
                }
            } else if (o.get("fixture")) |fixture| {
                try c.fields(item.*, &.{ "fixture", "raw" }, &.{"fixture"});
                if (o.get("raw")) |raw| if (raw != .bool or !raw.bool)
                    return c.fail("raw fixture selector must be true", .{});
                const known = fixture == .string and for (fixtures) |f| {
                    if (mem.eql(u8, f.name, fixture.string)) break true;
                } else false;
                if (!known) return c.fail("unknown fixture", .{});
            } else for (o.values()) |*v| try references(c, v, previous, fixtures);
        },
        else => {},
    }
}

fn expectations(c: *Check, probe: []const u8, expect: *Json) Error!void {
    var it = expect.object.iterator();
    while (it.next()) |e| {
        const key = e.key_ptr.*;
        const v = e.value_ptr;
        if (mem.eql(u8, key, "json")) {
            if (v.* != .object or v.object.count() == 0)
                return c.fail("json requires pointer/assertion map", .{});
            var paths = v.object.iterator();
            while (paths.next()) |p| {
                try pointer(c, .{ .string = p.key_ptr.* });
                try matcher(c, p.value_ptr.*);
            }
        } else if (mem.eql(u8, key, "headers") or mem.eql(u8, key, "cookies")) {
            if (v.* != .object or v.object.count() == 0)
                return c.fail("{s} requires assertion map", .{key});
            for (v.object.keys(), v.object.values()) |name, comparison| {
                if (mem.eql(u8, key, "headers")) for (name) |ch| if (std.ascii.isUpper(ch))
                    return c.fail("response header names must be lowercase", .{});
                try textMatcher(c, comparison);
            }
        } else if (mem.eql(u8, key, "body") or mem.eql(u8, key, "stdout") or
            mem.eql(u8, key, "stderr"))
        {
            try textMatcher(c, v.*);
        } else if (mem.eql(u8, probe, "service") and mem.eql(u8, key, "user")) {
            if (!identifier(v.*)) return c.fail("invalid user", .{});
        } else if (mem.eql(u8, probe, "service") and mem.eql(u8, key, "groups")) {
            const members = if (v.* == .array) v.array.items else blk: {
                try c.fields(v.*, &.{ "contains", "absent" }, &.{});
                break :blk v.object.values();
            };
            for (members) |g| if (!identifier(g))
                return c.fail("groups requires group names or numeric IDs", .{});
        } else if (mem.eql(u8, probe, "mount") and
            (mem.eql(u8, key, "flags") or mem.eql(u8, key, "absent_flags")))
        {
            _ = try c.strings(v.*);
        } else if (mem.eql(u8, probe, "file") and mem.eql(u8, key, "readable")) {
            if (v.* != .bool) return c.fail("readable requires a boolean", .{});
        } else if (mem.eql(u8, probe, "service") and mem.eql(u8, key, "connect_rules") and
            v.* == .array)
        {
            // Declarations compare without order.
            const rules = try c.gpa.dupe([]const u8, try c.strings(v.*));
            mem.sort([]const u8, rules, {}, plan.lessThan);
            for (v.array.items, rules) |*item, rule| item.* = .{ .string = rule };
        } else if (mem.eql(u8, probe, "service") and v.* == .array and
            (mem.eql(u8, key, "capabilities") or mem.eql(u8, key, "bounding_capabilities")))
        {
            const names = try c.strings(v.*);
            var mask: i64 = 0;
            for (names, 0..) |name, i| {
                const bit = for (capabilities, 0..) |cap, b| {
                    if (mem.eql(u8, cap, name)) break b;
                } else return c.fail("invalid capability list", .{});
                if (plan.has(names[0..i], name)) return c.fail("invalid capability list", .{});
                mask |= @as(i64, 1) << @intCast(bit);
            }
            v.* = .{ .integer = mask };
        } else if (mem.eql(u8, probe, "listeners")) {
            try listeners(c, key, v);
        } else if (mem.eql(u8, probe, "tree") and mem.eql(u8, key, "content")) {
            // Files may be binary and large: only literal absence is searched.
            try c.fields(v.*, &.{ "absent", "contains_none" }, &.{});
            if (v.object.count() == 0)
                return c.fail("content requires absent or contains_none", .{});
            if (v.object.get("absent")) |needle| try needleInput(c, needle);
            if (v.object.get("contains_none")) |list| {
                if (list != .array or list.array.items.len == 0 or list.array.items.len > 16)
                    return c.fail("contains_none requires 1..16 strings", .{});
                for (list.array.items) |needle| try needleInput(c, needle);
            }
        } else if ((mem.eql(u8, probe, "tree") and !mem.eql(u8, key, "entries") and
            !mem.eql(u8, key, "files")) or (mem.eql(u8, probe, "service") and
            plan.has(&.{ "comm", "cmdline" }, key)))
        {
            try textMatcher(c, v.*);
        } else if (mem.eql(u8, probe, "write")) {
            const named = if (v.* == .object) blk: {
                try c.fields(v.*, &.{"one_of"}, &.{"one_of"});
                break :blk try c.strings(v.object.get("one_of").?);
            } else if (v.* == .string) &[_][]const u8{v.string} else &[_][]const u8{};
            if (named.len == 0) return c.fail("errno requires EACCES, EPERM or EROFS", .{});
            for (named) |name| if (!plan.has(&refusals, name))
                return c.fail("errno requires EACCES, EPERM or EROFS", .{});
        } else try matcher(c, v.*);
    }
}

fn listeners(c: *Check, comparison: []const u8, entries: *Json) Error!void {
    const equals = mem.eql(u8, comparison, "equals");
    if (entries.* != .array or (entries.array.items.len == 0 and !equals))
        return c.fail("listeners require nonempty patterns, or equals: []", .{});
    for (entries.array.items, 0..) |*entry, i| {
        try c.fields(entry.*, &.{ "protocol", "address", "port" }, if (equals)
            &.{ "protocol", "address", "port" }
        else
            &.{});
        const l = &entry.object;
        if (l.count() == 0) return c.fail("empty listener pattern", .{});
        if (l.get("protocol")) |p| if (p != .string or !plan.has(&.{ "tcp", "udp" }, p.string))
            return c.fail("invalid listener protocol", .{});
        if (l.get("port")) |p| if (!port(p)) return c.fail("invalid listener port", .{});
        if (l.get("address")) |a| try l.put(c.gpa, "address", .{
            .string = canonicalAddress(c.gpa, a) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidAddress => return c.fail("invalid listener address", .{}),
            },
        });
        for (entries.array.items[0..i]) |other| if (sameListener(other.object, l.*))
            return c.fail("duplicate listener", .{});
    }
}

pub fn matcher(c: *Check, v: Json) Error!void {
    if (v != .object) return;
    const named = for (v.object.keys()) |key| {
        if (plan.has(&matchers, key)) break true;
    } else false;
    // A literal object without matcher keys compares by equality.
    if (!named) return;
    try c.fields(v, &matchers, &.{});
    var it = v.object.iterator();
    while (it.next()) |e| {
        const key = e.key_ptr.*;
        const m = e.value_ptr.*;
        if (mem.eql(u8, key, "min") or mem.eql(u8, key, "max")) {
            if (m != .integer and
                m != .float) return c.fail("numeric matcher requires number", .{});
        } else if (mem.eql(u8, key, "count")) {
            if (m != .integer or m.integer < 0)
                return c.fail("count requires nonnegative integer", .{});
        } else if (mem.eql(u8, key, "one_of") or mem.eql(u8, key, "contains_all") or
            mem.eql(u8, key, "contains_none"))
        {
            if (m != .array or m.array.items.len == 0)
                return c.fail("{s} requires nonempty list", .{key});
        } else if (mem.eql(u8, key, "type")) {
            if (m != .string or
                !plan.has(&types, m.string)) return c.fail("invalid type matcher", .{});
        } else if (mem.eql(u8, key, "matches") or mem.eql(u8, key, "not_matches")) {
            if (m != .string or
                m.string.len > 512) return c.fail("regex exceeds 512 bytes", .{});
        } else if (mem.eql(u8, key, "occurrences")) {
            if (m != .object or m.object.count() == 0)
                return c.fail("occurrences requires literal strings and counts", .{});
            for (m.object.keys(), m.object.values()) |needle, count| if (needle.len == 0 or
                count != .integer or count.integer < 0)
                return c.fail(
                    "occurrences requires nonempty strings and nonnegative counts",
                    .{},
                );
        }
    }
}

pub fn textMatcher(c: *Check, v: Json) Error!void {
    switch (v) {
        .object => |o| {
            if (!o.contains("run") and !o.contains("step") and !o.contains("fixture")) {
                if (o.count() == 0) return c.fail("empty text matcher", .{});
                try c.fields(v, &matchers, &.{});
            }
            if (o.get("not_equals")) |other| try textInput(c, other);
        },
        .string, .null => {},
        else => return c.fail(
            "text assertion requires a string, null, reference or matcher",
            .{},
        ),
    }
    try matcher(c, v);
}

fn textInput(c: *Check, v: Json) Error!void {
    if (v == .object and (v.object.contains("step") or v.object.contains("fixture") or
        v.object.contains("run"))) return;
    if (v != .string) return c.fail("expected NUL-free string", .{});
}

fn textMap(c: *Check, v: Json, headers: bool) Error!void {
    if (v != .object) return c.fail("expected text mapping", .{});
    for (v.object.keys(), v.object.values()) |key, text| {
        if (headers and !token(key)) return c.fail("invalid header name {s}", .{key});
        try textInput(c, text);
        if (headers and text == .string and mem.findAny(u8, text.string, "\r\n") != null)
            return c.fail("invalid header value", .{});
    }
}

fn pointer(c: *Check, v: Json) Error!void {
    if (v != .string) return c.fail("expected NUL-free string", .{});
    const p = v.string;
    if (p.len > 0 and p[0] != '/') return c.fail("invalid JSON pointer {s}", .{p});
    for (p, 0..) |ch, i| if (ch == '~' and (i + 1 == p.len or (p[i + 1] != '0' and
        p[i + 1] != '1')))
        return c.fail("invalid JSON pointer {s}", .{p});
    var parts = mem.splitScalar(u8, p, '/');
    while (parts.next()) |part| if (part.len > 1024)
        return c.fail("JSON pointer segment too long", .{});
}

fn port(v: Json) bool {
    return v == .integer and v.integer >= 1 and v.integer <= 65535;
}

/// identifier is an account name or a numeric ID.
fn identifier(v: Json) bool {
    return (v == .integer and v.integer >= 0 and v.integer < 1 << 32) or
        (v == .string and plan.account(v.string));
}

/// token is an HTTP header name or authorization scheme.
fn token(s: []const u8) bool {
    return s.len > 0 and
        plan.allIn(
            s,
            "!#$%&'*+.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-",
        );
}

const Url = struct { path: []const u8, port: ?[]const u8 };

/// splitUrl splits an HTTP(S) URL as Python's urlsplit does, refusing one
/// without a host, with userinfo, a fragment, or a control character.
fn splitUrl(url: []const u8) ?Url {
    for (url) |ch| if (ch <= ' ' or ch == 0x7f) return null;
    const rest = url[mem.find(u8, url, "://").? + 3 ..];
    const end = mem.findAny(u8, rest, "/?#") orelse rest.len;
    const netloc = rest[0..end];
    if (mem.findScalar(u8, netloc, '@') != null) return null;
    if (mem.findScalar(u8, rest, '#')) |hash| if (hash + 1 < rest.len) return null;
    const after = rest[end..];
    const path = after[0 .. mem.findAny(u8, after, "?#") orelse after.len];
    var host = netloc;
    var port_text: []const u8 = "";
    if (mem.startsWith(u8, netloc, "[")) {
        const close = mem.findScalar(u8, netloc, ']') orelse return null;
        host = netloc[1..close];
        _ = Io.net.Ip6Address.parse(host, 0) catch return null;
        const tail = netloc[close + 1 ..];
        if (tail.len > 0 and tail[0] != ':') return null;
        if (tail.len > 0) port_text = tail[1..];
    } else {
        if (mem.findAny(u8, netloc, "[]") != null) return null;
        const colon = mem.findScalar(u8, netloc, ':');
        if (colon) |at| {
            host = netloc[0..at];
            port_text = netloc[at + 1 ..];
        }
    }
    if (host.len == 0) return null;
    return .{ .path = path, .port = if (port_text.len == 0) null else port_text };
}

/// canonicalAddress writes an address as the guest reports listeners:
/// dotted IPv4, or all eight IPv6 groups in hex without leading zeros.
fn canonicalAddress(gpa: Allocator, v: Json) error{ OutOfMemory, InvalidAddress }![]const u8 {
    if (v != .string) return error.InvalidAddress;
    if (Io.net.Ip4Address.parse(v.string, 0)) |a| {
        return gpa.print("{d}.{d}.{d}.{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] });
    } else |_| {}
    const a = Io.net.Ip6Address.parse(v.string, 0) catch return error.InvalidAddress;
    var out: std.ArrayList(u8) = .empty;
    for (0..8) |i| {
        if (i > 0) try out.append(gpa, ':');
        try out.print(gpa, "{x}", .{mem.readInt(u16, a.bytes[i * 2 ..][0..2], .big)});
    }
    return out.items;
}

fn sameListener(a: std.json.ObjectMap, b: std.json.ObjectMap) bool {
    if (a.count() != b.count()) return false;
    for (a.keys(), a.values()) |key, value| {
        const other = b.get(key) orelse return false;
        switch (value) {
            .string => |s| if (other != .string or !mem.eql(u8, s, other.string)) return false,
            .integer => |n| if (other != .integer or n != other.integer) return false,
            else => return false,
        }
    }
    return true;
}

const testing = std.testing;
const expectPlan = plan.expectPlan;
const expectRefused = plan.expectRefused;
const web = plan.web;
const firstStep = plan.firstStep;

test "fixed origins take bounded path segments" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{
        "path: a",
        "path: []",
        "path: [x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, " ++
            "x, " ++
            "x, x, x, x, x, x]",
        "path: ['..']",
        "path: ['.']",
        "path: ['', x]",
        "path: [42]",
        "path:\n                - [nested]",
    }) |path| try expectRefused(a, try web(a, try a.print(
        \\          - fetch:
        \\              url: http://localhost/
        \\              {s}
        \\            expect:
        \\              status: 200
    , .{path})), "");
    const long = try a.alloc(u8, 1025);
    @memset(long, 'x');
    try expectRefused(a, try web(a, try a.print(
        \\          - fetch:
        \\              url: http://localhost/
        \\              path: [{s}]
        \\            expect:
        \\              status: 200
    , .{long})), "invalid path segment");
    for ([_][]const u8{
        "http://localhost/base", "http://localhost/?", "http://localhost/#",
        "http://localhost/?q=1",
    }) |url| try expectRefused(a, try web(a, try a.print(
        \\          - fetch:
        \\              url: {s}
        \\              path: [api]
        \\            expect:
        \\              status: 200
    , .{url})), "literal origin");
    _ = try expectPlan(a, try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\              path: [api, '']
        \\            expect:
        \\              status: 200
    ));
}

test "assertions are typed matchers, and literal objects stay literal" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const long = try a.alloc(u8, 513);
    @memset(long, 'x');
    var refused: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "contains_all", "contains_none" }) |op| for ([_][]const u8{
        "x", "null", "[]", "{}", "42",
    }) |v| try refused.append(a, try a.print("json:\n                /items:\n" ++
        "                  {s}: {s}", .{ op, v }));
    for ([_][]const u8{ "false", "42", "null", "{}", "[]" }) |v|
        try refused.append(a, try a.print("body:\n                not_equals: {s}", .{v}));
    for ([_][]const u8{
        "matches",
        "not_matches",
    }) |op| for ([_][]const u8{ "3", "false", long }) |v|
        try refused.append(a, try a.print("body:\n                {s}: {s}", .{ op, v }));
    try refused.appendSlice(a, &.{
        "status:\n                one_of: 200",
        "json:\n                /bad~2key: true",
        "status:\n                min: 1\n                typo: 2",
        "status: 1152921504606846976",
        "status: .inf",
        "body:\n                occurrences:\n                  '': 0",
        "body:\n                occurrences:\n                  x: -1",
        "body:\n                occurrences:\n                  x: true",
        "body:\n                occurrences: {}",
        "{}",
        "unknown: 1",
    });
    for ([_][]const u8{ "body", "headers", "cookies" }) |field| for ([_][]const u8{
        "\n                not_contains: secret", " {}", " 3", " [secret]",
    }) |v| try refused.append(a, if (mem.eql(u8, field, "body"))
        try a.print("{s}:{s}", .{ field, v })
    else
        try a.print("{s}:\n                x-token:{s}", .{ field, v }));
    for (refused.items) |expect| try expectRefused(a, try web(a, try a.print(
        \\          - fetch:
        \\              url: http://localhost/
        \\            expect:
        \\              {s}
    , .{expect})), "");
    for ([_][]const u8{ "stdout", "stderr" }) |field| for ([_][]const u8{
        "\n                not_contains: secret", " {}", " 3", " [secret]",
    }) |v| try expectRefused(a, try web(a, try a.print(
        \\          - exec:
        \\              argv: [/usr/bin/client]
        \\            expect:
        \\              {s}:{s}
    , .{ field, v })), "");
    _ = try expectPlan(a, try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\            expect:
        \\              json:
        \\                /configuration:
        \\                  not_contains: a literal field
    ));
}

test "captures select an earlier step's field its probe has" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const long = try a.alloc(u8, 513);
    @memset(long, 'x');
    for ([_][]const u8{ "''", long, "3", "\n                  run: true" }) |pattern|
        try expectRefused(a, try web(a, try a.print(
            \\          - name: form
            \\            fetch:
            \\              url: http://localhost/
            \\            expect:
            \\              status: 200
            \\          - fetch:
            \\              url: http://localhost/
            \\              bearer:
            \\                step: form
            \\                regex: {s}
            \\            expect:
            \\              status: 200
        , .{pattern})), "");
    for ([_][]const u8{ "header: x-token", "cookie: session", "body: true" }) |selector|
        try expectRefused(a, try web(a, try a.print(
            \\          - name: client
            \\            exec:
            \\              argv: [/usr/bin/client]
            \\            expect:
            \\              exit: 0
            \\          - fetch:
            \\              url: http://localhost/
            \\              bearer:
            \\                step: client
            \\                {s}
            \\            expect:
            \\              status: 200
        , .{selector})), "unavailable for the selected probe");
    try expectRefused(a, try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\              bearer:
        \\                step: future
        \\                json: /token
        \\            expect:
        \\              status: 200
        \\          - name: future
        \\            fetch:
        \\              url: http://localhost/
        \\            expect:
        \\              status: 200
    ), "earlier named step");
    const loaded = try expectPlan(a, try web(a,
        \\          - name: login
        \\            fetch:
        \\              url: http://localhost/
        \\            expect:
        \\              status: 200
        \\          - fetch:
        \\              url: http://localhost/
        \\              bearer:
        \\                step: login
        \\                header: X-Token
        \\            expect:
        \\              status: 200
    ));
    const steps = loaded.drivers[0].probes.?.object.get("cases").?.array.items[0]
        .object.get("steps").?.array.items;
    try testing.expectEqualStrings("x-token", steps[1].object.get(
        "request",
    ).?.object.get("bearer").?
        .object.get("header").?.string);
    for ([_][]const u8{
        "false",
        "'true'",
        "1",
        "null",
    }) |raw| try expectRefused(a, try web(a, try a.print(
        \\          - fetch:
        \\              url: http://localhost/
        \\              method: POST
        \\              body:
        \\                fixture: password
        \\                raw: {s}
        \\            expect:
        \\              status: 200
    , .{raw})), "raw fixture selector must be true");
    try expectRefused(a, try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\              bearer:
        \\                fixture: missing
        \\            expect:
        \\              status: 200
    ), "unknown fixture");
}

test "a HEAD response's body is not asserted: curl never reads one" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const head =
        \\          - fetch:
        \\              url: http://127.0.0.1/
        \\              method: HEAD
        \\            expect:
        \\              status: 200
    ;
    _ = try expectPlan(a, try web(a, head));
    for ([_][]const u8{
        "              body: ''",
        "              json:\n                /a: 1",
    }) |e|
        try expectRefused(
            a,
            try web(a, try mem.concat(a, u8, &.{ head, "\n", e })),
            "HEAD reads no body",
        );
}

test "requests refuse injection, ambiguity and nested type errors" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][2][]const u8{
        .{ "url: http://localhost/\n              headers:\n                x: 3", "" },
        .{
            "url: http://localhost/\n              headers:\n" ++
                "                x: \"good\\r\\nbad:value\"",
            "",
        },
        .{ "url: 'http://user:secret@localhost/'", "userinfo" },
        .{ "url: http://localhost/\n              resolve: 127.0.0.1", "" },
        .{ "url: http://localhost/\n              multipart:\n                doc:\n" ++
            "                  file: relative", "absolute" },
        .{ "url: file:///etc/passwd", "literal HTTP(S) URL" },
        .{ "url: http://localhost:0/", "invalid URL port" },
        .{ "url: http://localhost:99999/", "invalid URL port" },
        .{ "url: http://:80/", "hostname" },
        .{ "url: http://localhost/x#frag", "fragment" },
        .{ "url: http://localhost/\n              method: TRACE", "invalid HTTP method" },
        .{ "url: http://localhost/\n              method: HEAD\n              body: x", "HEAD" },
        .{
            "url: http://localhost/\n              body: x\n" ++
                "              form:\n                q: x",
            "one request body",
        },
        .{ "url: http://localhost/\n              session: Bad", "identity" },
    }) |case| try expectRefused(a, try web(a, try a.print(
        \\          - fetch:
        \\              {s}
        \\            expect:
        \\              status: 200
    , .{case[0]})), case[1]);
    for ([_][]const u8{
        "authorization: null",
        "authorization: {}",
        "authorization:\n                scheme: Token",
        "authorization:\n                credentials: secret",
        "authorization:\n                scheme: Token bad\n                credentials: secret",
        "authorization:\n                scheme: \"Token\\r\\nInjected\"\n                " ++
            "credentials: secret",
        "authorization:\n                scheme: Token\n                credentials: 42",
        "authorization:\n                scheme: Token\n                credentials: secret\n" ++
            "                unknown: true",
        "authorization:\n                scheme: Token\n                credentials:\n" ++
            "                  fixture: password\n              bearer: other",
        "authorization:\n                scheme: Token\n                credentials:\n" ++
            "                  fixture: password\n              headers:\n" ++
            "                aUtHoRiZaTiOn: Token other",
    }) |auth| try expectRefused(a, try web(a, try a.print(
        \\          - fetch:
        \\              url: http://localhost/
        \\              {s}
        \\            expect:
        \\              status: 200
    , .{auth})), "");
    try expectRefused(a, try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\            unknown: typo
        \\            expect:
        \\              status: 200
    ), "unknown field unknown");
    try expectRefused(a, try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\            file: /etc/passwd
        \\            expect:
        \\              status: 200
    ), "exactly one probe");
}

test "polling repeats only reads, within the phase budget" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectRefused(a, try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\              method: POST
        \\            await: 1s
        \\            expect:
        \\              status: 200
    ), "await cannot repeat an HTTP mutation");
    try expectRefused(a, try web(a,
        \\          - exec:
        \\              argv: [/usr/bin/client]
        \\            await: 1s
        \\            expect:
        \\              exit: 0
    ), "read-only client operation");
    try expectRefused(a, try web(a,
        \\          - exec:
        \\              argv: [/usr/bin/other]
        \\            expect:
        \\              exit: 0
    ), "policy.run");
    const long = try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\            await: 900s
        \\            expect:
        \\              status: 200
    );
    try expectRefused(a, long, "await must fit within the phase timeout");
    const loaded = try expectPlan(a, try a.print("timeout: 1200s\n{s}", .{long}));
    try testing.expectEqual(1200, loaded.timeout_seconds);
    try testing.expectEqual(900, firstStep(loaded).get("await_seconds").?.integer);
    try expectRefused(
        a,
        try a.print("timeout: 1200s\n{s}", .{try mem.replaceOwned(u8, a, long, "900s", "1201s")}),
        "phase timeout",
    );
    for ([_][]const u8{ "0s", "1801s", "-1s", "1m", "1200", "true", "null", "'01s'" }) |v|
        try expectRefused(a, try a.print("timeout: {s}\n{s}", .{ v, long }), "phase timeout");
    const post = try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\              method: POST
        \\            timeout: 45s
        \\            expect:
        \\              status: 200
    );
    const first = firstStep(try expectPlan(a, post));
    try testing.expectEqual(45, first.get("timeout_seconds").?.integer);
    try testing.expectEqual(0, first.get("await_seconds").?.integer);
    for ([_][]const u8{ "0s", "301s", "-1s", "1m", "45", "true" }) |v| try expectRefused(
        a,
        try mem.replaceOwned(u8, a, post, "timeout: 45s", try a.print("timeout: {s}", .{v})),
        "timeout must be 1s..300s",
    );
    try expectRefused(
        a,
        try mem.replaceOwned(u8, a, post, "timeout: 45s", "timeout: 45s\n            await: 60s"),
        "await cannot repeat",
    );
    try expectRefused(a, try web(a,
        \\          - file: /etc/passwd
        \\            timeout: 1s
        \\            expect:
        \\              exists: true
    ), "timeout applies to fetch, exec, tree and tcp");
}

test "readiness suites run read-only probes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]struct { []const u8, bool }{
        .{ "          - fetch:\n              url: http://localhost/\n" ++
            "            expect:\n              status: 200", true },
        .{ "          - fetch:\n              url: http://localhost/\n              method: " ++
            "POST\n" ++
            "            expect:\n              status: 200", false },
        .{ "          - exec:\n              argv: [/usr/bin/client]\n              readonly: " ++
            "true\n" ++
            "            expect:\n              exit: 0", true },
        .{ "          - exec:\n              argv: [/usr/bin/client]\n" ++
            "            expect:\n              exit: 0", false },
    }) |case| {
        const text = try mem.replaceOwned(
            u8,
            a,
            try web(a, case[0]),
            "  - name: web\n",
            "  - name: web\n    readiness: true\n",
        );
        if (case[1]) {
            try testing.expect((try expectPlan(a, text)).drivers[0].readiness);
        } else try expectRefused(a, text, "read-only");
    }
    for ([_][]const u8{ "1", "'true'", "null" }) |v| try expectRefused(
        a,
        try mem.replaceOwned(u8, a, try web(a,
            \\          - fetch:
            \\              url: http://localhost/
            \\            expect:
            \\              status: 200
        ), "  - name: web\n", try a.print("  - name: web\n    readiness: {s}\n", .{v})),
        "boolean",
    );
}

test "listeners, services, files and mounts take their own assertions" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]struct { []const u8, bool }{
        .{ "absent:\n                - port: 5432", true },
        .{ "contains:\n                - address: 127.0.0.1\n                  port: 8080", true },
        .{ "equals: []", true },
        .{ "absent: []", false },
        .{ "contains:\n                - {}", false },
        .{ "equals:\n                - port: 5432", false },
        .{ "contains:\n                - address: 127.000.0.1", false },
        .{ "contains:\n                - port: 1\n                - port: 1", false },
    }) |case| {
        const text = try web(a, try a.print(
            \\          - listeners: tcp
            \\            expect:
            \\              {s}
        , .{case[0]}));
        if (case[1]) _ = try expectPlan(a, text) else try expectRefused(a, text, "");
    }
    const scoped = try expectPlan(a, try web(a,
        \\          - listeners:
        \\              protocol: tcp
        \\              port: 11434
        \\            expect:
        \\              equals:
        \\                - protocol: tcp
        \\                  address: '::1'
        \\                  port: 11434
    ));
    try testing.expectEqualStrings("0:0:0:0:0:0:0:1", firstStep(scoped).get("expect").?.object
        .get("equals").?.array.items[0].object.get("address").?.string);
    for ([_][]const u8{
        "port: 11434",
        "protocol: tcp",
        "protocol: unix\n                port: 11434",
        "protocol: tcp\n                port: '11434'",
        "protocol: tcp\n                port: false",
        "protocol: tcp\n                port: 0",
        "protocol: tcp\n                port: 65536",
        "protocol: tcp\n                port: 11434\n                ignore: true",
    }) |request| try expectRefused(a, try web(a, try a.print(
        \\          - listeners:
        \\              {s}
        \\            expect:
        \\              equals: []
    , .{request})), "");
    const rules = try expectPlan(a, try web(a,
        \\          - service: app
        \\            expect:
        \\              connect_rules: [udp/53, tcp/443 public]
        \\              capabilities: [net_raw, chown]
    ));
    const expect = firstStep(rules).get("expect").?.object;
    try testing.expectEqualStrings(
        "tcp/443 public",
        expect.get("connect_rules").?.array.items[0].string,
    );
    try testing.expectEqual((1 << 13) | 1, expect.get("capabilities").?.integer);
    for ([_][]const u8{
        "connect_rules: [tcp/443 public, 443]",
        "capabilities: [net_raw, net_raw]",
        "capabilities: [cap_net_raw]",
        "user: Bad",
        "user: 4294967296",
        "groups:\n                contains: [a, b]",
        "groups:\n                other: a",
    }) |e| try expectRefused(a, try web(a, try a.print(
        \\          - service: app
        \\            expect:
        \\              {s}
    , .{e})), "");
    _ = try expectPlan(a, try web(a,
        \\          - file: /run/config/app/secret
        \\            expect:
        \\              readable: false
    ));
    for ([_][]const u8{ "null", "0", "'false'", "\n                equals: false" }) |v|
        try expectRefused(a, try web(a, try a.print(
            \\          - file: /run/config/app/secret
            \\            expect:
            \\              readable: {s}
        , .{v})), "readable requires a boolean");
    for ([_][]const u8{ "file: relative", "file: /a/../b", "mount: x", "service: Bad" }) |probe|
        try expectRefused(a, try web(a, try a.print(
            \\          - {s}
            \\            expect:
            \\              exists: true
        , .{probe})), "");
}

test "trees take absolute roots, allow patterns and per-entry rules" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kafka = try expectPlan(a, try web(a,
        \\          - tree:
        \\              roots: [/data/svc/kafka, /run/svc/kafka]
        \\              allow: ['^log/[^/]+-[0-9]+/']
        \\            timeout: 60s
        \\            await: 30s
        \\            expect:
        \\              files:
        \\                min: 1
        \\              path:
        \\                not_matches: '\.log$'
        \\              content:
        \\                contains_none:
        \\                  - werewolf-check
        \\                  - fixture: password
    ));
    try testing.expectEqual(60, firstStep(kafka).get("timeout_seconds").?.integer);
    for ([_][]const u8{
        "tree: relative\n            expect:\n              files: 1",
        "tree:\n              roots: []\n            expect:\n              files: 1",
        "tree:\n              roots: [/a]\n              allow: ['']\n            expect:\n" ++
            "              files: 1",
        "tree:\n              root: /a\n            expect:\n              files: 1",
        "tree: /a\n            expect:\n              size: 1",
        "tree: /a\n            expect:\n              content: secret",
        "tree: /a\n            expect:\n              content:\n                matches: x",
        "tree: /a\n            expect:\n              content:\n                absent: ''",
        "tree: /a\n            expect:\n              name: 3",
    }) |probe| try expectRefused(a, try web(a, try a.print("          - {s}", .{probe})), "");
}

test "writes expect a refusal, once, that the suite's sandbox does not cause" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    _ = try expectPlan(a, try web(a,
        \\          - write:
        \\              path: /usr/share/suricata/rules/werewolf.rules
        \\              existing: true
        \\            expect:
        \\              errno: EROFS
    ));
    for ([_][]const u8{
        "errno: ENOENT",
        "errno:\n                one_of: [EACCES, ENOENT]",
        "errno:\n                not_equals: EROFS",
    }) |e| try expectRefused(a, try web(a, try a.print(
        \\          - write: /usr/share/app/x
        \\            expect:
        \\              {s}
    , .{e})), "");
    try expectRefused(a, try web(a,
        \\          - write: /usr/share/app/x
        \\            await: 5s
        \\            expect:
        \\              errno: EROFS
    ), "cannot repeat");
    const leashed = try mem.replaceOwned(u8, a, try web(a,
        \\          - write: /usr/share/app/x
        \\            expect:
        \\              errno: EROFS
    ), "    policy:\n", "    user: app\n    policy:\n      pledge: stdio rpath wpath\n" ++
        "      read: [/usr/share/app]\n");
    _ = try expectPlan(a, leashed);
    // Its own sandbox would refuse the rest, whatever the machine allows.
    for ([_][]const u8{ "errno: EACCES", "errno:\n                one_of: [EACCES, EROFS]" }) |e|
        try expectRefused(a, try mem.replaceOwned(u8, a, leashed, "errno: EROFS", e), "only EROFS");
    try expectRefused(a, try mem.replaceOwned(u8, a, leashed, "rpath wpath", "rpath"), "wpath");
    try expectRefused(
        a,
        try mem.replaceOwned(u8, a, leashed, "[/usr/share/app]", "[/usr/share/application]"),
        "read grants",
    );
}

test "a conversation sends, expects, pauses and may end with a close" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ruby = try expectPlan(a, try web(a,
        \\          - tcp:
        \\              connect: 127.0.0.1:8080
        \\              readonly: true
        \\              exchange:
        \\                - send: "GET / HTTP/1.1\r\nHost: localhost\r\n"
        \\                - pause: 1s
        \\                - send:
        \\                    fixture: password
        \\                - expect:
        \\                    prefix: "HTTP/1.1 200 OK\r\n"
        \\                    matches: 'answering\n$'
        \\                - close: eof
        \\            await: 10s
    ));
    const exchange = firstStep(ruby).get("request").?.object.get("exchange").?.array.items;
    try testing.expectEqual(1, exchange[1].object.get("pause").?.integer);
    try testing.expectEqualStrings("eof", exchange[4].object.get("close").?.array.items[0].string);
    try testing.expectEqual(0, firstStep(ruby).get("expect").?.object.count());
    _ = try expectPlan(a, try web(a,
        \\          - tcp:
        \\              unix: /run/svc/gvmd/run/gvmd.sock
        \\              exchange:
        \\                - send: <get_version/>
        \\                - expect:
        \\                    contains: </get_version_response>
    ));
    _ = try expectPlan(a, try web(a,
        \\          - tcp:
        \\              connect: '[::1]:443'
        \\              tls: verify
        \\              ca: /run/config/app/ca
        \\              exchange:
        \\                - close: [eof, reset]
    ));
    for ([_][]const u8{
        "connect: 127.0.0.1",
        "connect: 127.0.0.1:0",
        "connect: 127.0.0.1:08",
        "connect: 'Local:80'",
        "connect: '::1:80'",
        "unix: relative",
        "connect: localhost:80\n              unix: /run/x",
        "connect: localhost:80\n              tls: maybe",
        "connect: localhost:80\n              tls: insecure\n              ca: /ca",
        "unix: /run/x\n              tls: insecure",
    }) |target| try expectRefused(a, try web(a, try a.print(
        \\          - tcp:
        \\              {s}
        \\              exchange:
        \\                - send: x
    , .{target})), "");
    for ([_][]const u8{
        "- send: ''",
        "- send: 3",
        "- pause: 0s",
        "- pause: 1m",
        "- expect: {}",
        "- expect:\n                    matches: ''",
        "- expect:\n                    not_matches: x",
        "- close: open",
        "- close: [eof, eof]",
        "- close: eof\n                - send: x",
        "- send: x\n                  expect:\n                    prefix: y",
        "- shout: x",
    }) |item| try expectRefused(a, try web(a, try a.print(
        \\          - tcp:
        \\              connect: localhost:80
        \\              exchange:
        \\                {s}
    , .{item})), "");
    try expectRefused(a, try web(a,
        \\          - tcp:
        \\              connect: localhost:80
        \\              exchange:
        \\                - send: QUIT
        \\            await: 5s
    ), "read-only conversation");
    try expectRefused(a, try web(a,
        \\          - tcp:
        \\              connect: localhost:80
        \\              exchange:
        \\                - send: QUIT
        \\            expect:
        \\              status: 200
    ), "carries its expectations itself");
}

test "squat attacks a named service as root, never as readiness" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dns = try mem.replaceOwned(u8, a, try web(a,
        \\          - squat: blocky
    ), "run: [/usr/bin/client]", "run: [/usr/bin/sv, /usr/bin/drill]");
    _ = try expectPlan(a, dns);
    try expectRefused(a, try web(a, "          - squat: blocky"), "policy.run");
    try expectRefused(
        a,
        try mem.replaceOwned(u8, a, dns, "    policy:\n", "    user: app\n    policy:\n"),
        "as root",
    );
    try expectRefused(
        a,
        try mem.replaceOwned(u8, a, dns, "  - name: web\n", "  - name: web\n    readiness: true\n"),
        "readiness",
    );
    try expectRefused(a, try mem.replaceOwned(u8, a, dns, "squat: blocky", "squat: Blocky"), "");
}

test "services match their members' commands as text; environ is not readable" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    _ = try expectPlan(a, try web(a,
        \\          - service: misp
        \\            expect:
        \\              comm:
        \\                matches: "(^|\n)misp-serve(\n|$)"
        \\              cmdline:
        \\                contains: /usr/lib/werewolf/feed-run
    ));
    for ([_][]const u8{
        "comm: [misp-serve]",
        "environ:\n                absent: ADMIN_PASSWORD",
        "cmdline:\n                typo: 1",
    }) |e|
        try expectRefused(a, try web(a, try a.print(
            \\          - service: misp
            \\            expect:
            \\              {s}
        , .{e})), "");
}
