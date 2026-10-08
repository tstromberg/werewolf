//! Settings: the values a service takes from one machine's config tar,
//! declared in its service file and rendered into what its daemon reads
//! (docs/design/settings.md).
//!
//!     setting NAME TYPE[...] [required] [as KEY]
//!     render  FORMAT FILE [from PATH]
//!
//! The declarations come from the verified image; the values from
//! settings.json in the tar. A value can fill a declared key with a value
//! of the declared type, and do nothing else: it cannot name a key, and no
//! type's alphabet holds the delimiters of a format it may be rendered in,
//! so nothing is ever quoted. leash parses the declarations, service-config
//! renders them, and the host's howl checks with the same functions.

const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;
const Ip4Address = std.Io.net.Ip4Address;
const Ip6Address = std.Io.net.Ip6Address;

pub const max_settings = 32;
pub const max_values = 32;
pub const max_input = 32 << 10;
const max_string = 1 << 10;
const max_url = 2 << 10;

/// What a setting holds. Named as Go's net/netip names them, where it has
/// a name.
pub const Type = enum {
    /// A literal IPv4 or IPv6 address, without a zone.
    ip,
    /// A network: no host bits, and not /0.
    cidr,
    /// A literal address and port: 10.0.0.1:22, [fd00::1]:22.
    addrport,
    /// A hostname or literal address, and a port.
    hostport,
    /// RFC 1123, at most 253 bytes, without a trailing dot.
    hostname,
    /// 1 to 65535, a JSON number.
    port,
    /// http or https, without a user or password.
    url,
    /// A signed 64-bit JSON number.
    int,
    /// JSON true or false.
    bool,
    /// Printable UTF-8 without control characters, at most 1 KiB.
    string,
};

pub const Format = enum {
    /// KEY=VALUE lines, a list joined by commas: leash adds them to the
    /// service's environment.
    env,
    /// One JSON object; with `from`, the image's object, its declared keys
    /// replaced. A key with dots, a.b.c, is a path into nested objects.
    json,
    /// KEY VALUE... lines, a list joined by spaces, a bool yes or no.
    conf,
};

pub const Setting = struct {
    name: []const u8,
    type: Type,
    list: bool = false,
    required: bool = false,
    /// From `as`; else filled in by `declare`, from the name.
    key: ?[]const u8 = null,
};

pub const Render = struct {
    format: Format,
    file: []const u8,
    from: ?[]const u8 = null,
};

/// The name the copy of settings.json takes in the service's directory.
pub const input_file = "settings";

/// `setting NAME TYPE[...] [required] [as KEY]`, without its key word.
/// On error, why says what is wrong.
pub fn parseSetting(args: []const []const u8, why: *[]const u8) error{Invalid}!Setting {
    if (args.len < 2) return fail(why, "setting takes NAME and TYPE");
    if (!isName(args[0])) return fail(why, "a setting's name is [a-z][a-z0-9-]*, at most 32");
    const list = std.mem.endsWith(u8, args[1], "...");
    const type_name = if (list) args[1][0 .. args[1].len - 3] else args[1];
    const t = std.meta.stringToEnum(Type, type_name) orelse return fail(
        why,
        "no such type: ip cidr addrport hostport hostname port url int bool string",
    );
    if (list and (t == .int or t == .bool)) return fail(why, "an int or bool is not a list");
    var s: Setting = .{ .name = args[0], .type = t, .list = list };
    var rest = args[2..];
    if (rest.len > 0 and std.mem.eql(u8, rest[0], "required")) {
        s.required = true;
        rest = rest[1..];
    }
    if (rest.len == 2 and std.mem.eql(u8, rest[0], "as")) {
        s.key = rest[1];
    } else if (rest.len != 0) return fail(why, "after the type: [required] [as KEY]");
    return s;
}

/// `render FORMAT FILE [from PATH]`, without its key word.
pub fn parseRender(args: []const []const u8, why: *[]const u8) error{Invalid}!Render {
    if (args.len != 2 and args.len != 4) return fail(why, "render takes FORMAT FILE [from PATH]");
    const format = std.meta.stringToEnum(Format, args[0]) orelse
        return fail(why, "no such format: env json conf");
    if (!isFile(args[1])) return fail(why, "render's file is a name in the service's directory");
    if (std.mem.eql(u8, args[1], input_file)) return fail(why, "settings is the input's name");
    var r: Render = .{ .format = format, .file = args[1] };
    if (args.len == 4) {
        if (!std.mem.eql(u8, args[2], "from"))
            return fail(why, "render takes FORMAT FILE [from PATH]");
        if (format != .json) return fail(why, "from is for json");
        if (!isCleanPath(args[3])) return fail(why, "from takes an absolute path, without . or ..");
        r.from = args[3];
    }
    return r;
}

/// Check a service's declarations together and fill in each key: no name
/// or key twice, at most max_settings, and no type in a format that cannot
/// hold it.
pub fn declare(
    gpa: Allocator,
    settings: []Setting,
    r: Render,
    why: *[]const u8,
) error{ Invalid, OutOfMemory }!void {
    if (settings.len == 0) return fail(why, "render without a setting");
    if (settings.len > max_settings) return fail(why, "at most 32 settings");
    for (settings) |*s| {
        if (s.key == null) s.key = switch (r.format) {
            .env => try envName(gpa, s.name),
            .json, .conf => s.name,
        };
        const key = s.key.?;
        switch (r.format) {
            .env => {
                if (!isVariable(key)) return fail(why, "an env key is [A-Za-z_][A-Za-z0-9_]*");
                if (std.mem.eql(u8, key, "PATH") or std.mem.startsWith(u8, key, "LD_"))
                    return fail(why, "PATH and LD_* are not settings");
                if (s.list and (s.type == .string or s.type == .url))
                    return fail(
                        why,
                        "env joins a list with commas, which a string or url may hold",
                    );
            },
            .conf => {
                if (!isKey(key)) return fail(why, "a conf key is [A-Za-z0-9_.:-]+, at most 64");
                if (s.type == .string or s.type == .url)
                    return fail(why, "conf cannot hold a string or url: a space or # would end it");
            },
            .json => if (!isKey(key)) return fail(
                why,
                "a json key is [A-Za-z0-9_.:-]+, at most 64",
            ),
        }
    }
    for (settings, 0..) |a, i| for (settings[0..i]) |b| {
        if (std.mem.eql(u8, a.name, b.name)) return fail(why, "a setting is declared twice");
        if (std.mem.eql(u8, a.key.?, b.key.?)) return fail(why, "two settings have one key");
    };
}

/// Where a value was refused, and why. Never the value: settings are not
/// secret, but one put there by mistake should not reach a console.
pub const Diagnostic = struct {
    setting: []const u8 = "",
    index: ?usize = null,
    why: []const u8 = "",
};

/// settings.json, checked against the declarations: one value per setting,
/// null where it is absent. An empty list is absent.
pub fn parseValues(
    gpa: Allocator,
    settings: []const Setting,
    input: []const u8,
    diag: *Diagnostic,
) error{ Invalid, OutOfMemory }![]const ?json.Value {
    if (input.len > max_input) return refuse(diag, "", null, "settings.json is over 32 KiB");
    const doc = json.parseFromSliceLeaky(json.Value, gpa, input, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.DuplicateField => return refuse(diag, "", null, "a key is given twice"),
        else => return refuse(diag, "", null, "settings.json is not JSON"),
    };
    if (doc != .object) return refuse(diag, "", null, "settings.json is not an object");
    const values = try gpa.alloc(?json.Value, settings.len);
    @memset(values, null);
    var it = doc.object.iterator();
    while (it.next()) |e| {
        const i = for (settings, 0..) |s, i| {
            if (std.mem.eql(u8, s.name, e.key_ptr.*)) break i;
        } else
            // Named only if it could be a setting's name: nothing from
            // outside the image reaches a log unchecked, nor at any length.
            return if (isName(e.key_ptr.*))
                refuse(diag, e.key_ptr.*, null, "not a setting of this service")
            else
                refuse(diag, "", null, "a key that is not a setting name");
        const s = settings[i];
        const v = e.value_ptr.*;
        if (s.list) {
            if (v != .array) return refuse(diag, s.name, null, "not a list");
            if (v.array.items.len > max_values) return refuse(
                diag,
                s.name,
                null,
                "more than 32 values",
            );
            for (v.array.items, 0..) |item, n| if (reason(s.type, item)) |r|
                return refuse(diag, s.name, n, r);
            if (v.array.items.len > 0) values[i] = v;
        } else {
            if (reason(s.type, v)) |r| return refuse(diag, s.name, null, r);
            values[i] = v;
        }
    }
    for (settings, values) |s, v| if (s.required and v == null)
        return refuse(diag, s.name, null, "required");
    return values;
}

/// What the daemon reads, from checked values. base is the `from` file's
/// contents, for json.
pub fn render(
    gpa: Allocator,
    settings: []const Setting,
    r: Render,
    values: []const ?json.Value,
    base: ?[]const u8,
) error{ Invalid, OutOfMemory }![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    switch (r.format) {
        .env, .conf => for (settings, values) |s, value| {
            const v = value orelse continue;
            try out.appendSlice(gpa, s.key.?);
            try out.append(gpa, if (r.format == .env) '=' else ' ');
            const items: []const json.Value = if (s.list) v.array.items else &.{v};
            for (items, 0..) |item, n| {
                if (n > 0) try out.append(gpa, if (r.format == .env) ',' else ' ');
                try appendText(gpa, &out, item, r.format);
            }
            try out.append(gpa, '\n');
        },
        .json => {
            var obj: json.ObjectMap = .empty;
            if (base) |text| {
                const doc = json.parseFromSliceLeaky(json.Value, gpa, text, .{}) catch |err|
                    switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.Invalid,
                    };
                if (doc != .object) return error.Invalid;
                obj = doc.object;
            }
            for (settings, values) |s, value| {
                const v = value orelse continue;
                // A key with dots is a path into the object, a.b.c: each
                // part but the last an object, made where the base has
                // none, so a setting can fill a key the daemon nests.
                var target = &obj;
                var parts = std.mem.splitScalar(u8, s.key.?, '.');
                var last = parts.first();
                while (parts.next()) |part| {
                    const slot = try target.getOrPut(gpa, last);
                    if (!slot.found_existing) slot.value_ptr.* = .{ .object = .empty };
                    if (slot.value_ptr.* != .object) return error.Invalid;
                    target = &slot.value_ptr.object;
                    last = part;
                }
                try target.put(gpa, last, v);
            }
            const doc: json.Value = .{ .object = obj };
            try out.appendSlice(gpa, try json.Stringify.valueAlloc(gpa, doc, .{}));
            try out.append(gpa, '\n');
        },
    }
    return out.items;
}

/// An env file service-config rendered, read back by leash: only declared
/// keys, once each, values without control characters.
pub fn parseEnv(
    gpa: Allocator,
    settings: []const Setting,
    text: []const u8,
) error{ Invalid, OutOfMemory }![]const [2][]const u8 {
    var vars: std.ArrayList([2][]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const eq = std.mem.findScalar(u8, line, '=') orelse return error.Invalid;
        const key = line[0..eq];
        const value = line[eq + 1 ..];
        for (settings) |s| {
            if (std.mem.eql(u8, s.key.?, key)) break;
        } else return error.Invalid;
        for (vars.items) |v| if (std.mem.eql(u8, v[0], key)) return error.Invalid;
        for (value) |c| if (c < 0x20 or c == 0x7f) return error.Invalid;
        try vars.append(gpa, .{ key, value });
    }
    return vars.items;
}

/// A value given as text, as the host's flags give it, made the JSON value
/// settings.json carries. Null, with why set, if it is not of the type.
pub fn fromText(t: Type, text: []const u8, why: *[]const u8) ?json.Value {
    const v: json.Value = switch (t) {
        .port, .int => .{ .integer = std.fmt.parseInt(i64, text, 10) catch {
            why.* = "not a decimal number";
            return null;
        } },
        .bool => if (std.mem.eql(u8, text, "true"))
            .{ .bool = true }
        else if (std.mem.eql(u8, text, "false"))
            .{ .bool = false }
        else {
            why.* = "not true or false";
            return null;
        },
        else => .{ .string = text },
    };
    if (reason(t, v)) |r| {
        why.* = r;
        return null;
    }
    return v;
}

/// Why v is not a value of type t, or null if it is.
pub fn reason(t: Type, v: json.Value) ?[]const u8 {
    switch (t) {
        .int => return if (v == .integer) null else "not a whole number",
        .bool => return if (v == .bool) null else "not true or false",
        .port => {
            if (v != .integer) return "not a port number";
            return if (v.integer >= 1 and v.integer <= 65535) null else "a port is 1 to 65535";
        },
        else => {},
    }
    if (v != .string) return "not a string";
    const s = v.string;
    return switch (t) {
        .ip => if (ip(s)) null else "not a literal address",
        .cidr => cidr(s),
        .addrport => if (addrport(s)) null else "not a literal address and port",
        .hostport => if (hostport(s)) null else "not a host and port",
        .hostname => if (hostname(s)) null else "not a hostname",
        .url => url(s),
        .string => string(s),
        .int, .bool, .port => unreachable,
    };
}

fn ip(s: []const u8) bool {
    if (std.mem.findScalar(u8, s, ':') != null)
        _ = Ip6Address.parse(s, 0) catch return false
    else
        _ = Ip4Address.parse(s, 0) catch return false;
    return true;
}

fn cidr(s: []const u8) ?[]const u8 {
    const slash = std.mem.findScalar(u8, s, '/') orelse return "not a network";
    const bits_text = s[slash + 1 ..];
    if (bits_text.len == 0 or bits_text.len > 3) return "not a network";
    for (bits_text) |c| if (!std.ascii.isDigit(c)) return "not a network";
    const bits = std.fmt.parseInt(u8, bits_text, 10) catch return "not a network";
    var buf: [16]u8 = undefined;
    const bytes: []const u8 = if (std.mem.findScalar(u8, s[0..slash], ':') != null) b: {
        buf = (Ip6Address.parse(s[0..slash], 0) catch return "not a network").bytes;
        break :b &buf;
    } else b: {
        buf[0..4].* = (Ip4Address.parse(s[0..slash], 0) catch return "not a network").bytes;
        break :b buf[0..4];
    };
    if (bits > bytes.len * 8) return "not a network";
    // A setting that means everything is not a setting.
    if (bits == 0) return "a default route";
    for (bytes, 0..) |byte, i| {
        const used = @min(@as(usize, bits) -| (i * 8), 8);
        const mask: u8 = if (used == 8) 0 else @as(u8, 0xff) >> @intCast(used);
        if (byte & mask != 0) return "host bits set";
    }
    return null;
}

/// A host and port, split: [v6]:port, or host:port.
fn splitPort(s: []const u8) ?struct { host: []const u8, bracketed: bool } {
    const colon = std.mem.findScalarLast(u8, s, ':') orelse return null;
    const p = s[colon + 1 ..];
    if (p.len == 0 or p.len > 5) return null;
    for (p) |c| if (!std.ascii.isDigit(c)) return null;
    const n = std.fmt.parseInt(u16, p, 10) catch return null;
    if (n == 0) return null;
    const host = s[0..colon];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']')
        return .{ .host = host[1 .. host.len - 1], .bracketed = true };
    return .{ .host = host, .bracketed = false };
}

fn addrport(s: []const u8) bool {
    const hp = splitPort(s) orelse return false;
    if (hp.bracketed) {
        _ = Ip6Address.parse(hp.host, 0) catch return false;
        return true;
    }
    _ = Ip4Address.parse(hp.host, 0) catch return false;
    return true;
}

fn hostport(s: []const u8) bool {
    if (addrport(s)) return true;
    const hp = splitPort(s) orelse return false;
    return !hp.bracketed and hostname(hp.host);
}

fn hostname(s: []const u8) bool {
    if (s.len == 0 or s.len > 253) return false;
    var labels = std.mem.splitScalar(u8, s, '.');
    while (labels.next()) |l| {
        if (l.len == 0 or l.len > 63 or l[0] == '-' or l[l.len - 1] == '-') return false;
        for (l) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }
    return true;
}

fn url(s: []const u8) ?[]const u8 {
    if (s.len > max_url) return "a url is at most 2 KiB";
    const rest = if (std.mem.startsWith(u8, s, "https://"))
        s[8..]
    else if (std.mem.startsWith(u8, s, "http://"))
        s[7..]
    else
        return "a url is http or https";
    for (s) |c| if (c <= ' ' or c >= 0x7f) return "a url is printable ASCII, without spaces";
    const end = std.mem.findAny(u8, rest, "/?#") orelse rest.len;
    const authority = rest[0..end];
    if (std.mem.findScalar(u8, authority, '@') != null)
        return "a url carries no user or password: put a secret in a file";
    if (hostname(authority) or hostport(authority)) return null;
    if (authority.len >= 2 and authority[0] == '[' and authority[authority.len - 1] == ']') {
        _ = Ip6Address.parse(authority[1 .. authority.len - 1], 0) catch return "not a url's host";
        return null;
    }
    _ = Ip4Address.parse(authority, 0) catch return "not a url's host";
    return null;
}

fn string(s: []const u8) ?[]const u8 {
    if (s.len > max_string) return "a string is at most 1 KiB";
    if (!std.unicode.utf8ValidateSlice(s)) return "not UTF-8";
    for (s) |c| if (c < 0x20 or c == 0x7f) return "a control character";
    return null;
}

fn appendText(gpa: Allocator, out: *std.ArrayList(u8), v: json.Value, format: Format) !void {
    switch (v) {
        .string => |s| try out.appendSlice(gpa, s),
        .integer => |n| try out.print(gpa, "{d}", .{n}),
        .bool => |b| try out.appendSlice(gpa, switch (format) {
            .conf => if (b) "yes" else "no",
            else => if (b) "true" else "false",
        }),
        else => unreachable,
    }
}

fn fail(why: *[]const u8, text: []const u8) error{Invalid} {
    why.* = text;
    return error.Invalid;
}

fn refuse(diag: *Diagnostic, setting: []const u8, index: ?usize, why: []const u8) error{Invalid} {
    diag.* = .{ .setting = setting, .index = index, .why = why };
    return error.Invalid;
}

/// database-url as DATABASE_URL.
fn envName(gpa: Allocator, name: []const u8) ![]const u8 {
    const key = try gpa.alloc(u8, name.len);
    for (name, key) |c, *k| k.* = if (c == '-') '_' else std.ascii.toUpper(c);
    return key;
}

/// [a-z][a-z0-9-]*, at most 32: a key in settings.json, a service's config
/// file's name, and so a flag of howl pack's.
pub fn isName(s: []const u8) bool {
    if (s.len == 0 or s.len > 32 or !std.ascii.isLower(s[0])) return false;
    for (s) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

fn isVariable(s: []const u8) bool {
    if (s.len == 0 or std.ascii.isDigit(s[0])) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    return true;
}

/// A conf directive or a JSON key: [A-Za-z0-9_.:-]+, at most 64.
fn isKey(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "_.:-", c) == null)
        return false;
    return true;
}

/// A file name: [A-Za-z0-9._-], at most 64, not . or ..
fn isFile(s: []const u8) bool {
    if (s.len == 0 or s.len > 64 or std.mem.eql(u8, s, ".") or std.mem.eql(u8, s, ".."))
        return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._-", c) == null)
        return false;
    return true;
}

/// Absolute, with no empty, . or .. part, no trailing slash, and no space
/// or control character.
fn isCleanPath(p: []const u8) bool {
    if (p.len < 2 or p[0] != '/') return false;
    for (p) |c| if (c <= ' ' or c == 0x7f) return false;
    var parts = std.mem.splitScalar(u8, p[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return false;
    }
    return true;
}

// --- the config tar's own rules -------------------------------------------------
// What init, cloud-metadata and howl pack all hold a config tar to, so a
// tar the host packs is one the machine takes.

/// The most a machine's hostname may be: the kernel's (__NEW_UTS_LEN).
pub const max_hostname = 64;

/// The least a data.key may be: LUKS2 is made with a quick key derivation,
/// as a random key needs no slow one, so the key itself must be strong.
pub const min_data_key = 32;

/// Whether s may be a machine's hostname: a hostname setting's rules, and
/// no longer than the kernel takes.
pub fn isHostname(s: []const u8) bool {
    return s.len <= max_hostname and hostname(s);
}

/// A config tar entry's name, made relative and plain: no leading /, no
/// . or .. or empty parts, and only letters, digits and . _ - /; "" for
/// the archive's root, ./ itself. Null if it cannot be.
pub fn entryName(raw: []const u8) ?[]const u8 {
    var n = raw;
    while (std.mem.startsWith(u8, n, "./")) n = n[2..];
    if (std.mem.eql(u8, n, ".")) return "";
    if (n.len > 0 and n[0] == '/') return null;
    n = std.mem.trimEnd(u8, n, "/");
    if (n.len == 0) return "";
    for (n) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._-/", c) == null)
        return null;
    var parts = std.mem.splitScalar(u8, n, '/');
    while (parts.next()) |p| {
        if (p.len == 0 or std.mem.eql(u8, p, ".") or std.mem.eql(u8, p, "..")) return null;
    }
    return n;
}

// --- tests ---------------------------------------------------------------------

const testing = std.testing;

fn str(s: []const u8) json.Value {
    return .{ .string = s };
}

test "addrport is a literal address and port, as the bastion had it" {
    for ([_][]const u8{ "10.20.0.10:22", "[fd00::1]:443", "127.0.0.1:65535" }) |v|
        try testing.expectEqual(null, reason(.addrport, str(v)));
    for ([_][]const u8{
        "*:22",
        "host.example:22",
        "10.0.0.1:*",
        "10.0.0.1:0",
        "10.0.0.1:65536",
        "10.0.0.1:22\nPermitTTY yes",
        "10.0.0.1:22 10.0.0.2:22",
        "fd00::1:22",
        "[fd00::1%eth0]:22",
        "[10.0.0.1]:22",
        ":22",
    }) |v| try testing.expect(reason(.addrport, str(v)) != null);
}

test "cidr is a network, never a default route, as the router had it" {
    for ([_][]const u8{ "10.20.0.0/24", "192.168.1.4/32", "fd00::/64", "fd00::1/128" }) |v|
        try testing.expectEqual(null, reason(.cidr, str(v)));
    try testing.expectEqualStrings("a default route", reason(.cidr, str("0.0.0.0/0")).?);
    try testing.expectEqualStrings("a default route", reason(.cidr, str("::/0")).?);
    try testing.expectEqualStrings("host bits set", reason(.cidr, str("10.20.0.1/24")).?);
    try testing.expectEqualStrings("host bits set", reason(.cidr, str("fd00::1/64")).?);
    for ([_][]const u8{
        "10.0.0.0/33",
        "fd00::/129",
        "10.0.0.0/-1",
        "10.0.0.0/24\n",
        "example.com/24",
    }) |v|
        try testing.expectEqualStrings("not a network", reason(.cidr, str(v)).?);
}

test "the other types" {
    try testing.expectEqual(null, reason(.ip, str("10.0.0.1")));
    try testing.expectEqual(null, reason(.ip, str("fd00::1")));
    try testing.expect(reason(.ip, str("fe80::1%eth0")) != null);
    try testing.expect(reason(.ip, str("10.0.0.1:22")) != null);
    try testing.expectEqual(null, reason(.hostport, str("db.internal:5432")));
    try testing.expectEqual(null, reason(.hostport, str("[fd00::1]:5432")));
    try testing.expect(reason(.hostport, str("db.internal")) != null);
    try testing.expect(reason(.hostport, str("-db:5432")) != null);
    try testing.expectEqual(null, reason(.hostname, str("bao.example.com")));
    try testing.expectEqual(null, reason(.hostname, str("db")));
    try testing.expect(reason(.hostname, str("bao.example.com.")) != null);
    try testing.expect(reason(.hostname, str("a b")) != null);
    try testing.expect(reason(.hostname, str("a_b")) != null);
    try testing.expectEqual(null, reason(.port, .{ .integer = 8200 }));
    try testing.expect(reason(.port, .{ .integer = 0 }) != null);
    try testing.expect(reason(.port, .{ .integer = 65536 }) != null);
    try testing.expect(reason(.port, str("8200")) != null);
    try testing.expectEqual(null, reason(.url, str("https://bao.example.com:8200")));
    try testing.expectEqual(null, reason(.url, str("http://10.0.0.1/health?x=1")));
    try testing.expectEqual(null, reason(.url, str("https://[fd00::1]:8200/")));
    try testing.expect(reason(.url, str("https://user:pw@db.example.com/")) != null);
    try testing.expect(reason(.url, str("file:///etc/shadow")) != null);
    try testing.expect(reason(.url, str("https://a b/")) != null);
    try testing.expect(reason(.url, str("https://")) != null);
    try testing.expectEqual(null, reason(.int, .{ .integer = -4 }));
    try testing.expect(reason(.int, .{ .float = 1.5 }) != null);
    try testing.expectEqual(null, reason(.bool, .{ .bool = true }));
    try testing.expect(reason(.bool, str("true")) != null);
    try testing.expectEqual(null, reason(.string, str("Engineering, Ünïcode")));
    try testing.expect(reason(.string, str("a\nb")) != null);
    try testing.expect(reason(.string, str("\xff")) != null);
}

test isHostname {
    try testing.expect(isHostname("lima-werewolf-demo"));
    try testing.expect(isHostname("db.example.com"));
    for ([_][]const u8{ "", "a b", "-x", "x-", "a..b", "a_b", "x." }) |h|
        try testing.expect(!isHostname(h));
    // 64 bytes is the kernel's most; a label, 63.
    const a31: [31]u8 = @splat('a');
    const a32: [32]u8 = @splat('a');
    const b32: [32]u8 = @splat('b');
    try testing.expect(isHostname(&a31 ++ "." ++ &b32));
    try testing.expect(!isHostname(&a32 ++ "." ++ &b32));
    try testing.expect(!isHostname(&a32 ++ &b32));
}

test entryName {
    try testing.expectEqualStrings("authorized_keys", entryName("./authorized_keys").?);
    try testing.expectEqualStrings("cloudflared/token", entryName("cloudflared/token").?);
    try testing.expectEqualStrings("nginx", entryName("nginx/").?);
    try testing.expectEqualStrings("", entryName("./").?);
    try testing.expectEqualStrings("", entryName(".").?);
    for ([_][]const u8{ "/etc/passwd", "../x", "a/../../x", "a//b", "/", "a b", "a\x1b", "é" }) |n|
        try testing.expectEqual(null, entryName(n));
}

test "fromText makes the value a flag means" {
    var why: []const u8 = "";
    try testing.expectEqual(@as(i64, 8200), fromText(.port, "8200", &why).?.integer);
    try testing.expect(fromText(.port, "http", &why) == null);
    try testing.expect(fromText(.bool, "true", &why).?.bool);
    try testing.expect(fromText(.bool, "yes", &why) == null);
    try testing.expectEqualStrings("10.0.0.0/8", fromText(.cidr, "10.0.0.0/8", &why).?.string);
    try testing.expect(fromText(.cidr, "10.0.0.1/8", &why) == null);
    try testing.expectEqualStrings("host bits set", why);
}

test "declarations" {
    var why: []const u8 = "";
    const s = try parseSetting(&.{ "destinations", "addrport...", "as", "PermitOpen" }, &why);
    try testing.expect(s.list and !s.required and s.type == .addrport);
    try testing.expectEqualStrings("PermitOpen", s.key.?);
    const r = try parseSetting(&.{ "api-addr", "url", "required" }, &why);
    try testing.expect(r.required and !r.list and r.key == null);
    for ([_][]const []const u8{
        &.{"x"},
        &.{ "X", "ip" },
        &.{ "x", "float" },
        &.{ "x", "int..." },
        &.{ "x", "ip", "as" },
        &.{ "x", "ip", "as", "K", "required" },
        &.{ "x", "ip", "optional" },
    }) |args| try testing.expectError(error.Invalid, parseSetting(args, &why));

    const j = try parseRender(
        &.{ "json", "config.json", "from", "/etc/tailscale/config.json" },
        &why,
    );
    try testing.expectEqualStrings("/etc/tailscale/config.json", j.from.?);
    for ([_][]const []const u8{
        &.{ "yaml", "x" },
        &.{ "conf", "../x" },
        &.{ "conf", "settings" },
        &.{ "conf", "x", "from", "/etc/x" },
        &.{ "json", "x", "from", "etc/x" },
        &.{ "json", "x", "of", "/etc/x" },
        &.{ "json", "x", "from", "/etc/a b" },
    }) |args| try testing.expectError(error.Invalid, parseRender(args, &why));
}

test "declare names keys and refuses what a format cannot hold" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: []const u8 = "";

    var env = [_]Setting{.{ .name = "database-url", .type = .url }};
    try declare(gpa, &env, .{ .format = .env, .file = "app.env" }, &why);
    try testing.expectEqualStrings("DATABASE_URL", env[0].key.?);

    const refused = [_]struct { Setting, Format }{
        .{ .{ .name = "x", .type = .string }, .conf },
        .{ .{ .name = "x", .type = .url }, .conf },
        .{ .{ .name = "x", .type = .string, .list = true }, .env },
        .{ .{ .name = "x", .type = .url, .list = true }, .env },
        .{ .{ .name = "path", .type = .string }, .env },
        .{ .{ .name = "x", .type = .string, .key = "LD_PRELOAD" }, .env },
        .{ .{ .name = "x", .type = .ip, .key = "Permit Open" }, .conf },
        .{ .{ .name = "x", .type = .ip, .key = "a b" }, .json },
    };
    for (refused) |c| {
        var one = [_]Setting{c[0]};
        try testing.expectError(
            error.Invalid,
            declare(gpa, &one, .{ .format = c[1], .file = "f" }, &why),
        );
    }
    var twice = [_]Setting{
        .{ .name = "a", .type = .ip, .key = "K" },
        .{ .name = "b", .type = .ip, .key = "K" },
    };
    try testing.expectError(
        error.Invalid,
        declare(gpa, &twice, .{ .format = .conf, .file = "f" }, &why),
    );
}

test "the bastion renders as it did" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: []const u8 = "";
    var diag: Diagnostic = .{};
    var s = [_]Setting{.{
        .name = "destinations",
        .type = .addrport,
        .list = true,
        .key = "PermitOpen",
    }};
    const r: Render = .{ .format = .conf, .file = "destinations" };
    try declare(gpa, &s, r, &why);

    const v = try parseValues(
        gpa,
        &s,
        "{\"destinations\":[\"10.20.0.10:22\",\"[fd00::1]:443\"]}",
        &diag,
    );
    try testing.expectEqualStrings(
        "PermitOpen 10.20.0.10:22 [fd00::1]:443\n",
        try render(gpa, &s, r, v, null),
    );
    // Empty or absent: no line, and sshd_config's own PermitOpen none holds.
    try testing.expectEqualStrings(
        "",
        try render(gpa, &s, r, try parseValues(gpa, &s, "{\"destinations\":[]}", &diag), null),
    );
    try testing.expectEqualStrings(
        "",
        try render(gpa, &s, r, try parseValues(gpa, &s, "{}", &diag), null),
    );

    try testing.expectError(
        error.Invalid,
        parseValues(gpa, &s, "{\"destinations\":[],\"permit-tty\":true}", &diag),
    );
    try testing.expectEqualStrings("permit-tty", diag.setting);
    try testing.expectEqualStrings("not a setting of this service", diag.why);
    // A key that could not be a setting's name is not echoed, whatever it holds.
    try testing.expectError(
        error.Invalid,
        parseValues(gpa, &s, "{\"destinations\":[],\"PermitTTY\":true}", &diag),
    );
    try testing.expectEqualStrings("", diag.setting);
    try testing.expectEqualStrings("a key that is not a setting name", diag.why);
    try testing.expectError(
        error.Invalid,
        parseValues(gpa, &s, "{\"destinations\":[],\"destinations\":[]}", &diag),
    );
    try testing.expectError(
        error.Invalid,
        parseValues(gpa, &s, "{\"destinations\":[\"10.0.0.1:22\",\"*:22\"]}", &diag),
    );
    try testing.expectEqualStrings("destinations", diag.setting);
    try testing.expectEqual(@as(?usize, 1), diag.index);
    try testing.expectError(
        error.Invalid,
        parseValues(gpa, &s, "{\"destinations\":\"10.0.0.1:22\"}", &diag),
    );
    try testing.expectError(error.Invalid, parseValues(gpa, &s, "[]", &diag));
}

test "tailscale's settings cannot change the image's policy" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: []const u8 = "";
    var diag: Diagnostic = .{};
    var s = [_]Setting{.{
        .name = "routes",
        .type = .cidr,
        .list = true,
        .key = "advertiseRoutes",
    }};
    const r: Render = .{
        .format = .json,
        .file = "config.json",
        .from = "/etc/tailscale/config.json",
    };
    try declare(gpa, &s, r, &why);
    const image = "{\"version\":\"alpha0\",\"locked\":true,\"advertiseRoutes\":[],\"runSSHServer" ++
        "\":false,\"authKey\":\"file:/private/key\"}";

    const out = try render(
        gpa,
        &s,
        r,
        try parseValues(gpa, &s, "{\"routes\":[\"10.20.0.0/24\"]}", &diag),
        image,
    );
    const got = try json.parseFromSliceLeaky(json.Value, gpa, out, .{});
    try testing.expect(got.object.get("locked").?.bool);
    try testing.expect(!got.object.get("runSSHServer").?.bool);
    try testing.expectEqualStrings("file:/private/key", got.object.get("authKey").?.string);
    try testing.expectEqualStrings(
        "10.20.0.0/24",
        got.object.get("advertiseRoutes").?.array.items[0].string,
    );
    try testing.expectEqualStrings("version", got.object.keys()[0]);

    for ([_][]const u8{
        "{\"routes\":[],\"runSSHServer\":true}",
        "{\"routes\":[],\"authKey\":\"replacement\"}",
        "{\"advertiseRoutes\":[\"0.0.0.0/1\"]}",
        "{\"routes\":[\"0.0.0.0/0\"]}",
    }) |input| try testing.expectError(error.Invalid, parseValues(gpa, &s, input, &diag));
    try testing.expectError(error.Invalid, render(gpa, &s, r, &.{null}, "[]"));
}

test "env and conf render every type, and env reads back" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: []const u8 = "";
    var diag: Diagnostic = .{};
    const input =
        \\{"database-url":"https://db.internal:5432/app","workers":4,"debug":false,
        \\ "peers":["a.internal:8201","10.0.0.2:8201"],"name":"Team = blue"}
    ;
    var e = [_]Setting{
        .{ .name = "database-url", .type = .url, .required = true },
        .{ .name = "workers", .type = .int },
        .{ .name = "debug", .type = .bool },
        .{ .name = "peers", .type = .hostport, .list = true },
        .{ .name = "name", .type = .string },
        .{ .name = "region", .type = .hostname },
    };
    const re: Render = .{ .format = .env, .file = "app.env" };
    try declare(gpa, &e, re, &why);
    const text = try render(gpa, &e, re, try parseValues(gpa, &e, input, &diag), null);
    try testing.expectEqualStrings(
        \\DATABASE_URL=https://db.internal:5432/app
        \\WORKERS=4
        \\DEBUG=false
        \\PEERS=a.internal:8201,10.0.0.2:8201
        \\NAME=Team = blue
        \\
    , text);
    const vars = try parseEnv(gpa, &e, text);
    try testing.expectEqualStrings("NAME", vars[4][0]);
    try testing.expectEqualStrings("Team = blue", vars[4][1]);
    try testing.expectError(error.Invalid, parseEnv(gpa, &e, "LD_PRELOAD=/tmp/x.so\n"));
    try testing.expectError(error.Invalid, parseEnv(gpa, &e, "WORKERS=1\nWORKERS=2\n"));
    try testing.expectError(error.Invalid, parseValues(gpa, &e, "{}", &diag));
    try testing.expectEqualStrings("database-url", diag.setting);
    try testing.expectEqualStrings("required", diag.why);

    var c = [_]Setting{
        .{ .name = "maxmemory", .type = .int },
        .{ .name = "protected-mode", .type = .bool },
    };
    const rc: Render = .{ .format = .conf, .file = "valkey.conf" };
    try declare(gpa, &c, rc, &why);
    try testing.expectEqualStrings(
        "maxmemory 256\nprotected-mode yes\n",
        try render(
            gpa,
            &c,
            rc,
            try parseValues(gpa, &c, "{\"maxmemory\":256,\"protected-mode\":true}", &diag),
            null,
        ),
    );
}

test "a dotted json key fills a nested object" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: []const u8 = "";
    var diag: Diagnostic = .{};
    var s = [_]Setting{
        .{
            .name = "domains",
            .type = .hostname,
            .list = true,
            .key = "authority.policy.x509.allow.dns",
        },
        .{ .name = "names", .type = .hostname, .list = true, .key = "dnsNames" },
    };
    const r: Render = .{ .format = .json, .file = "ca.json", .from = "/etc/step-ca/ca.json" };
    try declare(gpa, &s, r, &why);
    const image = "{\"address\":\":443\",\"authority\":{\"enableAdmin\":false,\"policy\":{\"x509" ++
        "\":" ++
        "{\"allow\":{\"dns\":[]},\"allowWildcardNames\":false}}}}";
    const out = try render(
        gpa,
        &s,
        r,
        try parseValues(
            gpa,
            &s,
            "{\"domains\":[\"a.example\"],\"names\":[\"ca.example\"]}",
            &diag,
        ),
        image,
    );
    const got = try json.parseFromSliceLeaky(json.Value, gpa, out, .{});
    const authority = got.object.get("authority").?.object;
    try testing.expect(!authority.get("enableAdmin").?.bool);
    const x509 = authority.get("policy").?.object.get("x509").?.object;
    try testing.expect(!x509.get("allowWildcardNames").?.bool);
    try testing.expectEqualStrings(
        "a.example",
        x509.get("allow").?.object.get("dns").?.array.items[0].string,
    );
    try testing.expectEqualStrings(
        "ca.example",
        got.object.get("dnsNames").?.array.items[0].string,
    );
    // A path through a value that is not an object is refused.
    try testing.expectError(
        error.Invalid,
        render(gpa, &s, r, &.{ .{ .array = .init(gpa) }, null }, "{\"authority\":1}"),
    );
    // Without a base, the path is made whole.
    const alone = try render(
        gpa,
        &s,
        .{ .format = .json, .file = "x" },
        &.{ null, .{ .array = .init(gpa) } },
        null,
    );
    try testing.expectEqualStrings("{\"dnsNames\":[]}\n", alone);
}

test "json without from is the settings alone" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: []const u8 = "";
    var diag: Diagnostic = .{};
    var s = [_]Setting{
        .{ .name = "api-addr", .type = .url, .required = true, .key = "api_addr" },
        .{ .name = "cluster-addr", .type = .url, .key = "cluster_addr" },
    };
    const r: Render = .{ .format = .json, .file = "settings.json" };
    try declare(gpa, &s, r, &why);
    try testing.expectEqualStrings(
        "{\"api_addr\":\"https://bao.example.com:8200\"}\n",
        try render(
            gpa,
            &s,
            r,
            try parseValues(gpa, &s, "{\"api-addr\":\"https://bao.example.com:8200\"}", &diag),
            null,
        ),
    );
}
