//! evidence judges what a machine shows of its protected boot: the
//! updater's credentials, a posture line a kernel message interrupted, the
//! UKI's initrd, ab-status's record of a fresh boot, a refused retry. What
//! each must hold is the table in evidence.yaml, which a check reads with
//! lib/form.zig's parser (load), a module host itself does not take.

const std = @import("std");
const qemu = @import("qemu.zig");
const Why = @import("check.zig").Why;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;

pub const Field = struct { name: []const u8, values: []const u64 };

/// Table is evidence.yaml.
pub const Table = struct {
    updater: []const Field,
    coordinator: []const u8,
    enforced: []const []const u8,
    published: []const []const u8,
    ssh: []const []const u8,
    cloud: []const []const u8,
};

pub const yaml = @embedFile("evidence.yaml");

/// load parses evidence.yaml with form, lib/form.zig as a module.
pub fn load(gpa: Allocator, comptime form: type) !Table {
    var diag: form.Diagnostic = .{};
    const root = form.parse(gpa, yaml, &diag) catch |err| {
        std.log.err("evidence.yaml:{d}: {s}", .{ diag.line, diag.why });
        return err;
    };
    const updater = root.get("updater") orelse return error.BadEvidenceTable;
    if (updater != .map) return error.BadEvidenceTable;
    var fields: std.ArrayList(Field) = .empty;
    for (updater.map) |e| {
        const values = try scalars(gpa, e.value);
        var numbers: std.ArrayList(u64) = .empty;
        for (values) |v| try numbers.append(gpa, try std.fmt.parseInt(u64, v, 10));
        try fields.append(gpa, .{ .name = e.key, .values = numbers.items });
    }
    const coordinator = root.get("coordinator") orelse return error.BadEvidenceTable;
    if (coordinator != .scalar) return error.BadEvidenceTable;
    return .{
        .updater = fields.items,
        .coordinator = coordinator.scalar.text,
        .enforced = try scalars(gpa, root.get("enforced")),
        .published = try scalars(gpa, root.get("published")),
        .ssh = try scalars(gpa, root.get("ssh")),
        .cloud = try scalars(gpa, root.get("cloud")),
    };
}

fn scalars(gpa: Allocator, node: anytype) ![]const []const u8 {
    const list = switch (@typeInfo(@TypeOf(node))) {
        .optional => node orelse return error.BadEvidenceTable,
        else => node,
    };
    if (list != .list or list.list.len == 0) return error.BadEvidenceTable;
    var out: std.ArrayList([]const u8) = .empty;
    for (list.list) |item| {
        if (item != .scalar) return error.BadEvidenceTable;
        try out.append(gpa, item.scalar.text);
    }
    return out.items;
}

/// updaterStatus requires each of the table's fields once in the live
/// coordinator's /proc status, with exactly its values: saved and
/// filesystem IDs too, and no capability even dormant.
pub fn updaterStatus(t: Table, status: []const u8, why: *Why) error{Refused}!void {
    var found: [32]bool = @splat(false);
    var lines = mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        const colon = mem.findScalar(u8, line, ':') orelse continue;
        const key = line[0..colon];
        const index = for (t.updater, 0..) |f, i| {
            if (mem.eql(u8, f.name, key)) break i;
        } else continue;
        if (found[index]) return why.refuse("duplicate updater status field: {s}", .{key});
        found[index] = true;
        const base: u8 = if (mem.startsWith(u8, key, "Cap")) 16 else 10;
        var words = mem.tokenizeAny(u8, line[colon + 1 ..], " \t");
        var n: usize = 0;
        var same = true;
        while (words.next()) |word| : (n += 1) {
            const value = std.fmt.parseInt(u64, word, base) catch
                return why.refuse("invalid updater status field: {s}", .{key});
            if (n >= t.updater[index].values.len or value != t.updater[index].values[n])
                same = false;
        }
        if (!same or n != t.updater[index].values.len)
            return why.refuse("unsafe updater status field: {s}", .{line});
    }
    var missing: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&missing);
    var sorted: [32][]const u8 = undefined;
    var count: usize = 0;
    for (t.updater, 0..) |f, i| if (!found[i]) {
        sorted[count] = f.name;
        count += 1;
    };
    if (count == 0) return;
    mem.sortUnstable([]const u8, sorted[0..count], {}, lessThan);
    for (sorted[0..count], 0..) |name, i|
        w.print("{s}{s}", .{ if (i > 0) ", " else "", name }) catch {};
    return why.refuse("missing updater status fields: {s}", .{w.buffered()});
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

const handover_start = "werewolf: up in ";
const handover_end = "handing over to runit";
const credentials = "autoupdate: coordinator";

/// updaterConsole requires boots handovers on the console, each fresh boot
/// attesting the coordinator's credentials after it, and none other.
pub fn updaterConsole(t: Table, console: []const u8, boots: usize, why: *Why) error{Refused}!void {
    var parts: [64][]const u8 = undefined;
    var n: usize = 0;
    var rest = console;
    while (handover(rest)) |at| {
        if (n == parts.len - 1) return why.refuse("unexpected boot count in updater console", .{});
        parts[n] = rest[0..at.start];
        n += 1;
        rest = rest[at.end..];
    }
    parts[n] = rest;
    n += 1;
    if (n != boots + 1) return why.refuse("unexpected boot count in updater console", .{});
    for (parts[1..n]) |part| {
        var seen = false;
        var from: usize = 0;
        while (mem.findPos(u8, part, from, credentials)) |i| {
            const end = mem.findAnyPos(u8, part, i, "\r\n") orelse part.len;
            if (!mem.eql(u8, part[i..end], t.coordinator))
                return why.refuse("missing or unsafe updater credentials in boot console", .{});
            seen = true;
            from = end;
        }
        if (!seen) return why.refuse("missing or unsafe updater credentials in boot console", .{});
    }
}

const Span = struct { start: usize, end: usize };

/// handover finds "werewolf: up in ", then the last "handing over to runit"
/// on its line.
fn handover(s: []const u8) ?Span {
    var from: usize = 0;
    while (mem.findPos(u8, s, from, handover_start)) |start| {
        const line_end = mem.findAnyPos(u8, s, start, "\r\n") orelse s.len;
        const line = s[start + handover_start.len .. line_end];
        if (mem.findLast(u8, line, handover_end)) |i|
            return .{ .start = start, .end = start + handover_start.len + i + handover_end.len };
        from = start + 1;
    }
    return null;
}

/// refusedRetry requires a refused command (exit 1) to have appended a
/// fresh ImageRolledBack error to the updater's audit log, and returns its
/// sequence number. before must be the log's start, unchanged.
pub fn refusedRetry(
    gpa: Allocator,
    code: ?u8,
    before: []const u8,
    after: []const u8,
    why: *Why,
) error{ Refused, OutOfMemory }!i64 {
    if (code == null or code.? != 1)
        return why.refuse("updater retry did not return a command refusal", .{});
    if (!mem.startsWith(u8, after, before))
        return why.refuse("updater audit log changed its existing history", .{});
    var previous: i64 = 0;
    if (before.len > 0) {
        var it = mem.splitBackwardsScalar(u8, mem.trimEnd(u8, before, "\n"), '\n');
        previous = seq(gpa, it.first()) orelse
            return why.refuse("updater audit log has no sequence numbers", .{});
    }
    var lines = mem.tokenizeScalar(u8, after[before.len..], '\n');
    while (lines.next()) |line| {
        const parsed = json.parseFromSliceLeaky(json.Value, gpa, line, .{}) catch
            return why.refuse("updater audit log holds a record that is not JSON", .{});
        if (parsed != .object) continue;
        const number = seq(gpa, line) orelse continue;
        if (number > previous and holds(parsed, "event", "error") and
            holds(parsed, "error", "ImageRolledBack")) return number;
    }
    return why.refuse("updater retry did not record a fresh ImageRolledBack refusal", .{});
}

fn seq(gpa: Allocator, line: []const u8) ?i64 {
    const v = json.parseFromSliceLeaky(json.Value, gpa, line, .{}) catch return null;
    if (v != .object) return null;
    const n = v.object.get("seq") orelse return null;
    return if (n == .integer) n.integer else null;
}

fn holds(v: json.Value, key: []const u8, want: []const u8) bool {
    const got = v.object.get(key) orelse return false;
    return got == .string and mem.eql(u8, got.string, want);
}

/// postureFailures recovers a whole "posture: fail=" summary from a console
/// whose kernel audit messages interrupted it, and returns the checks it
/// says failed, or null if there is no whole summary.
pub fn postureFailures(gpa: Allocator, console: []const u8) !?[]const []const u8 {
    var joined: std.ArrayList(u8) = try .initCapacity(gpa, console.len);
    var i: usize = 0;
    while (i < console.len) {
        if (qemu.kernelRecord(console[i..], .spaces)) |len| {
            i += len;
            continue;
        }
        if (console[i] != '\r' and console[i] != '\n') joined.appendAssumeCapacity(console[i]);
        i += 1;
    }
    const clean = joined.items;
    const start = "posture: fail=";
    var from: usize = 0;
    while (mem.findPos(u8, clean, from, start)) |at| : (from = at + 1) {
        var j = at + start.len;
        const list_start = j;
        while (j < clean.len and (std.ascii.isLower(clean[j]) or std.ascii.isDigit(clean[j]) or
            clean[j] == ',' or clean[j] == '-')) j += 1;
        const list = clean[list_start..j];
        j = literal(clean, j, " pass=") orelse continue;
        j = digitsAt(clean, j) orelse continue;
        j = literal(clean, j, " skip=") orelse continue;
        j = digitsAt(clean, j) orelse continue;
        _ = literal(clean, j, " ") orelse continue;
        var out: std.ArrayList([]const u8) = .empty;
        var names = mem.tokenizeScalar(u8, list, ',');
        while (names.next()) |name| {
            for (out.items) |seen| {
                if (mem.eql(u8, seen, name)) break;
            } else try out.append(gpa, name);
        }
        return out.items;
    }
    return null;
}

fn literal(s: []const u8, i: usize, w: []const u8) ?usize {
    return if (mem.startsWith(u8, s[i..], w)) i + w.len else null;
}

fn digitsAt(s: []const u8, i: usize) ?usize {
    var j = i;
    while (j < s.len and std.ascii.isDigit(s[j])) j += 1;
    return if (j == i) null else j;
}

/// sameSet is whether a and b hold the same names.
pub fn sameSet(a: []const []const u8, b: []const []const u8) bool {
    return subset(a, b) and subset(b, a);
}

/// subset is whether every name in a is in b.
pub fn subset(a: []const []const u8, b: []const []const u8) bool {
    for (a) |x| {
        for (b) |y| {
            if (mem.eql(u8, x, y)) break;
        } else return false;
    }
    return true;
}

/// nativeInitrd requires the signed native UKI's one .initrd section to
/// be the exported stage0, which verifies the external root.
pub fn nativeInitrd(uki: []const u8, stage0: []const u8, why: *Why) error{Refused}!void {
    if (uki.len < 0x40 or
        !mem.eql(u8, uki[0..2], "MZ")) return why.refuse("invalid native UKI", .{});
    const pe = mem.readInt(u32, uki[0x3c..][0..4], .little);
    if (pe > uki.len -| 24 or !mem.eql(u8, uki[pe..][0..4], "PE\x00\x00"))
        return why.refuse("invalid native UKI", .{});
    const sections = mem.readInt(u16, uki[pe + 6 ..][0..2], .little);
    const optional = mem.readInt(u16, uki[pe + 20 ..][0..2], .little);
    var matches: usize = 0;
    var same = false;
    for (0..sections) |index| {
        const header = pe + 24 + optional + index * 40;
        if (header + 40 > uki.len) return why.refuse("invalid native UKI", .{});
        if (!mem.eql(u8, mem.trimEnd(u8, uki[header..][0..8], "\x00"), ".initrd")) continue;
        const size = mem.readInt(u32, uki[header + 8 ..][0..4], .little);
        const offset = mem.readInt(u32, uki[header + 20 ..][0..4], .little);
        matches += 1;
        same = @as(u64, offset) + size <= uki.len and mem.eql(u8, uki[offset..][0..size], stage0);
    }
    if (matches != 1 or !same)
        return why.refuse("native UKI initrd differs from the exported stage0", .{});
}

/// Boot is what a fresh boot must show: which release, in which slot, on
/// which authenticated root.
pub const Boot = struct {
    release: []const u8,
    slot: []const u8,
    root_hash: []const u8,
    /// previous is the boot ID this one must differ from.
    previous: ?[]const u8 = null,
    secure: bool = true,
    committed: bool = true,
};

/// boot requires ab-status's evidence, value, to be b's, enforced as the
/// table says, and returns its boot ID.
pub fn boot(t: Table, value: json.Value, b: Boot, why: *Why) error{Refused}![]const u8 {
    if (value != .object) return why.refuse("missing structured guest evidence", .{});
    const o = value.object;
    const id = o.get("boot_id") orelse json.Value{ .string = "" };
    if (id != .string or !isBootId(id.string)) return why.refuse("invalid boot ID", .{});
    if (b.previous) |p| if (mem.eql(u8, p, id.string))
        return why.refuse("stale evidence from the previous boot", .{});
    if (!holds(value, "release", b.release) or !holds(value, "slot", b.slot))
        return why.refuse("wrong release or slot", .{});
    if (!holds(value, "root_hash", b.root_hash)) return why.refuse("wrong authenticated root", .{});
    for (t.enforced) |flag| if (!isTrue(o.get(flag)))
        return why.refuse("{s} is not enforced", .{flag});
    if (b.secure and !isTrue(o.get("secure_boot")))
        return why.refuse("Secure Boot is not enforced outside setup mode", .{});
    const committed = o.get("committed") orelse json.Value{ .null = {} };
    if (committed != .bool or committed.bool != b.committed)
        return why.refuse("unexpected health-commit state", .{});
    return id.string;
}

fn isTrue(v: ?json.Value) bool {
    const x = v orelse return false;
    return x == .bool and x.bool;
}

/// isBootId is whether s is a lowercase UUID, as the kernel writes boot_id.
pub fn isBootId(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |c, i| switch (i) {
        8, 13, 18, 23 => if (c != '-') return false,
        else => if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return false,
    };
    return true;
}

/// Results are a posture report's check IDs and their results.
pub const Results = std.array_hash_map.String([]const u8);

/// results maps a posture report's check IDs to their results.
pub fn results(gpa: Allocator, report: json.Value) !Results {
    var out: Results = .empty;
    if (report != .object) return out;
    const checks = report.object.get("checks") orelse return out;
    if (checks != .array) return out;
    for (checks.array.items) |entry| {
        if (entry != .object) continue;
        const id = entry.object.get("id") orelse continue;
        const result = entry.object.get("result") orelse continue;
        if (id != .string or result != .string) continue;
        try out.put(gpa, id.string, result.string);
    }
    return out;
}

/// passes is whether every check in required passed.
pub fn passes(
    checks: Results,
    required: []const []const u8,
) bool {
    for (required) |id| {
        const result = checks.get(id) orelse return false;
        if (!mem.eql(u8, result, "pass")) return false;
    }
    return true;
}

const testing = std.testing;

test "the table parses" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const t = try load(arena.allocator(), @import("form"));
    try testing.expectEqual(10, t.updater.len);
    try testing.expectEqualSlices(u64, &.{ 77, 77, 77, 77 }, t.updater[0].values);
    try testing.expectEqual(7, t.published.len);
    try testing.expectEqual(4, t.ssh.len);
    try testing.expectEqual(7, t.cloud.len);
}

test "refusedRetry needs a fresh ImageRolledBack refusal" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const old = "{\"seq\": 7, \"event\": \"error\", \"error\": \"ImageRolledBack\"}\n";
    const new = "{\"seq\": 8, \"event\": \"error\", \"error\": \"ImageRolledBack\"}\n";
    try testing.expectEqual(8, try refusedRetry(gpa, 1, old, old ++ new, &why));
    try testing.expectEqual(8, try refusedRetry(gpa, 1, "", new, &why));
    const wrong = "{\"seq\": 8, \"event\": \"error\", \"error\": \"NetworkUnavailable\"}\n";
    for ([_]struct { ?u8, []const u8 }{
        .{ 0, old ++ new },    .{ 255, old ++ new }, .{ 1, old },
        .{ 1, old ++ old },    .{ 1, old ++ wrong }, .{ 1, new },
        .{ null, old ++ new },
    }) |case|
        try testing.expectError(error.Refused, refusedRetry(gpa, case[0], old, case[1], &why));
}

test "updaterStatus accepts only the coordinator's exact credentials" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const t = try load(gpa, @import("form"));
    var why: Why = .{};
    const status = "Uid:\t77\t77\t77\t77\nGid:\t77\t77\t77\t77\nThreads:\t1\n" ++
        "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n" ++
        "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n" ++
        "CapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";
    try updaterStatus(t, status, &why);
    var invalid: std.ArrayList([]const u8) = .empty;
    try invalid.appendSlice(gpa, &.{ "", status ++ "Uid:\t77\t77\t77\t77\n" });
    for ([_][]const u8{ "Uid", "Gid" }) |key| for (0..4) |column| {
        var values: [4][]const u8 = @splat("77");
        values[column] = "0";
        const line = try gpa.print(
            "{s}:\t{s}\t{s}\t{s}\t{s}",
            .{ key, values[0], values[1], values[2], values[3] },
        );
        try invalid.append(
            gpa,
            try mem.replaceOwned(
                u8,
                gpa,
                status,
                try gpa.print("{s}:\t77\t77\t77\t77", .{key}),
                line,
            ),
        );
    };
    var lines = mem.tokenizeScalar(u8, status, '\n');
    while (lines.next()) |line| {
        const key = line[0..mem.findScalar(u8, line, ':').?];
        try invalid.append(
            gpa,
            try mem.replaceOwned(u8, gpa, status, try gpa.print("{s}\n", .{line}), ""),
        );
        const wrong = if (mem.startsWith(u8, key, "Cap"))
            "1"
        else if (mem.eql(u8, key, "Threads"))
            "2"
        else
            "0";
        try invalid.append(
            gpa,
            try mem.replaceOwned(
                u8,
                gpa,
                status,
                line,
                try gpa.print("{s}:\t{s}", .{ key, wrong }),
            ),
        );
        try invalid.append(
            gpa,
            try mem.replaceOwned(
                u8,
                gpa,
                status,
                line,
                try gpa.print("{s}:\tnot-a-number", .{key}),
            ),
        );
    }
    for (invalid.items) |bad| try testing.expectError(error.Refused, updaterStatus(t, bad, &why));
}

test "updaterConsole needs credentials after each fresh handover" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const t = try load(gpa, @import("form"));
    var why: Why = .{};
    const up = "werewolf: up in 0.1s, handing over to runit\r\n";
    const said = "autoupdate: coordinator uid=77 gid=77 caps=0 nnp=1\r\n";
    try updaterConsole(t, up ++ said, 1, &why);
    try updaterConsole(t, up ++ said ++ up ++ said, 2, &why);
    for ([_]struct { []const u8, usize }{
        .{ "", 1 },                       .{ said ++ up, 1 },
        .{ up, 1 },                       .{ up ++ said ++ up, 2 },
        .{ up ++ said ++ up ++ said, 1 },
    }) |case| try testing.expectError(error.Refused, updaterConsole(t, case[0], case[1], &why));
    for ([_][2][]const u8{
        .{
            "uid=77",
            "uid=0",
        },
        .{ "gid=77", "gid=0" },
        .{ "caps=0", "caps=1" },
        .{ "nnp=1", "nnp=0" },
    }) |change| {
        const bad = try mem.replaceOwned(u8, gpa, said, change[0], change[1]);
        try testing.expectError(
            error.Refused,
            updaterConsole(t, try mem.concat(gpa, u8, &.{ up, bad }), 1, &why),
        );
    }
}

test "postureFailures rejoins a summary kernel audit interrupted" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const interrupted = "posture: fail=bo[    6.82] audit: refusal\r\n" ++
        "ot-ipe-enforced,boot-rollback-protected pass=89 skip=4 {}\r\n";
    const got = (try postureFailures(gpa, interrupted)).?;
    try testing.expect(sameSet(got, &.{ "boot-ipe-enforced", "boot-rollback-protected" }));
    try testing.expectEqual(
        0,
        (try postureFailures(gpa, "posture: fail= pass=92 skip=4 {}")).?.len,
    );
    try testing.expectEqual(
        null,
        try postureFailures(gpa, "posture: fail=boot-ipe-enforced pass=89"),
    );
    try testing.expectEqual(
        null,
        try postureFailures(gpa, "[    1.0] audit: posture: fail= pass=99 skip=0 \n"),
    );
}

test "boot needs a fresh, exact, enforced and committed boot" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const t = try load(gpa, @import("form"));
    var why: Why = .{};
    const good =
        \\{"boot_id": "12345678-1234-1234-1234-123456789abc", "release": "B", "slot": "b",
        \\ "root_hash": "aaaa", "verified_root": true, "ipe": true, "secure_boot": true,
        \\ "committed": true}
    ;
    const want: Boot = .{ .release = "B", .slot = "b", .root_hash = "aaaa" };
    const value = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
    try testing.expectEqualStrings(
        "12345678-1234-1234-1234-123456789abc",
        try boot(t, value, want, &why),
    );
    for ([_][2][]const u8{
        .{ "boot_id", "\"\"" },       .{ "release", "\"A\"" },       .{ "slot", "\"a\"" },
        .{ "root_hash", "\"bbbb\"" }, .{ "verified_root", "false" }, .{ "ipe", "false" },
        .{ "secure_boot", "false" },  .{ "committed", "false" },     .{ "secure_boot", "\"true\"" },
    }) |case| {
        var bad = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
        try bad.object.put(
            gpa,
            case[0],
            try json.parseFromSliceLeaky(json.Value, gpa, case[1], .{}),
        );
        try testing.expectError(error.Refused, boot(t, bad, want, &why));
    }
    var stale = want;
    stale.previous = "12345678-1234-1234-1234-123456789abc";
    try testing.expectError(error.Refused, boot(t, value, stale, &why));
    try testing.expectError(error.Refused, boot(t, .{ .null = {} }, want, &why));
    var insecure = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
    try insecure.object.put(gpa, "secure_boot", .{ .bool = false });
    var plain = want;
    plain.secure = false;
    _ = try boot(t, insecure, plain, &why);
    var uncommitted = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
    try uncommitted.object.put(gpa, "committed", .{ .bool = false });
    var trial = want;
    trial.committed = false;
    _ = try boot(t, uncommitted, trial, &why);
}

test "nativeInitrd finds stage0 as the UKI's one initrd" {
    var uki: [0x200]u8 = @splat(0);
    @memcpy(uki[0..2], "MZ");
    mem.writeInt(u32, uki[0x3c..][0..4], 0x40, .little);
    @memcpy(uki[0x40..][0..4], "PE\x00\x00");
    mem.writeInt(u16, uki[0x46..][0..2], 2, .little);
    mem.writeInt(u16, uki[0x54..][0..2], 0, .little);
    const first = 0x40 + 24;
    @memcpy(uki[first..][0..8], ".linux\x00\x00");
    @memcpy(uki[first + 40 ..][0..8], ".initrd\x00");
    mem.writeInt(u32, uki[first + 48 ..][0..4], 6, .little);
    mem.writeInt(u32, uki[first + 60 ..][0..4], 0x100, .little);
    @memcpy(uki[0x100..][0..6], "stage0");
    var why: Why = .{};
    try nativeInitrd(&uki, "stage0", &why);
    try testing.expectError(error.Refused, nativeInitrd(&uki, "stage1", &why));
    try testing.expectError(error.Refused, nativeInitrd("MZ", "stage0", &why));
}
