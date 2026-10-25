//! sqlite reads and writes a database through the vendored SQLite, for
//! checks that seed or inspect unwound's age store. A program that uses it
//! links the amalgamation's object and libc (-lc).

const std = @import("std");
const Allocator = std.mem.Allocator;

const sqlite3 = opaque {};
const sqlite3_stmt = opaque {};
extern "c" fn sqlite3_open_v2([*:0]const u8, *?*sqlite3, c_int, ?[*:0]const u8) c_int;
extern "c" fn sqlite3_close(*sqlite3) c_int;
extern "c" fn sqlite3_exec(
    *sqlite3,
    [*:0]const u8,
    ?*const anyopaque,
    ?*anyopaque,
    ?*?[*:0]u8,
) c_int;
extern "c" fn sqlite3_errmsg(*sqlite3) [*:0]const u8;
extern "c" fn sqlite3_prepare_v2(*sqlite3, [*]const u8, c_int, *?*sqlite3_stmt, ?*anyopaque) c_int;
extern "c" fn sqlite3_bind_text(*sqlite3_stmt, c_int, [*]const u8, c_int, isize) c_int;
extern "c" fn sqlite3_bind_int64(*sqlite3_stmt, c_int, i64) c_int;
extern "c" fn sqlite3_bind_null(*sqlite3_stmt, c_int) c_int;
extern "c" fn sqlite3_step(*sqlite3_stmt) c_int;
extern "c" fn sqlite3_finalize(*sqlite3_stmt) c_int;
extern "c" fn sqlite3_column_count(*sqlite3_stmt) c_int;
extern "c" fn sqlite3_column_type(*sqlite3_stmt, c_int) c_int;
extern "c" fn sqlite3_column_int64(*sqlite3_stmt, c_int) i64;
extern "c" fn sqlite3_column_text(*sqlite3_stmt, c_int) ?[*]const u8;
extern "c" fn sqlite3_column_bytes(*sqlite3_stmt, c_int) c_int;

const ok = 0;
const constraint = 19;
const row = 100;
const done = 101;
const integer_type = 1;
const null_type = 5;
/// transient makes SQLite copy bound text at once.
const transient: isize = -1;

pub const Cell = union(enum) {
    null,
    int: i64,
    text: []const u8,

    pub fn eql(a: Cell, b: Cell) bool {
        return switch (a) {
            .null => b == .null,
            .int => |n| b == .int and b.int == n,
            .text => |t| b == .text and std.mem.eql(u8, b.text, t),
        };
    }

    /// jsonStringify writes the value as JSON's null, number or string.
    pub fn jsonStringify(v: Cell, jw: anytype) !void {
        switch (v) {
            .null => try jw.write(null),
            .int => |n| try jw.write(n),
            .text => |t| try jw.write(t),
        }
    }
};

pub fn eqlRow(a: []const Cell, b: []const Cell) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!x.eql(y)) return false;
    return true;
}

pub const Mode = enum { read_only, read_write };

pub const Db = struct {
    handle: *sqlite3,
    gpa: Allocator,

    /// open opens path; read_write creates it when missing.
    pub fn open(gpa: Allocator, path: []const u8, mode: Mode) !Db {
        const name = try gpa.dupeSentinel(u8, path, 0);
        var handle: ?*sqlite3 = null;
        const flags: c_int = switch (mode) {
            .read_only => 0x1,
            .read_write => 0x2 | 0x4,
        };
        const rc = sqlite3_open_v2(name, &handle, flags, null);
        if (rc != ok) {
            if (handle) |h| _ = sqlite3_close(h);
            return error.OpenFailed;
        }
        return .{ .handle = handle.?, .gpa = gpa };
    }

    pub fn close(db: Db) void {
        _ = sqlite3_close(db.handle);
    }

    /// message is SQLite's account of the last failure.
    pub fn message(db: Db) []const u8 {
        return std.mem.span(sqlite3_errmsg(db.handle));
    }

    /// exec runs sql, which may hold many statements and no parameters.
    pub fn exec(db: Db, sql: []const u8) !void {
        const text = try db.gpa.dupeSentinel(u8, sql, 0);
        if (sqlite3_exec(db.handle, text, null, null, null) != ok) return error.SqlFailed;
    }

    /// run runs one statement, binding params in order, and discards its rows.
    /// A refused constraint is error.Constraint.
    pub fn run(db: Db, sql: []const u8, params: []const Cell) !void {
        _ = try db.rows(sql, params);
    }

    /// one is a query's first row, or null.
    pub fn one(db: Db, sql: []const u8, params: []const Cell) !?[]const Cell {
        const all = try db.rows(sql, params);
        return if (all.len > 0) all[0] else null;
    }

    /// rows runs one statement, binding params in order, and returns its rows.
    pub fn rows(db: Db, sql: []const u8, params: []const Cell) ![]const []const Cell {
        var stmt: ?*sqlite3_stmt = null;
        if (sqlite3_prepare_v2(db.handle, sql.ptr, @intCast(sql.len), &stmt, null) != ok)
            return error.SqlFailed;
        defer _ = sqlite3_finalize(stmt.?);
        for (params, 1..) |p, i| {
            const at: c_int = @intCast(i);
            const rc = switch (p) {
                .null => sqlite3_bind_null(stmt.?, at),
                .int => |n| sqlite3_bind_int64(stmt.?, at, n),
                .text => |t| sqlite3_bind_text(stmt.?, at, t.ptr, @intCast(t.len), transient),
            };
            if (rc != ok) return error.SqlFailed;
        }
        var out: std.ArrayList([]const Cell) = .empty;
        const columns: usize = @intCast(sqlite3_column_count(stmt.?));
        while (true) {
            const rc = sqlite3_step(stmt.?);
            if (rc == done) return out.items;
            if (rc & 0xff == constraint) return error.Constraint;
            if (rc != row) return error.SqlFailed;
            const values = try db.gpa.alloc(Cell, columns);
            for (values, 0..) |*v, i| {
                const at: c_int = @intCast(i);
                v.* = switch (sqlite3_column_type(stmt.?, at)) {
                    null_type => .null,
                    integer_type => .{ .int = sqlite3_column_int64(stmt.?, at) },
                    else => .{ .text = try db.gpa.dupe(
                        u8,
                        (sqlite3_column_text(stmt.?, at) orelse
                            return error.SqlFailed)[0..@intCast(sqlite3_column_bytes(stmt.?, at))],
                    ) },
                };
            }
            try out.append(db.gpa, values);
        }
    }
};
