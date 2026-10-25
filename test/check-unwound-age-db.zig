//! check-unwound-age-db holds cmd/unwound/age.sql to its promises, through
//! the pinned SQLite: an age check's request and provenance are immutable,
//! process identity is never invented, a cached row pins only its own
//! domain's check, and both tables stay bounded without losing that check.
//!
//!     check-unwound-age-db cmd/unwound/age.sql
const std = @import("std");
const sqlite = @import("host").sqlite;

const insert_check =
    \\INSERT INTO age_check
    \\  (domain, started_at, cause, request_id, dns_id, qname, qtype,
    \\   transport, source_label, service_uid, policy_namespace,
    \\   policy_generation, provenance
;
const request = [_]sqlite.Cell{
    .{ .text = "example.com" }, .{ .int = 1790000000 }, .{ .text = "miss" },
    .{ .int = 17 },             .{ .int = 1234 },       .{ .text = "www.example.com" },
    .{ .int = 1 },              .{ .text = "udp" },     .{ .text = "127.53.0.8" },
    .{ .int = 208 },            .{ .text = "web" },     .{ .int = 4 },
    .{ .text = "uid_only" },
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 2) return error.Usage;
    const schema = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], gpa, .limited(1 << 20));
    const db: sqlite.Db = try .open(gpa, ":memory:", .read_write);
    defer db.close();
    check(gpa, db, schema) catch |err| {
        std.debug.print("check-unwound-age-db: {t}: {s}\n", .{ err, db.message() });
        return err;
    };
    std.debug.print(
        "check-unwound-age-db: provenance, evidence and eviction constraints pass\n",
        .{},
    );
}

fn check(gpa: std.mem.Allocator, db: sqlite.Db, schema: []const u8) !void {
    try db.exec("PRAGMA foreign_keys=ON");
    try db.exec(schema);
    try expect(db, "PRAGMA user_version", &.{}, &.{.{ .int = 1 }});

    try db.run(insert_check ++ ")\n VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", &request);
    const check_id = (try db.one("SELECT id FROM age_check", &.{})).?[0];
    try db.run(
        \\INSERT INTO domain_age
        \\  (domain, source, status, registered_at, effective_at, fetched_at,
        \\   retry_after, last_used_at, psl_generation, bootstrap_generation,
        \\   last_check_id)
        \\ VALUES (?, 'rdap', 'valid', ?, ?, ?, ?, ?, ?, ?, ?)
    , &.{
        .{ .text = "example.com" }, .{ .int = 1500000000 },     .{ .int = 1500000000 },
        .{ .int = 1790000000 },     .{ .int = 1790086400 },     .{ .int = 1790000000 },
        .{ .text = "psl-1" },       .{ .text = "bootstrap-1" }, check_id,
    });
    try expect(
        db,
        "SELECT qname, service_uid, policy_namespace, process_pid FROM age_check WHERE id = ?",
        &.{check_id},
        &.{ .{ .text = "www.example.com" }, .{ .int = 208 }, .{ .text = "web" }, .null },
    );

    // A uid-only check may not claim a process, column by column.
    inline for (.{ "process_pid", "process_start_ticks", "process_exe", "netns_inode" }, .{
        sqlite.Cell{ .int = 123 },
        sqlite.Cell{ .int = 456 },
        sqlite.Cell{ .text = "/usr/bin/invented" },
        sqlite.Cell{ .int = 789 },
    }) |column, value| try rejected(
        db,
        insert_check ++ ", " ++ column ++ ")\n VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &(request ++ [_]sqlite.Cell{value}),
    );
    try rejected(db,
        \\UPDATE age_check SET provenance='kernel_verified', process_pid=123,
        \\  process_start_ticks=456, process_exe='/usr/bin/invented', netns_inode=789
        \\ WHERE id=?
    , &.{check_id});
    try rejected(db,
        \\INSERT INTO domain_age
        \\  (domain, source, status, fetched_at, retry_after, last_used_at,
        \\   psl_generation, bootstrap_generation, last_check_id)
        \\ VALUES ('other.example', 'none', 'unknown', 1, 2, 1, 'psl-1', 'iana-1', ?)
    , &.{check_id});
    try rejected(
        db,
        "UPDATE domain_age SET domain = 'other.example' WHERE domain = 'example.com'",
        &.{},
    );
    try rejected(db, "UPDATE age_check SET domain = 'other.example' WHERE id = ?", &.{check_id});
    try db.run(
        "UPDATE age_check SET finished_at = ?, rdap_result = 'valid' WHERE id = ?",
        &.{ .{ .int = 1790000001 }, check_id },
    );
    try rejected(db,
        \\INSERT INTO domain_age
        \\  (domain, source, status, registered_at, effective_at, fetched_at,
        \\   retry_after, last_used_at, psl_generation, bootstrap_generation)
        \\ VALUES ('young.example', 'crtsh', 'valid', NULL, NULL,
        \\         1790000000, 1790086400, 1790000000, 'psl-1', 'bootstrap-1')
    , &.{});

    // Evicting a domain's cached verdict must not erase the triggering request.
    try db.run("DELETE FROM domain_age WHERE domain = 'example.com'", &.{});
    try expect(db, "SELECT qname FROM age_check WHERE id = ?", &.{check_id}, &.{
        .{ .text = "www.example.com" },
    });
    try db.run(
        \\INSERT INTO domain_age
        \\  (domain, source, status, fetched_at, retry_after, last_used_at,
        \\   psl_generation, bootstrap_generation, last_check_id)
        \\ VALUES ('example.com', 'none', 'unknown', 1790000000, 1790003600,
        \\         9999999, 'psl-1', 'bootstrap-1', ?)
    , &.{check_id});

    try db.exec("BEGIN");
    for (0..20001) |i| try db.run(
        \\INSERT INTO domain_age
        \\  (domain, source, status, fetched_at, retry_after, last_used_at,
        \\   psl_generation, bootstrap_generation)
        \\ VALUES (?, 'none', 'unknown', 1790000000, 1790003600, ?, 'psl-1', 'bootstrap-1')
    , &.{ .{ .text = try gpa.print("d{d}.example", .{i}) }, .{ .int = @intCast(i) } });
    try db.exec("COMMIT");
    const one: []const sqlite.Cell = &.{.{ .int = 1 }};
    try expect(db, "SELECT count(*) FROM domain_age", &.{}, &.{.{ .int = 20000 }});
    try expect(db, "SELECT 1 FROM domain_age WHERE domain='d0.example'", &.{}, null);
    try expect(db, "SELECT 1 FROM domain_age WHERE domain='d20000.example'", &.{}, one);
    try expect(db, "SELECT 1 FROM domain_age WHERE domain='example.com'", &.{}, one);

    try db.exec("BEGIN");
    for (0..120001) |i| try db.run(
        \\INSERT INTO age_check (domain, started_at, cause, provenance)
        \\ VALUES ('example.org', ?, 'refresh', 'scheduled')
    , &.{.{ .int = @intCast(i) }});
    try db.exec("COMMIT");
    const checks = (try db.one("SELECT count(*) FROM age_check", &.{})).?[0];
    if (checks != .int or checks.int > 120000) {
        std.debug.print("check-unwound-age-db: {any} age checks kept, past 120000\n", .{checks});
        return error.Unbounded;
    }
    try expect(db, "SELECT 1 FROM age_check WHERE id = ?", &.{check_id}, one);
}

/// rejected requires the schema to refuse sql as a constraint violation.
fn rejected(db: sqlite.Db, sql: []const u8, params: []const sqlite.Cell) !void {
    db.run(sql, params) catch |err| switch (err) {
        error.Constraint => return,
        else => return err,
    };
    std.debug.print("check-unwound-age-db: accepted invalid age evidence or " ++
        "invented process identity: {s}\n", .{sql});
    return error.Accepted;
}

/// expect requires sql's first row to be want, or no row when want is null.
fn expect(
    db: sqlite.Db,
    sql: []const u8,
    params: []const sqlite.Cell,
    want: ?[]const sqlite.Cell,
) !void {
    const got = try db.one(sql, params);
    if (if (got) |g| want != null and sqlite.eqlRow(g, want.?) else want == null) return;
    std.debug.print("check-unwound-age-db: {s}: got {any}, want {any}\n", .{ sql, got, want });
    return error.Mismatch;
}
