//! Single-writer SQLite foundation for the isolated domain-age worker.
//! Only that worker may construct a Db; the DNS frontend never links SQLite.
const std = @import("std");
const age = @import("age.zig");

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
extern "c" fn sqlite3_libversion_number() c_int;
extern "c" fn sqlite3_prepare_v2(
    *sqlite3,
    [*:0]const u8,
    c_int,
    *?*sqlite3_stmt,
    ?*anyopaque,
) c_int;
extern "c" fn sqlite3_bind_text(*sqlite3_stmt, c_int, [*]const u8, c_int, ?*const anyopaque) c_int;
extern "c" fn sqlite3_bind_int64(*sqlite3_stmt, c_int, i64) c_int;
extern "c" fn sqlite3_bind_null(*sqlite3_stmt, c_int) c_int;
extern "c" fn sqlite3_step(*sqlite3_stmt) c_int;
extern "c" fn sqlite3_finalize(*sqlite3_stmt) c_int;
extern "c" fn sqlite3_last_insert_rowid(*sqlite3) i64;
extern "c" fn sqlite3_changes(*sqlite3) c_int;
extern "c" fn sqlite3_column_int64(*sqlite3_stmt, c_int) i64;
extern "c" fn sqlite3_column_type(*sqlite3_stmt, c_int) c_int;
extern "c" fn sqlite3_column_text(*sqlite3_stmt, c_int) ?[*]const u8;
extern "c" fn sqlite3_column_bytes(*sqlite3_stmt, c_int) c_int;

const ok = 0;
const done = 101;
const row = 100;
const null_type = 5;
const open_readwrite = 0x00000002;
const open_create = 0x00000004;
const open_nomutex = 0x00008000;
const open_nofollow = 0x01000000;

pub const Trigger = struct {
    domain: []const u8,
    started_at: i64,
    cause: enum { miss, retry },
    request_id: i64,
    dns_id: u16,
    qname: []const u8,
    qtype: u16,
    transport: enum { udp, tcp },
    source_label: []const u8,
    service_uid: i64,
    policy_namespace: []const u8,
    policy_generation: i64,
};

pub const Result = struct {
    domain: []const u8,
    finished_at: i64,
    rdap_result: enum { valid, unknown, @"error" },
    crtsh_result: ?enum { history, none, @"error" } = null,
    source: enum { rdap, crtsh, none },
    status: enum { valid, history, unknown, @"error" },
    registered_at: ?i64 = null,
    effective_at: ?i64 = null,
    ct_first_seen_at: ?i64 = null,
    fetched_at: i64,
    retry_after: i64,
    evidence_uri: ?[]const u8 = null,
    psl_generation: []const u8,
    bootstrap_generation: []const u8,
};

const Statement = struct {
    handle: *sqlite3_stmt,

    fn text(s: *Statement, n: c_int, value: []const u8) !void {
        if (value.len > std.math.maxInt(c_int)) return error.InputTooLong;
        if (sqlite3_bind_text(s.handle, n, value.ptr, @intCast(value.len), null) != ok)
            return error.SQLite;
    }

    fn integer(s: *Statement, n: c_int, value: i64) !void {
        if (sqlite3_bind_int64(s.handle, n, value) != ok) return error.SQLite;
    }

    fn optionalInteger(s: *Statement, n: c_int, value: ?i64) !void {
        if (value) |v| return s.integer(n, v);
        if (sqlite3_bind_null(s.handle, n) != ok) return error.SQLite;
    }

    fn optionalText(s: *Statement, n: c_int, value: ?[]const u8) !void {
        if (value) |v| return s.text(n, v);
        if (sqlite3_bind_null(s.handle, n) != ok) return error.SQLite;
    }

    fn run(s: *Statement) !void {
        if (sqlite3_step(s.handle) != done) return error.SQLite;
    }

    fn close(s: *Statement) void {
        _ = sqlite3_finalize(s.handle);
    }
};

pub const Db = struct {
    handle: *sqlite3,

    /// The worker's private mount namespace supplies the writable directory.
    /// The caller must restrict the path to that directory before opening.
    pub fn open(path: [*:0]const u8) !Db {
        return openWith(path, true);
    }

    fn openWith(path: [*:0]const u8, require_wal: bool) !Db {
        if (sqlite3_libversion_number() != 3054001) return error.UnexpectedSQLite;
        var handle: ?*sqlite3 = null;
        if (sqlite3_open_v2(
            path,
            &handle,
            open_readwrite | open_create | open_nomutex | open_nofollow,
            null,
        ) != ok) {
            if (handle) |db| _ = sqlite3_close(db);
            return error.OpenFailed;
        }
        var db: Db = .{ .handle = handle.? };
        errdefer db.close();
        try db.exec("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;" ++
            " PRAGMA busy_timeout=1000; PRAGMA journal_mode=WAL;");
        if (require_wal) {
            var s = try db.prepare("PRAGMA journal_mode");
            defer s.close();
            if (sqlite3_step(s.handle) != row or
                !std.mem.eql(u8, columnText(s.handle, 0) orelse "", "wal"))
                return error.NotWal;
        }
        try db.exec(@embedFile("age.sql"));
        return db;
    }

    pub fn close(db: *Db) void {
        if (sqlite3_close(db.handle) != ok) @panic("age SQLite close failed");
    }

    fn exec(db: *Db, sql: [*:0]const u8) !void {
        if (sqlite3_exec(db.handle, sql, null, null, null) != ok) return error.SQLite;
    }

    fn prepare(db: *Db, sql: [*:0]const u8) !Statement {
        var handle: ?*sqlite3_stmt = null;
        if (sqlite3_prepare_v2(db.handle, sql, -1, &handle, null) != ok) return error.SQLite;
        return .{ .handle = handle orelse return error.SQLite };
    }

    /// Record the first DNS request before contacting an external provider.
    /// Individual process fields remain NULL: a source label proves UID only.
    pub fn beginCheck(db: *Db, t: Trigger) !i64 {
        var s = try db.prepare(
            "INSERT INTO age_check (domain,started_at,cause,request_id,dns_id,qname," ++
                "qtype,transport,source_label,service_uid,policy_namespace," ++
                "policy_generation,provenance) VALUES (?1,?2,?3,?4,?5,?6," ++
                "?7,?8,?9,?10,?11,?12,'uid_only')",
        );
        defer s.close();
        try s.text(1, t.domain);
        try s.integer(2, t.started_at);
        try s.text(3, @tagName(t.cause));
        try s.integer(4, t.request_id);
        try s.integer(5, t.dns_id);
        try s.text(6, t.qname);
        try s.integer(7, t.qtype);
        try s.text(8, @tagName(t.transport));
        try s.text(9, t.source_label);
        try s.integer(10, t.service_uid);
        try s.text(11, t.policy_namespace);
        try s.integer(12, t.policy_generation);
        try s.run();
        return sqlite3_last_insert_rowid(db.handle);
    }

    /// Finish the audit row and replace cached evidence in one transaction.
    /// A crash before COMMIT leaves the preceding evidence intact.
    pub fn finishCheck(db: *Db, id: i64, result: Result) !void {
        try db.exec("BEGIN IMMEDIATE");
        errdefer db.exec("ROLLBACK") catch {};
        {
            var s = try db.prepare("UPDATE age_check SET finished_at=?1,rdap_result=?2," ++
                "crtsh_result=?3 WHERE id=?4 AND domain=?5 AND finished_at IS NULL");
            defer s.close();
            try s.integer(1, result.finished_at);
            try s.text(2, @tagName(result.rdap_result));
            try s.optionalText(3, if (result.crtsh_result) |v| @tagName(v) else null);
            try s.integer(4, id);
            try s.text(5, result.domain);
            try s.run();
            if (sqlite3_changes(db.handle) != 1) return error.CheckMismatch;
        }
        {
            var s = try db.prepare(
                "INSERT INTO domain_age (domain,source,status,registered_at,effective_at," ++
                    "ct_first_seen_at,fetched_at,retry_after,last_used_at,evidence_uri," ++
                    "psl_generation,bootstrap_generation,last_check_id) VALUES " ++
                    "(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) " ++
                    "ON CONFLICT(domain) DO UPDATE SET source=excluded.source," ++
                    "status=excluded.status,registered_at=excluded.registered_at," ++
                    "effective_at=excluded.effective_at," ++
                    "ct_first_seen_at=excluded.ct_first_seen_at," ++
                    "fetched_at=excluded.fetched_at,retry_after=excluded.retry_after," ++
                    "last_used_at=excluded.last_used_at,evidence_uri=excluded.evidence_uri," ++
                    "psl_generation=excluded.psl_generation," ++
                    "bootstrap_generation=excluded.bootstrap_generation," ++
                    "last_check_id=excluded.last_check_id " ++
                    "WHERE excluded.fetched_at > domain_age.fetched_at OR " ++
                    "(excluded.fetched_at = domain_age.fetched_at AND " ++
                    "excluded.last_check_id > coalesce(domain_age.last_check_id,0))",
            );
            defer s.close();
            try s.text(1, result.domain);
            try s.text(2, @tagName(result.source));
            try s.text(3, @tagName(result.status));
            try s.optionalInteger(4, result.registered_at);
            try s.optionalInteger(5, result.effective_at);
            try s.optionalInteger(6, result.ct_first_seen_at);
            try s.integer(7, result.fetched_at);
            try s.integer(8, result.retry_after);
            try s.integer(9, result.finished_at);
            try s.optionalText(10, result.evidence_uri);
            try s.text(11, result.psl_generation);
            try s.text(12, result.bootstrap_generation);
            try s.integer(13, id);
            try s.run();
        }
        try db.exec("COMMIT");
    }

    /// Read dated evidence only. The verdict is always recomputed against now.
    /// Touch an LRU row at most once per hour to avoid one WAL write per DNS
    /// query while keeping active domains in the 20,000-row cache.
    pub fn decision(db: *Db, domain: []const u8, now: i64) !age.Decision {
        const found = try db.readDecision(domain, now) orelse
            return .{ .source = .none, .verdict = .unknown };
        if (now >= 3600) {
            var s = try db.prepare("UPDATE domain_age SET last_used_at=?2 " ++
                "WHERE domain=?1 AND last_used_at<=?3");
            defer s.close();
            try s.text(1, domain);
            try s.integer(2, now);
            try s.integer(3, now - 3600);
            try s.run();
        }
        return found;
    }

    fn readDecision(db: *Db, domain: []const u8, now: i64) !?age.Decision {
        var s = try db.prepare("SELECT source,status,registered_at,effective_at," ++
            "ct_first_seen_at,fetched_at FROM domain_age WHERE domain=?1");
        defer s.close();
        try s.text(1, domain);
        const rc = sqlite3_step(s.handle);
        if (rc == done) return null;
        if (rc != row) return error.SQLite;
        const source = columnText(s.handle, 0) orelse return error.Corrupt;
        const status = columnText(s.handle, 1) orelse return error.Corrupt;
        const evidence: age.Cached = .{
            .domain = domain,
            .source = if (std.mem.eql(u8, source, "rdap"))
                .rdap
            else if (std.mem.eql(u8, source, "crtsh"))
                .crtsh
            else if (std.mem.eql(u8, source, "none"))
                .none
            else
                return error.Corrupt,
            .status = if (std.mem.eql(u8, status, "valid"))
                .valid
            else if (std.mem.eql(u8, status, "history"))
                .history
            else if (std.mem.eql(u8, status, "unknown"))
                .unknown
            else if (std.mem.eql(u8, status, "error"))
                .@"error"
            else
                return error.Corrupt,
            .registered_at = columnOptionalInt(s.handle, 2),
            .effective_at = columnOptionalInt(s.handle, 3),
            .ct_first_seen_at = columnOptionalInt(s.handle, 4),
            .fetched_at = sqlite3_column_int64(s.handle, 5),
        };
        return .{
            .source = switch (evidence.source) {
                .rdap => .rdap,
                .crtsh => .crtsh,
                .none => .none,
            },
            .verdict = age.cachedVerdict(evidence, domain, now),
        };
    }
};

fn columnText(s: *sqlite3_stmt, index: c_int) ?[]const u8 {
    const ptr = sqlite3_column_text(s, index) orelse return null;
    const len = sqlite3_column_bytes(s, index);
    if (len < 0) return null;
    return ptr[0..@intCast(len)];
}

fn columnOptionalInt(s: *sqlite3_stmt, index: c_int) ?i64 {
    return if (sqlite3_column_type(s, index) == null_type) null else sqlite3_column_int64(s, index);
}

test "pinned static SQLite opens the age schema with foreign keys" {
    try std.testing.expectError(error.NotWal, Db.open(":memory:"));
    var db = try Db.openWith(":memory:", false);
    defer db.close();
    try db.exec(
        "INSERT INTO age_check (domain,started_at,cause,request_id,dns_id,qname,qtype," ++
            "transport,source_label,service_uid,policy_namespace,policy_generation,provenance)" ++
            " VALUES ('example.com',100,'miss',1,42,'a.example.com',1,'udp'," ++
            "'127.53.0.1',1001,'uid:1001',1,'uid_only');",
    );
    try db.exec(
        "INSERT INTO domain_age (domain,source,status,registered_at,effective_at," ++
            "fetched_at,retry_after,last_used_at,psl_generation,bootstrap_generation," ++
            "last_check_id) VALUES ('example.com','rdap','valid',1,1,100,200,100," ++
            "'test','test',1);",
    );
    try std.testing.expectError(error.SQLite, db.exec(
        "INSERT INTO domain_age (domain,source,status,registered_at,effective_at," ++
            "fetched_at,retry_after,last_used_at,psl_generation,bootstrap_generation," ++
            "last_check_id) VALUES ('other.com','rdap','valid',1,1,100,200,100," ++
            "'test','test',1);",
    ));
}

fn scalar(db: *Db, sql: [*:0]const u8) !i64 {
    var s = try db.prepare(sql);
    defer s.close();
    if (sqlite3_step(s.handle) != row) return error.SQLite;
    return sqlite3_column_int64(s.handle, 0);
}

test "age check provenance and evidence complete atomically" {
    const t = std.testing;
    var db = try Db.openWith(":memory:", false);
    defer db.close();
    const trigger: Trigger = .{
        .domain = "example.com",
        .started_at = 100,
        .cause = .miss,
        .request_id = 77,
        .dns_id = 42,
        .qname = "a.example.com",
        .qtype = 1,
        .transport = .udp,
        .source_label = "127.53.0.1",
        .service_uid = 1001,
        .policy_namespace = "uid:1001",
        .policy_generation = 9,
    };
    const id = try db.beginCheck(trigger);
    const good: Result = .{
        .domain = "example.com",
        .finished_at = 120,
        .rdap_result = .valid,
        .source = .rdap,
        .status = .valid,
        .registered_at = 1,
        .effective_at = 1,
        .fetched_at = 120,
        .retry_after = 120 + 7 * 86400,
        .evidence_uri = "https://rdap.example/",
        .psl_generation = "test-psl",
        .bootstrap_generation = "test-iana",
    };
    var wrong = good;
    wrong.domain = "other.com";
    try t.expectError(error.CheckMismatch, db.finishCheck(id, wrong));
    try t.expectEqual(@as(i64, 0), try scalar(&db, "SELECT count(*) FROM domain_age"));
    try t.expectEqual(
        @as(i64, 0),
        try scalar(&db, "SELECT count(*) FROM age_check WHERE finished_at IS NOT NULL"),
    );
    wrong = good;
    wrong.effective_at = 130;
    try t.expectError(error.SQLite, db.finishCheck(id, wrong));
    try t.expectEqual(@as(i64, 0), try scalar(&db, "SELECT count(*) FROM domain_age"));
    try db.finishCheck(id, good);
    try t.expectEqual(@as(
        i64,
        1,
    ), try scalar(&db, "SELECT count(*) FROM domain_age d JOIN age_check c ON " ++
        "d.last_check_id=c.id " ++
        "WHERE d.domain='example.com' AND c.request_id=77 AND c.service_uid=1001 " ++
        "AND c.provenance='uid_only' AND c.process_pid IS NULL"));
    try t.expectEqual(age.Verdict.young, (try db.decision("example.com", 120)).verdict);
    try t.expectEqual(
        age.Verdict.unknown,
        (try db.decision("example.com", 120 + age.rdap_cache_s + 1)).verdict,
    );
    try t.expectEqual(
        @as(i64, 120 + age.rdap_cache_s + 1),
        try scalar(&db, "SELECT last_used_at FROM domain_age WHERE domain='example.com'"),
    );
    try t.expectEqual(age.Verdict.unknown, (try db.decision("absent.com", 120)).verdict);
    try t.expectError(error.CheckMismatch, db.finishCheck(id, good));

    var newer_trigger = trigger;
    newer_trigger.request_id = 78;
    const slow = try db.beginCheck(newer_trigger);
    newer_trigger.request_id = 79;
    const fast = try db.beginCheck(newer_trigger);
    var newer = good;
    newer.finished_at = age.threshold_s + 200;
    newer.fetched_at = newer.finished_at;
    try db.finishCheck(fast, newer);
    var older = good;
    older.finished_at = newer.finished_at + 10;
    older.fetched_at = 130;
    try db.finishCheck(slow, older);
    try t.expectEqual(
        newer.fetched_at,
        try scalar(&db, "SELECT fetched_at FROM domain_age WHERE domain='example.com'"),
    );
    try t.expectEqual(
        fast,
        try scalar(&db, "SELECT last_check_id FROM domain_age WHERE domain='example.com'"),
    );
    const decision = try db.decision("example.com", newer.fetched_at);
    try t.expectEqual(age.Verdict.mature, decision.verdict);
    try t.expectEqual(.rdap, decision.source);
}
