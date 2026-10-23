//! Single-writer SQLite foundation for the isolated domain-age worker.
//! Only that worker may construct a Db; the DNS frontend never links SQLite.
const std = @import("std");

const sqlite3 = opaque {};
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

const ok = 0;
const open_readwrite = 0x00000002;
const open_create = 0x00000004;
const open_nomutex = 0x00008000;
const open_nofollow = 0x01000000;

pub const Db = struct {
    handle: *sqlite3,

    /// The worker's private mount namespace supplies the writable directory.
    /// The caller must restrict the path to that directory before opening.
    pub fn open(path: [*:0]const u8) !Db {
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
        try db.exec(@embedFile("age.sql"));
        return db;
    }

    pub fn close(db: *Db) void {
        if (sqlite3_close(db.handle) != ok) @panic("age SQLite close failed");
    }

    fn exec(db: *Db, sql: [*:0]const u8) !void {
        if (sqlite3_exec(db.handle, sql, null, null, null) != ok) return error.SQLite;
    }
};

test "pinned static SQLite opens the age schema with foreign keys" {
    var db = try Db.open(":memory:");
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
