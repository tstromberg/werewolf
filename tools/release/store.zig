//! store is where published objects go: the R2 bucket through aws, or a
//! directory, which tests and local mirrors use.

const std = @import("std");
const mem = std.mem;
const sys = @import("sys.zig");
const Sys = sys.Sys;

pub const endpoint = "https://c860af766754fb92eec27bc723e6db5d.r2.cloudflarestorage.com";

pub const Store = struct {
    /// bucket is s3://BUCKET/PREFIX or a directory.
    bucket: []const u8,

    pub fn init(bucket: []const u8) Store {
        return .{ .bucket = mem.trimEnd(u8, bucket, "/") };
    }

    /// remote says whether the bucket is R2, whose objects the public
    /// mirror serves.
    pub fn remote(st: Store) bool {
        return mem.startsWith(u8, st.bucket, "s3://");
    }

    /// fetch copies key to output and says whether the store had it.
    pub fn fetch(st: Store, s: *Sys, key: []const u8, output: []const u8) !bool {
        if (!st.remote()) {
            const source = try sys.join(s, &.{ st.bucket, key });
            if (!sys.exists(s, source)) return false;
            try sys.copy(s, source, output);
            return true;
        }
        const r = try sys.exec(s, &.{
            "aws",
            "s3",
            "cp",
            "--only-show-errors",
            "--endpoint-url",
            endpoint,
            try s.gpa.print("{s}/{s}", .{ st.bucket, key }),
            output,
        }, .{ .capture = .both, .env = try region(s) });
        if (r.ok()) return true;
        for ([_][]const u8{ "(404)", "NoSuchKey", "Not Found" }) |missing|
            if (mem.find(u8, r.stderr, missing) != null) return false;
        return s.refuse("protected object store read failed", .{});
    }

    /// upload puts source at key; an immutable object is cached for a year.
    pub fn upload(st: Store, s: *Sys, key: []const u8, source: []const u8, immutable: bool) !void {
        if (st.remote()) {
            const kind = if (mem.endsWith(u8, key, ".html"))
                "text/html; charset=utf-8"
            else if (mem.endsWith(u8, key, ".json"))
                "application/json"
            else
                "application/octet-stream";
            return sys.run(s, &.{
                "aws",                                           "s3",     "cp",
                "--only-show-error" ++
                    "s",
                "--endpoint-url",                                endpoint, "--cache-control",
                if (immutable)
                    "public,max-age=31536000,immutable"
                else
                    "no-cache",
                "--content-type",                                kind,     source,
                try s.gpa.print("{s}/{s}", .{ st.bucket, key }),
            }, .{ .env = try region(s) });
        }
        const destination = try sys.join(s, &.{ st.bucket, key });
        try sys.mkdirs(s, std.fs.path.dirname(destination).?);
        const incoming = try s.gpa.print("{s}.new", .{destination});
        try sys.copy(s, source, incoming);
        try sys.rename(s, incoming, destination);
    }
};

fn region(s: *Sys) !*const std.process.Environ.Map {
    const env = try s.gpa.create(std.process.Environ.Map);
    env.* = try s.env.clone(s.gpa);
    try env.put("AWS_DEFAULT_REGION", "auto");
    return env;
}
