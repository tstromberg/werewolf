//! Select a registry RDAP URL from an image-pinned IANA DNS bootstrap file.
//! The caller fetches only over HTTPS and checks the resolved address again.
const std = @import("std");
const mem = std.mem;

/// rdapUrl applies RFC 9224's label-wise longest match. The returned URL is
/// copied into out so it survives the bounded JSON parser's temporary arena.
/// A more-specific HTTP-only entry cannot fall back to a less-specific one.
pub fn rdapUrl(gpa: mem.Allocator, domain: []const u8, body: []const u8, out: []u8) ?[]const u8 {
    if (!validName(domain) or body.len == 0 or body.len > 1 << 20) return null;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const Service = [2][]const []const u8;
    const Registry = struct {
        version: []const u8,
        publication: []const u8,
        services: []const Service,
    };
    const data = std.json.parseFromSliceLeaky(
        Registry,
        arena.allocator(),
        body,
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    if (!mem.eql(u8, data.version, "1.0") or data.publication.len == 0 or
        data.services.len > 4096) return null;

    var best_labels: usize = 0;
    var best_url: ?[]const u8 = null;
    for (data.services) |service| {
        if (service[0].len > 256 or service[1].len > 16) return null;
        for (service[0]) |suffix| {
            if (!validName(suffix) or !labelSuffix(domain, suffix)) continue;
            const count = labels(suffix);
            if (count <= best_labels) continue;
            best_labels = count;
            best_url = null;
            for (service[1]) |url| {
                if (validBase(url)) {
                    best_url = url;
                    break;
                }
            }
        }
    }
    const base = best_url orelse return null;
    const segment = "domain/";
    if (base.len + segment.len + domain.len > out.len) return null;
    @memcpy(out[0..base.len], base);
    @memcpy(out[base.len..][0..segment.len], segment);
    @memcpy(out[base.len + segment.len ..][0..domain.len], domain);
    return out[0 .. base.len + segment.len + domain.len];
}

fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 253 or name[0] == '.' or name[name.len - 1] == '.')
        return false;
    var parts = mem.splitScalar(u8, name, '.');
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 63 or part[0] == '-' or part[part.len - 1] == '-')
            return false;
        for (part) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-')
            return false;
    }
    return true;
}

fn labelSuffix(name: []const u8, suffix: []const u8) bool {
    return mem.eql(u8, name, suffix) or
        (name.len > suffix.len and mem.endsWith(u8, name, suffix) and
            name[name.len - suffix.len - 1] == '.');
}

fn labels(name: []const u8) usize {
    var count: usize = 1;
    for (name) |c| if (c == '.') {
        count += 1;
    };
    return count;
}

fn validBase(url: []const u8) bool {
    const prefix = "https://";
    if (!mem.startsWith(u8, url, prefix) or url.len > 384 or url[url.len - 1] != '/')
        return false;
    const rest = url[prefix.len..];
    const slash = mem.indexOfScalar(u8, rest, '/') orelse return false;
    if (!validName(rest[0..slash])) return false;
    for (rest[slash..]) |c| {
        if (c < 0x21 or c > 0x7e or c == '?' or c == '#' or c == '\\') return false;
    }
    return true;
}

test "RDAP bootstrap picks the longest label match and requires HTTPS" {
    const t = std.testing;
    const body =
        "{\"version\":\"1.0\",\"publication\":\"2026-10-23T00:00:00Z\",\"services\":[" ++
        "[[\"com\"],[\"http://wrong.test/\",\"https://com.test/rdap/\"]]," ++
        "[[\"example.com\"],[\"https://specific.test/v1/\"]]," ++
        "[[\"blocked.com\"],[\"http://blocked.test/\"]]]}";
    var out: [512]u8 = undefined;
    try t.expectEqualStrings(
        "https://specific.test/v1/domain/a.example.com",
        rdapUrl(t.allocator, "a.example.com", body, &out).?,
    );
    try t.expectEqualStrings(
        "https://com.test/rdap/domain/goodexample.com",
        rdapUrl(t.allocator, "goodexample.com", body, &out).?,
    );
    try t.expect(rdapUrl(t.allocator, "blocked.com", body, &out) == null);
    try t.expect(rdapUrl(t.allocator, "evil.com.example", body, &out) == null);
    try t.expect(rdapUrl(t.allocator, "EXAMPLE.COM", body, &out) == null);
}

test "RDAP bootstrap rejects unsafe URL authorities and malformed files" {
    const t = std.testing;
    var out: [512]u8 = undefined;
    const prefix = "{\"version\":\"1.0\",\"publication\":\"now\",\"services\":[[[\"com\"],[\"";
    for ([_][]const u8{
        "https://user@evil.test/",
        "https://127.0.0.1:443/",
        "https://ok.test/?x=1",
        "https://ok.test/#fragment",
        "http://ok.test/",
    }) |bad| {
        const json = try mem.concat(t.allocator, u8, &.{ prefix, bad, "\"]]]}" });
        defer t.allocator.free(json);
        try t.expect(rdapUrl(t.allocator, "example.com", json, &out) == null);
    }
    try t.expect(rdapUrl(t.allocator, "example.com", "{}", &out) == null);
    try t.expect(rdapUrl(t.allocator, "example.com", "[]", &out) == null);
}
