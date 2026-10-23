//! Bounded HTTPS reads for the age authority. The caller runs this
//! under a public-address TCP/443 fence rule and supplies a validated CA set.
//! No full QNAME reaches this module: only a registered domain from the PSL.
const std = @import("std");
const age = @import("age.zig");
const bootstrap = @import("bootstrap.zig");

const rdap_bootstrap = @embedFile("data/rdap-dns.json");
pub const rdap_max = 64 << 10;
pub const crtsh_max = 256 << 10;

pub const Rdap = struct {
    lookup: age.Lookup,
    /// The selected HTTPS endpoint, copied into the caller's URL buffer.
    url: ?[]const u8,
};

/// A non-200 registry reply is an RDAP response, not an availability failure,
/// except for rate limits and server errors. It cannot be replaced with CT.
pub fn rdap(
    client: *std.http.Client,
    domain: []const u8,
    url_buf: *[512]u8,
    body: *[rdap_max]u8,
) Rdap {
    const url = bootstrap.rdapUrl(std.heap.page_allocator, domain, rdap_bootstrap, url_buf) orelse
        return .{ .lookup = .{ .body = &.{} }, .url = null };
    const result = get(client, url, body) catch |err| return .{
        .lookup = if (unavailableError(err)) .unavailable else .{ .body = &.{} },
        .url = url,
    };
    return .{ .lookup = rdapStatus(result.status, result.body), .url = url };
}

fn rdapStatus(status: std.http.Status, body: []const u8) age.Lookup {
    return switch (status) {
        .ok => .{ .body = body },
        .too_many_requests,
        .internal_server_error,
        .bad_gateway,
        .service_unavailable,
        .gateway_timeout,
        => .unavailable,
        else => .{ .body = &.{} },
    };
}

/// CT can substitute only for a transport or registry availability failure.
/// TLS validation, redirects, malformed replies and local policy failures
/// cannot turn into provisional mature evidence.
fn unavailableError(err: anyerror) bool {
    return switch (err) {
        error.UnknownHostName,
        error.NameServerFailure,
        error.NoAddressReturned,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.Timeout,
        error.ReadFailed,
        => true,
        else => false,
    };
}

/// crt.sh is consulted only after an RDAP transport/server availability
/// failure. The caller still validates its JSON and date with age.crtsh.
pub fn crtsh(client: *std.http.Client, domain: []const u8, body: *[crtsh_max]u8) ?[]const u8 {
    if (!validDomain(domain)) return null;
    var url_buf: [320]u8 = undefined;
    const url = std.mem.print(&url_buf, "https://crt.sh/?q={s}&output=json", .{domain}) catch
        return null;
    const result = get(client, url, body) catch return null;
    return if (result.status == .ok) result.body else null;
}

const Response = struct { status: std.http.Status, body: []const u8 };

fn get(client: *std.http.Client, url: []const u8, body: []u8) !Response {
    var writer: std.Io.Writer = .fixed(body);
    const response = client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &writer,
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
    }) catch |err| {
        // A response that exceeds our buffer is invalid evidence, not an
        // outage for which old CT history may authorize a name.
        if (writer.end == body.len) return error.TooLarge;
        return err;
    };
    return .{ .status = response.status, .body = writer.buffered() };
}

fn validDomain(domain: []const u8) bool {
    if (domain.len == 0 or domain.len > 253 or domain[0] == '.' or
        domain[domain.len - 1] == '.') return false;
    var labels = std.mem.splitScalar(u8, domain, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or
            label[label.len - 1] == '-') return false;
        for (label) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-')
            return false;
    }
    return true;
}

test "only normalized domain names may initiate a CT request" {
    const t = std.testing;
    try t.expect(validDomain("example.com"));
    for ([_][]const u8{ "", ".com", "example.com.", "EXAMPLE.COM", "a/b.com", "-x.com" }) |bad|
        try t.expect(!validDomain(bad));
    var client: std.http.Client = undefined;
    var url: [512]u8 = undefined;
    var rdap_body: [rdap_max]u8 = undefined;
    var ct_body: [crtsh_max]u8 = undefined;
    try t.expect(rdap(&client, "EXAMPLE.COM", &url, &rdap_body).url == null);
    try t.expect(crtsh(&client, "EXAMPLE.COM", &ct_body) == null);
    try t.expect(unavailableError(error.ConnectionRefused));
    try t.expect(!unavailableError(error.TooManyHttpRedirects));
    try t.expect(!unavailableError(error.TlsInitializationFailed));
    try t.expect(!unavailableError(error.TooLarge));
    try t.expect(rdapStatus(.ok, "valid").body.len == 5);
    try t.expect(rdapStatus(.too_many_requests, "") == .unavailable);
    try t.expect(rdapStatus(.service_unavailable, "") == .unavailable);
    try t.expect(rdapStatus(.not_found, "").body.len == 0);
    try t.expect(rdapStatus(.moved_permanently, "").body.len == 0);
}
