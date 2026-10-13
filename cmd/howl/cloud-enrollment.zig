//! Pin provider-authenticated public TPM identities before any cloud enrollment.
const std = @import("std");
const howl = @import("howl.zig");
const apk = @import("apk");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const Identity = struct {
    provider: []const u8,
    resource: []const u8,
    scope: []const u8,
    instance_id: []const u8,
    endorsement_key: []const u8,
};

pub fn retrieve(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 3) return why.refuse("_cloud-ek aws|gcp INSTANCE OUTPUT.json", .{});
    if (!validResource(args[0], args[1])) return error.BadCloudResource;
    var identity: Identity = undefined;
    var command: []const []const u8 = undefined;
    if (std.mem.eql(u8, args[0], "aws")) {
        const place = try @import("aws.zig").place(io, gpa, why);
        identity = .{
            .provider = "aws",
            .resource = args[1],
            .scope = place.region,
            .instance_id = args[1],
            .endorsement_key = "",
        };
        command = &.{
            "aws",        "--region",                place.region,
            "ec2",        "get-instance-tpm-ek-pub", "--instance-id",
            args[1],      "--key-format",            "der",
            "--key-type", "rsa-2048",                "--output",
            "json",
        };
    } else if (std.mem.eql(u8, args[0], "gcp")) {
        const place = try @import("gcp.zig").place(io, gpa, why);
        identity = .{ .provider = "gcp", .resource = args[1], .scope = try gpa.print(
            "{s}/{s}",
            .{ place.project, place.zone },
        ), .instance_id = try googleId(io, gpa, place, args[1]), .endorsement_key = "" };
        command = &.{
            "gcloud",                "--quiet", "--project", place.project, "compute",  "instances",
            "get-shielded-identity", args[1],   "--zone",    place.zone,    "--format", "json",
        };
    } else return why.refuse("cloud TPM identity retrieval currently supports aws and gcp", .{});
    const result = try std.process.run(
        gpa,
        io,
        .{ .argv = command, .stdout_limit = .limited(8193), .stderr_limit = .limited(8192) },
    );
    if (result.term != .exited or result.term.exited != 0)
        return why.refuse(
            "retrieving the provider TPM identity failed: {s}",
            .{std.mem.trim(u8, result.stderr, "\r\n")},
        );
    identity.endorsement_key = if (std.mem.eql(u8, identity.provider, "aws"))
        try awsKey(gpa, identity.resource, result.stdout)
    else
        try gcpKey(gpa, result.stdout);
    if (std.mem.eql(u8, identity.provider, "gcp")) {
        const place = try @import("gcp.zig").place(io, gpa, why);
        const current = try googleId(io, gpa, place, identity.resource);
        if (!std.mem.eql(u8, current, identity.instance_id) or
            !std.mem.eql(
                u8,
                identity.scope,
                try gpa.print("{s}/{s}", .{ place.project, place.zone }),
            ))
            return error.CloudTpmIdentityChanged;
    }
    const encoded = try std.json.Stringify.valueAlloc(gpa, identity, .{});
    const old = Io.Dir.cwd().readFileAlloc(
        io,
        args[2],
        gpa,
        .limited(8193),
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (old) |saved| {
        const pinned = try std.json.parseFromSliceLeaky(Identity, gpa, saved, .{});
        if (!same(pinned, identity)) return error.CloudTpmIdentityChanged;
        return;
    }
    try @import("enrollment.zig").durable(io, args[2], encoded);
}

fn same(a: Identity, b: Identity) bool {
    return std.mem.eql(u8, a.provider, b.provider) and
        std.mem.eql(u8, a.resource, b.resource) and
        std.mem.eql(u8, a.scope, b.scope) and
        std.mem.eql(u8, a.instance_id, b.instance_id) and
        std.mem.eql(u8, a.endorsement_key, b.endorsement_key);
}

fn googleId(
    io: Io,
    gpa: Allocator,
    place: @import("gcp.zig").Place,
    resource: []const u8,
) ![]const u8 {
    const result = try std.process.run(gpa, io, .{
        .argv = &.{
            "gcloud",   "--quiet", "--project", place.project, "compute",            "instances",
            "describe", resource,  "--zone",    place.zone,    "--format=value(id)",
        },
        .stdout_limit = .limited(64),
        .stderr_limit = .limited(8192),
    });
    if (result.term != .exited or result.term.exited != 0) return error.BadCloudResource;
    const id = std.mem.trim(u8, result.stdout, "\r\n");
    if (id.len == 0 or id[0] == '0') return error.BadCloudResource;
    for (id) |byte| if (!std.ascii.isDigit(byte)) return error.BadCloudResource;
    _ = std.fmt.parseInt(u64, id, 10) catch return error.BadCloudResource;
    return id;
}

fn validResource(provider: []const u8, resource: []const u8) bool {
    if (std.mem.eql(u8, provider, "aws")) {
        if ((resource.len != 10 and resource.len != 19) or
            !std.mem.startsWith(u8, resource, "i-")) return false;
        for (resource[2..]) |byte|
            if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
        return true;
    }
    if (!std.mem.eql(u8, provider, "gcp") or resource.len == 0 or resource.len > 63)
        return false;
    if (resource[0] < 'a' or resource[0] > 'z' or resource[resource.len - 1] == '-')
        return false;
    for (resource) |byte|
        if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'z') and byte != '-')
            return false;
    return true;
}

pub fn awsKey(gpa: Allocator, instance: []const u8, raw: []const u8) ![]const u8 {
    if (raw.len > 8192) return error.BadCloudTpmIdentity;
    const response = std.json.parseFromSliceLeaky(struct {
        InstanceId: []const u8,
        KeyFormat: []const u8,
        KeyType: []const u8,
        KeyValue: []const u8,
    }, gpa, raw, .{ .ignore_unknown_fields = true }) catch return error.BadCloudTpmIdentity;
    if (!std.mem.eql(u8, response.InstanceId, instance) or
        !std.mem.eql(u8, response.KeyFormat, "der") or
        !std.mem.eql(u8, response.KeyType, "rsa-2048") or response.KeyValue.len > 512)
        return error.BadCloudTpmIdentity;
    return canonical(
        gpa,
        try gpa.print(
            "-----BEGIN PUBLIC KEY-----\n{s}\n-----END PUBLIC KEY-----\n",
            .{response.KeyValue},
        ),
    );
}

pub fn gcpKey(gpa: Allocator, raw: []const u8) ![]const u8 {
    if (raw.len > 8192) return error.BadCloudTpmIdentity;
    const response = std.json.parseFromSliceLeaky(struct {
        encryptionKey: struct { ekPub: []const u8 },
    }, gpa, raw, .{ .ignore_unknown_fields = true }) catch return error.BadCloudTpmIdentity;
    return canonical(gpa, response.encryptionKey.ekPub);
}

fn canonical(gpa: Allocator, pem: []const u8) ![]const u8 {
    const begin = "-----BEGIN PUBLIC KEY-----";
    const end = "-----END PUBLIC KEY-----";
    const trimmed = std.mem.trim(u8, pem, " \r\n\t");
    if (trimmed.len > 1024 or !std.mem.startsWith(u8, trimmed, begin) or
        !std.mem.endsWith(u8, trimmed, end)) return error.BadCloudTpmIdentity;
    const key = apk.parseKey(gpa, trimmed) catch return error.BadCloudTpmIdentity;
    if (key.modulus.len != 256 or !std.mem.eql(u8, key.exponent, &.{ 1, 0, 1 }))
        return error.UnsupportedEndorsementKey;
    var body: std.ArrayList(u8) = .empty;
    for (trimmed[begin.len .. trimmed.len - end.len]) |byte|
        if (!std.ascii.isWhitespace(byte)) try body.append(gpa, byte);
    return gpa.print("{s}\n{s}\n{s}\n", .{ begin, body.items, end });
}

test "cloud EK replies bind AWS resource and accept only public RSA encryption keys" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const public = try Io.Dir.cwd().readFileAlloc(
        t.io,
        "lib/testdata/tpm-ab/signer.pub",
        gpa,
        .limited(1024),
    );
    const normalized = try canonical(gpa, public);
    var lines = std.mem.splitScalar(u8, normalized, '\n');
    _ = lines.next();
    const encoded = lines.next().?;
    const raw = try std.json.Stringify.valueAlloc(gpa, .{
        .InstanceId = "i-test",
        .KeyFormat = "der",
        .KeyType = "rsa-2048",
        .KeyValue = encoded,
    }, .{});
    try t.expectEqualStrings(normalized, try awsKey(gpa, "i-test", raw));
    try t.expectError(error.BadCloudTpmIdentity, awsKey(gpa, "i-foreign", raw));
    const google = try std.json.Stringify.valueAlloc(
        gpa,
        .{ .encryptionKey = .{ .ekPub = public } },
        .{},
    );
    try t.expectEqualStrings(normalized, try gcpKey(gpa, google));
    try t.expectError(error.BadCloudTpmIdentity, gcpKey(gpa, "{}"));
    try t.expectError(
        error.BadCloudTpmIdentity,
        gcpKey(gpa, "{\"signingKey\":{\"ekPub\":\"wrong\"}}"),
    );
    try t.expectError(
        error.BadCloudTpmIdentity,
        canonical(gpa, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
    );
    try t.expectError(
        error.BadCloudTpmIdentity,
        awsKey(gpa, "i-test", &(@as([8193]u8, @splat('x')))),
    );
}

test "a pinned cloud identity cannot silently move between resources or regions" {
    const a: Identity = .{
        .provider = "aws",
        .resource = "i-original",
        .scope = "us-west-2",
        .instance_id = "i-original",
        .endorsement_key = "key",
    };
    var b = a;
    try std.testing.expect(same(a, b));
    b.resource = "i-replacement";
    try std.testing.expect(!same(a, b));
    b = a;
    b.scope = "us-west-1";
    try std.testing.expect(!same(a, b));
    b = a;
    b.endorsement_key = "another key";
    try std.testing.expect(!same(a, b));
    b = a;
    b.instance_id = "replacement instance";
    try std.testing.expect(!same(a, b));
}

test "provider resource names cannot become CLI options" {
    const t = std.testing;
    try t.expect(validResource("aws", "i-0123456789abcdef0"));
    try t.expect(validResource("aws", "i-12345678"));
    try t.expect(!validResource("aws", "i-TEST"));
    try t.expect(!validResource("aws", "--endpoint-url=untrusted"));
    try t.expect(validResource("gcp", "werewolf-test-1"));
    try t.expect(!validResource("gcp", "--project=another"));
    try t.expect(!validResource("gcp", "Bad_Name"));
    try t.expect(!validResource("gcp", "trailing-"));
}
