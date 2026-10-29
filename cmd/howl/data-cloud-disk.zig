//! Provider storage transport. Only stopped, identity-bound machines qualify;
//! all guest filesystem interpretation remains inside the isolated helper.
const std = @import("std");
const howl = @import("howl.zig");
const cloud = @import("data-cloud.zig");
const Io = std.Io;
const Dir = Io.Dir;
const A = std.mem.Allocator;
const mem = std.mem;

pub fn copy(io: Io, a: A, name: []const u8, context: cloud.Context, arch: howl.Arch, work: []const u8, why: *howl.Why) ![]const u8 {
    const before = try stopped(io, a, name, context);
    var random: [12]u8 = undefined;
    try io.randomSecure(&random);
    const nonce = std.fmt.bytesToHex(random, .lower);
    const temporary = try a.print("ww-data-{s}", .{nonce});
    const raw = try a.print("{s}/cloud.raw", .{work});
    switch (context) {
        .azure => |c| {
            const snapshot = try azure(io, a, c.group, &.{ "snapshot", "create", "-n", temporary, "-l", c.location, "--source", before.disk, "--tags", "werewolf=transfer", "--query", "id", "-o", "tsv" });
            var deleted = false;
            defer if (!deleted) {
                _ = azure(io, a, c.group, &.{ "snapshot", "revoke-access", "--ids", snapshot, "-o", "none" }) catch {};
                _ = azure(io, a, c.group, &.{ "snapshot", "delete", "--ids", snapshot, "-o", "none" }) catch {
                    howl.say(io, "temporary snapshot {s} remains; revoke its access and delete it", .{snapshot});
                };
            };
            try unchanged(io, a, name, context, before);
            const sas = try azure(io, a, c.group, &.{ "snapshot", "grant-access", "--ids", snapshot, "--access-level", "Read", "--duration-in-seconds", "43200", "--query", "accessSas || accessSAS", "-o", "tsv" });
            const vhd = try a.print("{s}/cloud.vhd", .{work});
            try download(io, a, sas, vhd);
            _ = try azure(io, a, c.group, &.{ "snapshot", "revoke-access", "--ids", snapshot, "-o", "none" });
            _ = try azure(io, a, c.group, &.{ "snapshot", "delete", "--ids", snapshot, "-o", "none" });
            deleted = true;
            try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "vpc", "-O", "raw", vhd, raw });
        },
        .gcp => |c| {
            const enabled = try gcp(io, a, c.project, &.{ "services", "list", "--enabled", "--filter=config.name=cloudbuild.googleapis.com", "--format=value(config.name)" });
            if (!mem.eql(u8, enabled, "cloudbuild.googleapis.com")) return why.refuse(
                "GCP disk export needs Cloud Build: enable cloudbuild.googleapis.com and configure its image-export service account; see docs/data.md",
                .{},
            );
            const bucket = try a.print("gs://ww-data-{s}", .{nonce});
            const object = try a.print("{s}/disk.tar.gz", .{bucket});
            const region = c.zone[0 .. mem.findScalarLast(u8, c.zone, '-') orelse return error.TransferCloudPlace];
            _ = try gcp(io, a, c.project, &.{ "storage", "buckets", "create", bucket, "--location", region, "--uniform-bucket-level-access", "--public-access-prevention", "--soft-delete-duration=0" });
            var bucket_deleted = false;
            defer if (!bucket_deleted) {
                _ = gcp(io, a, c.project, &.{ "storage", "rm", object }) catch {};
                _ = gcp(io, a, c.project, &.{ "storage", "rm", "--recursive", bucket }) catch {
                    howl.say(io, "temporary bucket {s} remains; remove its objects and delete it", .{bucket});
                };
            };
            _ = try gcp(io, a, c.project, &.{ "compute", "images", "create", temporary, "--source-disk", before.disk, "--source-disk-zone", c.zone, "--architecture", @import("gcp.zig").machine(arch).arch });
            var image_deleted = false;
            defer if (!image_deleted) {
                _ = gcp(io, a, c.project, &.{ "compute", "images", "delete", temporary }) catch {
                    howl.say(io, "temporary image {s} remains in project {s}", .{ temporary, c.project });
                };
            };
            try unchanged(io, a, name, context, before);
            // The convenience `compute images export --quiet` command grants
            // IAM roles automatically and uses a shared scratch bucket. Submit
            // Google's documented exporter directly with existing permissions
            // and keep scratch, logs and output in our private temporary bucket.
            var args: std.ArrayList([]const u8) = .empty;
            try args.appendSlice(a, &.{ try a.print("-source_image=projects/{s}/global/images/{s}", .{ c.project, temporary }), try a.print("-destination_uri={s}", .{object}), try a.print("-scratch_bucket_gcs_path={s}/scratch/", .{bucket}), try a.print("-project={s}", .{c.project}), try a.print("-zone={s}", .{c.zone}), "-timeout=12h" });
            if (howl.environ.get("WEREWOLF_GCP_EXPORT_ACCOUNT")) |account| try args.append(a, try a.print("-compute_service_account={s}", .{account}));
            const config = try a.print("{s}/export-build.json", .{work});
            try Dir.cwd().writeFile(io, .{ .sub_path = config, .data = try std.json.Stringify.valueAlloc(a, .{
                .steps = .{.{ .name = "gcr.io/compute-image-import/gce_vm_image_export:release", .args = args.items }},
                .timeout = "43200s",
                .logsBucket = bucket,
                .options = .{ .logging = "GCS_ONLY" },
            }, .{}), .flags = .{ .permissions = .fromMode(0o600) } });
            _ = try gcp(io, a, c.project, &.{ "builds", "submit", "--no-source", "--config", config, "--region", region, "--timeout=12h" });
            const tarball = try a.print("{s}/cloud.tar.gz", .{work});
            try downloadConfig(io, a, try urlConfig(a, try a.print("https://storage.googleapis.com/{s}/disk.tar.gz", .{bucket[5..]})), tarball, c.project);
            const file = try Dir.cwd().createFile(io, raw, .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer file.close(io);
            // The provider creates one fixed disk.raw member. This never
            // extracts archive names, permissions or links onto the host.
            var unpack = try std.process.spawn(io, .{ .argv = &.{ "bsdtar", "-xOf", tarball, "disk.raw" }, .stdin = .ignore, .stdout = .{ .file = file }, .stderr = .ignore });
            defer unpack.kill(io);
            if (!(try unpack.wait(io)).success()) return error.TransferCloudDisk;
            try file.sync(io);
            _ = try gcp(io, a, c.project, &.{ "compute", "images", "delete", temporary });
            image_deleted = true;
            _ = try gcp(io, a, c.project, &.{ "storage", "rm", object });
            _ = try gcp(io, a, c.project, &.{ "storage", "rm", "--recursive", bucket });
            bucket_deleted = true;
        },
    }
    try unchanged(io, a, name, context, before);
    try Dir.cwd().setFilePermissions(io, raw, .fromMode(0o600), .{});
    return raw;
}

pub fn stopped(io: Io, a: A, name: []const u8, context: cloud.Context) !cloud.Machine {
    const machine = try cloud.state(io, a, name, context);
    if (machine.running) return error.TransferStorageInUse;
    return machine;
}

fn unchanged(io: Io, a: A, name: []const u8, context: cloud.Context, before: cloud.Machine) !void {
    const now = try stopped(io, a, name, context);
    if (!mem.eql(u8, now.disk, before.disk)) return error.TransferSourceChanged;
}

pub fn gcp(io: Io, a: A, project: []const u8, args: []const []const u8) ![]const u8 {
    return call(io, a, try mem.concat(a, []const u8, &.{ &.{ "gcloud", "--quiet", "--project", project }, args }));
}

pub fn azure(io: Io, a: A, group: []const u8, args: []const []const u8) ![]const u8 {
    for (args) |arg| if (mem.eql(u8, arg, "--ids")) return call(io, a, try mem.concat(a, []const u8, &.{ &.{"az"}, args }));
    return call(io, a, try mem.concat(a, []const u8, &.{ &.{"az"}, args, &.{ "--resource-group", group } }));
}

pub fn call(io: Io, a: A, args: []const []const u8) ![]const u8 {
    const result = try std.process.run(a, io, .{ .argv = args, .stdout_limit = .limited(1 << 20), .stderr_limit = .limited(16 << 10) });
    if (!result.term.success()) {
        // Command verbs diagnose the failing stage without exposing grant
        // responses, signed URLs, access tokens or provider response bodies.
        const start: usize = if (mem.eql(u8, args[0], "gcloud")) 4 else 1;
        howl.say(io, "{s} {s} {s}: cloud operation failed ({t}); provider response withheld", .{ args[0], args[start], args[start + 1], result.term });
        return error.TransferCloudOperation;
    }
    return mem.trim(u8, result.stdout, " \r\n");
}

pub fn download(io: Io, a: A, url: []const u8, path: []const u8) !void {
    const config = try urlConfig(a, url);
    return downloadConfig(io, a, config, path, null);
}

fn authenticatedConfig(io: Io, a: A, url: []const u8, project: ?[]const u8) ![]const u8 {
    const p = project orelse return url;
    const token = try gcp(io, a, p, &.{ "auth", "print-access-token" });
    if (token.len == 0 or token.len > 16384) return error.TransferCloudGrant;
    for (token) |ch| if (!std.ascii.isAlphanumeric(ch) and mem.findScalar(u8, "._~+-/=", ch) == null) return error.TransferCloudGrant;
    return a.print("{s}header = \"Authorization: Bearer {s}\"\n", .{ url, token });
}

fn downloadConfig(io: Io, a: A, url: []const u8, path: []const u8, project: ?[]const u8) !void {
    var config = try authenticatedConfig(io, a, url, project);
    var refreshed = Io.Clock.awake.now(io);
    const header = try request(io, a, config, &.{ "--head", "--output", "/dev/null", "--write-out", "%{http_code} %header{content-length}" });
    var fields = mem.tokenizeAny(u8, header, " \r\n");
    if (!mem.eql(u8, fields.next() orelse "", "200")) return error.TransferCloudDownload;
    const size = std.fmt.parseUnsigned(u64, fields.next() orelse "", 10) catch return error.TransferCloudDownload;
    if (size == 0 or size > (1 << 50) or fields.next() != null) return error.TransferCloudDisk;
    const file = try Dir.cwd().createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.setLength(io, size);
    var parts: [4][]const u8 = undefined;
    var made: usize = 0;
    defer for (parts[0..made]) |part| Dir.cwd().deleteFile(io, part) catch {};
    for (&parts, 0..) |*part, i| {
        part.* = try a.print("{s}.part-{d}", .{ path, i });
        const reserved = try Dir.cwd().createFile(io, part.*, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        reserved.close(io);
        made += 1;
    }
    var buffer: [64 << 10]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        if (project != null and refreshed.durationTo(Io.Clock.awake.now(io)).toSeconds() >= 60) {
            config = try authenticatedConfig(io, a, url, project);
            refreshed = Io.Clock.awake.now(io);
        }
        var children: [4]?std.process.Child = @splat(null);
        defer for (&children) |*child| if (child.*) |*active| active.kill(io);
        var counts: [4]u64 = @splat(0);
        var queued: u64 = 0;
        for (&children, 0..) |*child, i| {
            if (offset + queued == size) break;
            counts[i] = @min(@as(u64, 16 << 20), size - offset - queued);
            child.* = try spawnRequest(io, a, config, &.{ "--range", try a.print("{d}-{d}", .{ offset + queued, offset + queued + counts[i] - 1 }), "--max-filesize", try a.print("{d}", .{counts[i]}), "--output", parts[i], "--write-out", "%{http_code}" });
            queued += counts[i];
        }
        for (&children, 0..) |*child, i| {
            if (child.* == null) break;
            const status = try finishRequest(io, a, &child.*.?);
            child.* = null;
            if (!mem.eql(u8, status, "206")) return error.TransferCloudDownload;
            const chunk = try Dir.cwd().openFile(io, parts[i], .{});
            defer chunk.close(io);
            if ((try chunk.stat(io)).size != counts[i]) return error.TransferCloudDownload;
            var position: u64 = 0;
            while (position < counts[i]) {
                const n: usize = @intCast(@min(buffer.len, counts[i] - position));
                if (try chunk.readPositionalAll(io, buffer[0..n], position) != n) return error.TransferCloudDownload;
                if (!mem.allEqual(u8, buffer[0..n], 0)) try file.writePositionalAll(io, buffer[0..n], offset + position);
                position += n;
            }
            offset += counts[i];
        }
        if (offset % (1 << 30) == 0 or offset == size) howl.say(io, "storage: {d}/{d} MiB downloaded", .{ offset >> 20, size >> 20 });
    }
    try file.sync(io);
}

/// URLs and bearer tokens are supplied only on stdin. Curl reopens its private
/// output file on retry, so an interrupted request cannot append duplicate bytes.
fn request(io: Io, a: A, config: []const u8, args: []const []const u8) ![]const u8 {
    var child = try spawnRequest(io, a, config, args);
    defer child.kill(io);
    return finishRequest(io, a, &child);
}

fn spawnRequest(io: Io, a: A, config: []const u8, args: []const []const u8) !std.process.Child {
    const argv = try mem.concat(a, []const u8, &.{ &.{ "curl", "--disable", "--fail", "--silent", "--config", "-", "--proto", "=https", "--connect-timeout", "30", "--max-time", "600", "--retry", "3", "--retry-all-errors" }, args });
    var child = try std.process.spawn(io, .{ .argv = argv, .stdin = .pipe, .stdout = .pipe, .stderr = .ignore });
    errdefer child.kill(io);
    const input = child.stdin.?;
    child.stdin = null;
    {
        defer input.close(io);
        try input.writeStreamingAll(io, config);
    }
    return child;
}

fn finishRequest(io: Io, a: A, child: *std.process.Child) ![]const u8 {
    const output = child.stdout.?;
    child.stdout = null;
    defer output.close(io);
    var buffer: [128]u8 = undefined;
    var reader = output.readerStreaming(io, &buffer);
    const response = try reader.interface.allocRemaining(a, .limited(128));
    const term = try child.wait(io);
    if (!term.success()) {
        // Only the fixed numeric HTTP status may enter diagnostics.
        const code = if (response.len >= 3 and std.ascii.isDigit(response[0]) and std.ascii.isDigit(response[1]) and std.ascii.isDigit(response[2])) response[0..3] else "unknown";
        howl.say(io, "storage request failed: HTTP {s}, {any}; credentials withheld", .{ code, term });
        return error.TransferCloudDownload;
    }
    return response;
}

fn urlConfig(a: A, url: []const u8) ![]const u8 {
    if (!mem.startsWith(u8, url, "https://")) return error.TransferCloudUrl;
    for (url) |c| if (c < 0x21 or c > 0x7e or c == '"' or c == '\\') return error.TransferCloudUrl;
    return a.print("url = \"{s}\"\n", .{url});
}

/// Direct-upload disks already have their page blob allocated. Upload only
/// nonzero aligned pages; credentials travel on stdin, never in argv or logs.
pub fn uploadPages(io: Io, a: A, url: []const u8, path: []const u8, work: []const u8) !void {
    const config = try urlConfig(a, try a.print("{s}&comp=page", .{url}));
    const source = try Dir.cwd().openFile(io, path, .{});
    defer source.close(io);
    const size = (try source.stat(io)).size;
    if (size == 0 or size % 512 != 0) return error.TransferCloudDisk;
    const page_path = try a.print("{s}/upload.page", .{work});
    const page = try Dir.cwd().createFile(io, page_path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer page.close(io);
    defer Dir.cwd().deleteFile(io, page_path) catch {};
    const bytes = try a.alloc(u8, 4 << 20);
    defer a.free(bytes);
    var offset: u64 = 0;
    while (offset < size) {
        const n: usize = @intCast(@min(bytes.len, size - offset));
        if (try source.readPositionalAll(io, bytes[0..n], offset) != n) return error.TransferCloudDisk;
        if (!mem.allEqual(u8, bytes[0..n], 0)) {
            try page.setLength(io, n);
            try page.writePositionalAll(io, bytes[0..n], 0);
            var child = try std.process.spawn(io, .{ .argv = &.{
                "curl", "--disable", "--fail", "--silent", "--config", "-", "--proto", "=https", "--max-time", "600", "--request", "PUT", "--header", "x-ms-version: 2023-11-03", "--header", "x-ms-page-write: update", "--header", try a.print("x-ms-range: bytes={d}-{d}", .{ offset, offset + n - 1 }), "--upload-file", page_path,
            }, .stdin = .pipe, .stdout = .ignore, .stderr = .ignore });
            defer child.kill(io);
            const input = child.stdin.?;
            child.stdin = null;
            {
                defer input.close(io);
                try input.writeStreamingAll(io, config);
            }
            if (!(try child.wait(io)).success()) return error.TransferCloudUpload;
        }
        offset += n;
    }
}

test "signed storage URLs cannot inject curl configuration" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    _ = try urlConfig(a, "https://storage.example/blob?sig=a%2Fb&sp=r");
    for ([_][]const u8{ "http://storage.example/", "https://storage.example/\noutput=x", "https://storage.example/\"", "https://storage.example/\\", "https://storage.example/\r", "https://storage.example/\x7f" }) |url|
        try t.expectError(error.TransferCloudUrl, urlConfig(a, url));
}
