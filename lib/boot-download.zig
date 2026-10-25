//! boot-download fetches protected boot bundles: public pins, sizes and
//! digests a signed head authenticates, and a release floor each channel
//! keeps atomically. howl installs with it and the release tools check
//! publications with it; the caller authenticates heads and bundles
//! (cmd/howl/boot-image.zig). See lib/README.md.

const std = @import("std");
const prebuilt = @import("prebuilt");
const policy = @import("update-policy");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const mem = std.mem;

/// names are a slot's files.
pub const names = prebuilt.names;
pub const head_limit = prebuilt.max_manifest;
pub const signature_limit = 512;
/// A channel checked this recently, in seconds, is not asked again.
pub const cache_seconds = 300;
pub const user_agent = "Werewolf-howl/1 (+https://github.com/werewolf-linux/werewolf)";
const releases = "https://github.com/werewolf-linux/werewolf/releases/download/";
const github = "https://api.github.com/repos/werewolf-linux/werewolf/releases";

/// Request names a download. The certificates are paths; channel is
/// werewolf's published channel for the form and provider, which a mirror,
/// source, only serves.
pub const Request = struct {
    source: []const u8,
    cache: []const u8,
    boot_certificate: []const u8,
    image_certificate: []const u8,
    channel: []const u8,
    form: []const u8,
    arch: []const u8,
    provider: []const u8,
    /// version is a serial or a base-images- or protected- release tag.
    version: ?[]const u8 = null,
};

/// Head is what download needs of an authenticated boot.json.
pub const Head = struct { image: prebuilt.Manifest, disk: prebuilt.Artifact };

/// Admission authenticates what download fetched, before it is used.
pub const Admission = struct {
    context: *anyopaque,
    /// head checks directory's boot.json against boot.json.sig.
    head: *const fn (context: *anyopaque, gpa: Allocator, directory: []const u8) anyerror!Head,
    /// verify checks the whole bundle in directory.
    verify: *const fn (context: *anyopaque, gpa: Allocator, directory: []const u8) anyerror!void,
};

/// Transport writes url's body to a new file at path: at most limit bytes,
/// and exactly expected's bytes when given. HTTP 404 is error.NotPublished.
pub const Transport = struct {
    context: *anyopaque,
    fetch: *const fn (
        context: *anyopaque,
        url: []const u8,
        path: []const u8,
        limit: u64,
        expected: ?prebuilt.Artifact,
    ) anyerror!void,
};

/// Floor is the newest release a channel accepted. Its fields are in the
/// order the Python downloader sorted them, so the files match byte for byte.
pub const Floor = struct { build: []const u8, descriptor: []const u8, serial: []const u8 };

/// describe says what err means, for refusals.
pub fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.BadDownloadRequest => "invalid download request",
        error.BadImageVersion => "image version must be a timestamp or " ++
            "base-images-SERIAL GitHub release tag",
        error.BadDownloadSource => "download source must be an HTTPS directory " ++
            "without credentials or query",
        error.UnsupportedDownloadTarget => "unsupported protected download target",
        error.NotAPublishedForm => "download requires a named published form; " ++
            "custom images require --build",
        error.WrongProtectedChannel => "protected channel must be the published one " ++
            "for this form and provider",
        error.BadBootRelease, error.FutureBootRelease => "invalid or future boot release",
        error.BadBootIdentity => "invalid boot identity",
        error.BadSavedFloor => "invalid saved release floor",
        error.OlderBootRelease => "older protected boot release",
        error.ReusedBootSerial => "protected release serial reused",
        error.MissingSavedFloor => "saved release floor is missing; refusing to reset it",
        error.MetadataTooLarge => "metadata exceeds its bound",
        error.CachedDescriptorCollision => "cached descriptor collision",
        error.UnauthenticatedObject => "transport returned an unauthenticated object",
        error.BadCacheFile => "cache files must be regular files",
        error.RedirectChangesTransport => "download redirect changes protected transport",
        error.BadRedirect => "invalid HTTPS redirect",
        error.NotPublished => "protected image is not published at this mirror (HTTP 404)",
        error.MirrorRefused => "protected image mirror refused the request",
        error.UnexpectedResponse => "unexpected download response",
        error.SizeMismatch => "download size differs from authenticated size",
        error.TooLarge => "download exceeds authenticated bound",
        error.DownloadTimeout => "download exceeds its time limit",
        error.ArtifactMismatch => "download differs from authenticated artifact",
        error.BadReleaseList => "invalid GitHub releases response",
        error.TooManyReleasePages => "too many GitHub release pages",
        else => @errorName(err),
    };
}

fn hex64(text: []const u8) bool {
    if (text.len != 64) return false;
    for (text) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return false;
    return true;
}

fn serial(text: []const u8) bool {
    if (text.len != 16 or text[8] != 'T' or text[15] != 'Z') return false;
    for (text, 0..) |c, i| if (i != 8 and i != 15 and !std.ascii.isDigit(c)) return false;
    return true;
}

/// tag reports whether text is a release tag: base-images-SERIAL or
/// protected-SERIAL.
fn tag(text: []const u8) bool {
    const rest = mem.cutPrefix(u8, text, "base-images-") orelse
        mem.cutPrefix(u8, text, "protected-") orelse return false;
    return serial(rest);
}

/// validVersion reports whether text names a release: a tag or a serial,
/// never a path or a URL.
pub fn validVersion(text: []const u8) bool {
    return tag(text) or serial(text);
}

/// validate refuses a request before it reaches the network or the cache.
pub fn validate(r: Request) !void {
    inline for (comptime std.meta.fieldNames(Request)) |name| {
        const value: ?[]const u8 = @field(r, name);
        if (value) |v| if (v.len == 0 or mem.findScalar(u8, v, 0) != null)
            return error.BadDownloadRequest;
    }
    if (r.version) |v| if (!validVersion(v)) return error.BadImageVersion;
    const source = std.Uri.parse(r.source) catch return error.BadDownloadSource;
    if (!mem.eql(u8, source.scheme, "https") or source.host == null or source.user != null or
        source.password != null or source.query != null or source.fragment != null)
        return error.BadDownloadSource;
    for (r.source) |c| if (c < ' ' or c > '~') return error.BadDownloadSource;
    if ((!mem.eql(u8, r.arch, "aarch64") and !mem.eql(u8, r.arch, "x86_64")) or
        (!mem.eql(u8, r.provider, "lima") and !mem.eql(u8, r.provider, "qemu")))
        return error.UnsupportedDownloadTarget;
    if (r.form.len > 64 or !std.ascii.isLower(r.form[0])) return error.NotAPublishedForm;
    for (r.form) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-')
        return error.NotAPublishedForm;
    // Machines follow werewolf's channel for the form and provider themselves
    // (docs/design/independent-updates.md); a mirror serves its bundles.
    prebuilt.channel(r.channel) catch return error.WrongProtectedChannel;
    const tail = mem.cutSuffix(u8, r.channel, r.provider) orelse
        return error.WrongProtectedChannel;
    const head = mem.cutSuffix(u8, tail, "/") orelse return error.WrongProtectedChannel;
    const rest = mem.cutSuffix(u8, head, r.form) orelse return error.WrongProtectedChannel;
    if (!mem.endsWith(u8, rest, "/")) return error.WrongProtectedChannel;
}

/// freshness admits a release against the channel's floor and returns the
/// floor it sets: never older, and one serial names one build and head.
pub fn freshness(
    release: []const u8,
    build: []const u8,
    descriptor: []const u8,
    floor: ?Floor,
    now: i64,
) !Floor {
    const at = policy.parseSerial(release) catch return error.BadBootRelease;
    if (at > now + policy.day) return error.FutureBootRelease;
    if (!hex64(build) or !hex64(descriptor)) return error.BadBootIdentity;
    if (floor) |f| {
        // A corrupt floor refuses; it never resets to accept older releases.
        _ = policy.parseSerial(f.serial) catch return error.BadSavedFloor;
        if (!hex64(f.build) or !hex64(f.descriptor)) return error.BadSavedFloor;
        switch (mem.order(u8, release, f.serial)) {
            .lt => return error.OlderBootRelease,
            .eq => if (!mem.eql(u8, build, f.build) or !mem.eql(u8, descriptor, f.descriptor))
                return error.ReusedBootSerial,
            .gt => {},
        }
    }
    return .{ .serial = release, .build = build, .descriptor = descriptor };
}

/// read returns path's bytes, refusing more than limit.
pub fn read(io: Io, gpa: Allocator, path: []const u8, limit: usize) ![]u8 {
    const bytes = try Dir.cwd().readFileAlloc(io, path, gpa, .limited(limit + 1));
    if (bytes.len > limit) return error.MetadataTooLarge;
    return bytes;
}

/// sha256 returns the lowercase hex SHA-256 of path's bytes.
pub fn sha256(io: Io, path: []const u8) ![64]u8 {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var h = Sha256.init(.{});
    var buf: [64 << 10]u8 = undefined;
    var at: u64 = 0;
    while (true) {
        const n = try file.readPositionalAll(io, &buf, at);
        if (n == 0) break;
        h.update(buf[0..n]);
        at += n;
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

/// writeAtomic replaces path with bytes, mode 0600, syncing the file and
/// its directory, so a crash leaves the old bytes or the new.
pub fn writeAtomic(io: Io, path: []const u8, bytes: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse ".";
    // Zig otherwise opens Linux directories with O_PATH, which cannot be fsynced.
    const dir = try Dir.cwd().openDir(io, parent, .{ .iterate = true });
    defer dir.close(io);
    var atomic = try dir.createFileAtomic(io, std.fs.path.basename(path), .{
        .permissions = .fromMode(0o600),
        .replace = true,
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, bytes);
    try atomic.file.sync(io);
    try atomic.replace(io);
    const handle: Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try handle.sync(io);
}

fn writeJson(io: Io, gpa: Allocator, path: []const u8, value: anytype) !void {
    const text = try std.json.Stringify.valueAlloc(gpa, value, .{});
    try writeAtomic(io, path, try gpa.print("{s}\n", .{text}));
}

/// identity names a channel's state in the cache: what a request trusts,
/// never where it downloads from. It is SHA-256 of the JSON the Python
/// downloader hashed, so a floor kept before survives the upgrade.
fn identity(io: Io, gpa: Allocator, r: Request) ![64]u8 {
    // validate leaves nothing in these fields that JSON would escape.
    const text = try gpa.print(
        "{{\"arch\": \"{s}\", \"boot_certificate\": \"{s}\", \"channel\": \"{s}\", " ++
            "\"form\": \"{s}\", \"image_certificate\": \"{s}\", \"provider\": \"{s}\"{s}{s}{s}}}",
        .{
            r.arch,
            &try sha256(io, r.boot_certificate),
            r.channel,
            r.form,
            &try sha256(io, r.image_certificate),
            r.provider,
            if (r.version != null) ", \"version\": \"" else "",
            r.version orelse "",
            if (r.version != null) "\"" else "",
        },
    );
    var digest: [32]u8 = undefined;
    Sha256.hash(text, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Stamp is a cached file as a receipt saw it; a change to its bytes or
/// links changes it.
const Stamp = struct { inode: u64, size: u64, mtime: i64, ctime: i64 };

fn stamp(io: Io, path: []const u8) !Stamp {
    const st = try Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    if (st.kind != .file) return error.BadCacheFile;
    return .{
        .inode = @intCast(st.inode),
        .size = st.size,
        .mtime = @intCast(st.mtime.nanoseconds),
        .ctime = @intCast(st.ctime.nanoseconds),
    };
}

const Receipt = struct {
    validator: []const u8,
    files: std.json.ArrayHashMap(Stamp),
};

/// bundled lists a complete bundle's files for a build of arch.
fn bundled(gpa: Allocator, arch: []const u8, build: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{
        "boot.json",
        "boot.json.sig",
        "disk.img.zst",
        "latest.json",
        "latest.json.sig",
    }) |n|
        try out.append(gpa, n);
    for ([_][]const u8{ "latest.json", "latest.json.sig" }) |n|
        try out.append(gpa, try gpa.print("prebuilt/{s}/{s}", .{ arch, n }));
    for (names) |n| {
        try out.append(gpa, try gpa.print("slot/{s}", .{n}));
        try out.append(gpa, try gpa.print("prebuilt/{s}/{s}/{s}", .{ arch, build, n }));
    }
    return out.items;
}

/// complete reports whether bundle holds what validator admitted,
/// unchanged since.
pub fn complete(io: Io, gpa: Allocator, bundle: []const u8, validator: []const u8) bool {
    return completed(io, gpa, bundle, validator) catch false;
}

fn completed(io: Io, gpa: Allocator, bundle: []const u8, validator: []const u8) !bool {
    const receipt = try std.json.parseFromSliceLeaky(Receipt, gpa, try read(
        io,
        gpa,
        try gpa.print("{s}/complete.json", .{bundle}),
        64 << 10,
    ), .{});
    const head = try std.json.parseFromSliceLeaky(
        struct { image: struct { arch: []const u8, build: []const u8 } },
        gpa,
        try read(io, gpa, try gpa.print("{s}/boot.json", .{bundle}), head_limit),
        .{ .ignore_unknown_fields = true },
    );
    const arch = head.image.arch;
    if ((!mem.eql(u8, arch, "aarch64") and !mem.eql(u8, arch, "x86_64")) or
        !hex64(head.image.build)) return false;
    if (!mem.eql(u8, receipt.validator, validator)) return false;
    const required = try bundled(gpa, arch, head.image.build);
    if (receipt.files.map.count() != required.len) return false;
    for (required) |name| {
        const saved = receipt.files.map.get(name) orelse return false;
        const now = try stamp(io, try gpa.print("{s}/{s}", .{ bundle, name }));
        if (!std.meta.eql(now, saved)) return false;
    }
    return true;
}

fn privateDir(io: Io, path: []const u8) !void {
    _ = try Dir.cwd().createDirPathStatus(io, path, .fromMode(0o700));
}

/// download returns the directory of the newest bundle request's channel
/// admits, fetching what its cache lacks: heads first, signature before
/// JSON, then artifacts the head authenticates, and the floor last.
/// validator names the code that admits; a bundle another admitted is
/// admitted again. now is the time in seconds.
pub fn download(
    io: Io,
    gpa: Allocator,
    r: Request,
    admission: Admission,
    transport: Transport,
    validator: []const u8,
    now: i64,
) ![]const u8 {
    try validate(r);
    const id = try identity(io, gpa, r);
    const state = try gpa.print("{s}/channels/{s}", .{ r.cache, &id });
    try privateDir(io, state);
    const objects = try gpa.print("{s}/objects", .{r.cache});
    try privateDir(io, objects);
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/download.lock", .{state}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    try discardIncoming(io, gpa, state);

    const floor_path = try gpa.print("{s}/floor.json", .{state});
    const current_path = try gpa.print("{s}/current.json", .{state});
    const floor: ?Floor = if (read(io, gpa, floor_path, 4096)) |bytes|
        std.json.parseFromSliceLeaky(Floor, gpa, bytes, .{}) catch return error.BadSavedFloor
    else |err| if (err == error.FileNotFound) null else return err;
    if (floor) |f| _ = try freshness(f.serial, f.build, f.descriptor, f, now);
    const Current = struct { checked: f64, descriptor: []const u8 };
    const current: ?Current = if (read(io, gpa, current_path, 4096)) |bytes|
        try std.json.parseFromSliceLeaky(Current, gpa, bytes, .{})
    else |err| if (err == error.FileNotFound) null else return err;
    if (current != null and floor == null) return error.MissingSavedFloor;
    if (current) |c| if (mem.eql(u8, c.descriptor, floor.?.descriptor) and
        c.checked <= @as(f64, @floatFromInt(now)) and
        @as(f64, @floatFromInt(now)) - c.checked < cache_seconds)
    {
        const bundle = try gpa.print("{s}/{s}", .{ state, c.descriptor });
        if (complete(io, gpa, bundle, validator)) {
            const head = try admission.head(admission.context, gpa, bundle);
            _ = try freshness(head.image.serial, head.image.build, c.descriptor, floor, now);
            return bundle;
        }
    };

    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const staging = try gpa.print("{s}/incoming-{x}", .{ state, &nonce });
    try Dir.cwd().createDir(io, staging, .fromMode(0o700));
    // Renamed into place on success; anything left is partial.
    defer Dir.cwd().deleteTree(io, staging) catch {};

    const target = try gpa.print("{s}-{s}-{s}", .{ r.form, r.provider, r.arch });
    var base = if (r.version) |v|
        try gpa.print("{s}{s}{s}/{s}-", .{
            releases, if (serial(v)) "base-images-" else "", v, target,
        })
    else
        try gpa.print("{s}/{s}/{s}/{s}", .{
            mem.trimEnd(u8, r.source, "/"), r.form, r.provider, r.arch,
        });
    const latest = if (r.version != null) "" else "/latest/";
    const sig = try gpa.print("{s}/boot.json.sig", .{staging});
    // Signatures precede JSON on the server. A torn head refuses without
    // changing state.
    transport.fetch(transport.context, try gpa.print("{s}{s}boot.json.sig", .{
        base, latest,
    }), sig, signature_limit, null) catch |err| {
        const v = r.version orelse return err;
        if (err != error.NotPublished or !serial(v)) return err;
        // Releases published before the rename remain installable by serial.
        Dir.cwd().deleteFile(io, sig) catch {};
        base = try gpa.print("{s}protected-{s}/{s}-", .{ releases, v, target });
        try transport.fetch(
            transport.context,
            try gpa.print("{s}boot.json.sig", .{base}),
            sig,
            signature_limit,
            null,
        );
    };
    try transport.fetch(transport.context, try gpa.print("{s}{s}boot.json", .{
        base, latest,
    }), try gpa.print("{s}/boot.json", .{staging}), head_limit, null);
    const head = try admission.head(admission.context, gpa, staging);
    const descriptor = try sha256(io, try gpa.print("{s}/boot.json", .{staging}));
    const next = try freshness(head.image.serial, head.image.build, &descriptor, floor, now);
    const bundle = try gpa.print("{s}/{s}", .{ state, &descriptor });
    if (complete(io, gpa, bundle, validator)) {
        // Cached bytes remain subject to the new head and floor.
        const cached = try sha256(io, try gpa.print("{s}/boot.json", .{bundle}));
        if (!mem.eql(u8, &cached, &descriptor)) return error.CachedDescriptorCollision;
    } else {
        try Dir.cwd().deleteTree(io, bundle);
        try fetchBundle(io, gpa, .{
            .staging = staging,
            .objects = objects,
            .arch = r.arch,
            .head = head,
            .remote = if (r.version != null)
                base
            else
                try gpa.print("{s}/objects/{s}/", .{ base, &descriptor }),
        }, transport);
        try admission.verify(admission.context, gpa, staging);
        try receive(io, gpa, staging, r.arch, head.image.build, validator);
        try Dir.rename(Dir.cwd(), staging, Dir.cwd(), bundle, io);
    }
    try writeJson(io, gpa, floor_path, next);
    try writeJson(io, gpa, current_path, .{ .checked = now, .descriptor = descriptor[0..] });
    return bundle;
}

/// discardIncoming removes what an interrupted download left; the lock
/// says none is running.
fn discardIncoming(io: Io, gpa: Allocator, state: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, state, .{ .iterate = true });
    defer dir.close(io);
    var left: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| if (mem.startsWith(u8, entry.name, "incoming-"))
        try left.append(gpa, try gpa.dupe(u8, entry.name));
    for (left.items) |name| try dir.deleteTree(io, name);
}

const Fetching = struct {
    staging: []const u8,
    objects: []const u8,
    arch: []const u8,
    head: Head,
    /// remote is the URL artifacts' names follow.
    remote: []const u8,
};

/// fetchBundle stages the image head and the artifacts, each fetched only
/// when the object cache lacks it, and private until it matches the head.
fn fetchBundle(io: Io, gpa: Allocator, f: Fetching, transport: Transport) !void {
    const build = f.head.image.build;
    const public = try gpa.print("{s}/prebuilt/{s}", .{ f.staging, f.arch });
    try Dir.cwd().createDirPath(io, try gpa.print("{s}/{s}", .{ public, build }));
    for ([_]struct { []const u8, u64 }{
        .{ "latest.json", head_limit },
        .{ "latest.json.sig", signature_limit },
    }) |part| try transport.fetch(
        transport.context,
        try gpa.print("{s}{s}", .{ f.remote, part[0] }),
        try gpa.print("{s}/{s}", .{ public, part[0] }),
        part[1],
        null,
    );
    try Dir.cwd().createDir(io, try gpa.print("{s}/slot", .{f.staging}), .fromMode(0o700));
    var artifacts: [names.len + 1]struct { []const u8, prebuilt.Artifact } = undefined;
    inline for (names, 0..) |name, i| artifacts[i] = .{
        name,
        f.head.image.artifact(name) orelse return error.MissingBootArtifact,
    };
    artifacts[names.len] = .{ "disk.img.zst", f.head.disk };
    for (artifacts) |entry| {
        const name, const artifact = entry;
        if (!hex64(artifact.sha256)) return error.BadBootIdentity;
        const object = try gpa.print("{s}/{s}", .{ f.objects, artifact.sha256 });
        if (!try held(io, object, artifact)) {
            const part = try gpa.print("{s}/{s}.part", .{ f.staging, name });
            try transport.fetch(
                transport.context,
                try gpa.print("{s}{s}", .{ f.remote, name }),
                part,
                artifact.size,
                artifact,
            );
            if (!try held(io, part, artifact)) return error.UnauthenticatedObject;
            try Dir.cwd().setFilePermissions(io, part, .fromMode(0o400), .{});
            try Dir.rename(Dir.cwd(), part, Dir.cwd(), object, io);
        }
        const disk = mem.eql(u8, name, "disk.img.zst");
        try link(io, object, if (disk)
            try gpa.print("{s}/{s}", .{ f.staging, name })
        else
            try gpa.print("{s}/slot/{s}", .{ f.staging, name }));
        if (!disk) try link(io, object, try gpa.print("{s}/{s}/{s}", .{ public, build, name }));
    }
}

fn link(io: Io, from: []const u8, to: []const u8) !void {
    try Dir.hardLink(Dir.cwd(), from, Dir.cwd(), to, io, .{});
}

/// held reports whether path is a regular file of exactly artifact's bytes.
fn held(io: Io, path: []const u8, artifact: prebuilt.Artifact) !bool {
    const st = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err|
        switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
    if (st.kind != .file or st.size != artifact.size) return false;
    return mem.eql(u8, &try sha256(io, path), artifact.sha256);
}

/// receive mirrors the image head at the top, for publishers, and writes
/// the receipt complete checks.
fn receive(
    io: Io,
    gpa: Allocator,
    staging: []const u8,
    arch: []const u8,
    build: []const u8,
    validator: []const u8,
) !void {
    for ([_][]const u8{ "latest.json", "latest.json.sig" }) |name| try link(
        io,
        try gpa.print("{s}/prebuilt/{s}/{s}", .{ staging, arch, name }),
        try gpa.print("{s}/{s}", .{ staging, name }),
    );
    var receipt: Receipt = .{ .validator = validator, .files = .{} };
    for (try bundled(gpa, arch, build)) |name| try receipt.files.map.put(
        gpa,
        name,
        try stamp(io, try gpa.print("{s}/{s}", .{ staging, name })),
    );
    try writeJson(io, gpa, try gpa.print("{s}/complete.json", .{staging}), receipt);
}

/// versions lists, newest first, the releases on GitHub that carry a
/// complete bundle for form, provider and arch. GitHub only discovers:
/// installing still authenticates.
pub fn versions(
    io: Io,
    gpa: Allocator,
    transport: Transport,
    scratch: []const u8,
    form: []const u8,
    provider: []const u8,
    arch: []const u8,
) ![]const []const u8 {
    const Release = struct {
        tag_name: []const u8 = "",
        draft: bool = true,
        prerelease: bool = true,
        assets: []const struct { name: []const u8 } = &.{},
    };
    var required: [names.len + 5][]const u8 = undefined;
    for (&required, [_][]const u8{
        "boot.json", "boot.json.sig", "latest.json", "latest.json.sig", "disk.img.zst",
    } ++ names) |*r, name| r.* = try gpa.print("{s}-{s}-{s}-{s}", .{ form, provider, arch, name });
    var found: std.ArrayList([]const u8) = .empty;
    for (1..101) |page| {
        const path = try gpa.print("{s}/releases-{d}.json", .{ scratch, page });
        defer Dir.cwd().deleteFile(io, path) catch {};
        try transport.fetch(
            transport.context,
            try gpa.print("{s}?per_page=100&page={d}", .{ github, page }),
            path,
            16 << 20,
            null,
        );
        const list = std.json.parseFromSliceLeaky([]const Release, gpa, try read(
            io,
            gpa,
            path,
            16 << 20,
        ), .{ .ignore_unknown_fields = true }) catch return error.BadReleaseList;
        for (list) |release| {
            if (!tag(release.tag_name) or release.draft or release.prerelease) continue;
            var seen: [required.len]bool = @splat(false);
            for (release.assets) |a| for (required, &seen) |want, *s| {
                s.* = s.* or mem.eql(u8, a.name, want);
            };
            if (mem.findScalar(bool, &seen, false) != null) continue;
            for (found.items) |t| {
                if (mem.eql(u8, t, release.tag_name)) break;
            } else try found.append(gpa, release.tag_name);
        }
        if (list.len < 100) {
            mem.sort([]const u8, found.items, {}, newer);
            return found.items;
        }
    }
    return error.TooManyReleasePages;
}

/// newer orders tags by serial, then name, newest first.
fn newer(_: void, a: []const u8, b: []const u8) bool {
    const sa = a[mem.findScalarLast(u8, a, '-').? + 1 ..];
    const sb = b[mem.findScalarLast(u8, b, '-').? + 1 ..];
    return switch (mem.order(u8, sa, sb)) {
        .gt => true,
        .lt => false,
        .eq => mem.order(u8, a, b) == .gt,
    };
}

/// Https is the Transport werewolf's mirrors and GitHub are fetched with:
/// HTTPS only, every redirect checked, identity encoding, bounded size and
/// time, and the head's digest when it names one.
pub const Https = struct {
    io: Io,
    gpa: Allocator,
    client: std.http.Client,
    /// status is the HTTP status of the last error.MirrorRefused.
    status: u16 = 0,

    pub const Options = struct {
        /// ca_file replaces the system's authorities, as SSL_CERT_FILE does.
        ca_file: ?[]const u8 = null,
        /// environ supplies https_proxy and the like.
        environ: ?*const std.process.Environ.Map = null,
    };

    /// time_limit bounds one fetch, redirects and all.
    pub const time_limit: Io.Duration = .fromSeconds(900);

    /// init makes h. gpa must outlive h; a fetch uses it from its own task
    /// while the caller waits.
    pub fn init(h: *Https, io: Io, gpa: Allocator, options: Options) !void {
        h.* = .{ .io = io, .gpa = gpa, .client = .{ .allocator = gpa, .io = io } };
        errdefer h.client.deinit();
        if (options.ca_file) |path| {
            const now = Io.Clock.real.now(io);
            try h.client.ca_bundle.addCertsFromFilePath(gpa, io, now, Dir.cwd(), path);
            h.client.now = now;
        }
        if (options.environ) |env| try h.client.initDefaultProxies(gpa, env);
    }

    pub fn deinit(h: *Https) void {
        h.client.deinit();
    }

    pub fn transport(h: *Https) Transport {
        return .{ .context = h, .fetch = fetchOpaque };
    }

    fn fetchOpaque(
        context: *anyopaque,
        url: []const u8,
        path: []const u8,
        limit: u64,
        expected: ?prebuilt.Artifact,
    ) anyerror!void {
        const h: *Https = @ptrCast(@alignCast(context));
        return h.fetch(url, path, limit, expected);
    }

    pub fn fetch(
        h: *Https,
        url: []const u8,
        path: []const u8,
        limit: u64,
        expected: ?prebuilt.Artifact,
    ) !void {
        const Event = union(enum) { done: anyerror!void, timeout: Io.Cancelable!void };
        var buffer: [2]Event = undefined;
        var events: Io.Select(Event) = .init(h.io, &buffer);
        defer events.cancelDiscard();
        try events.concurrent(.done, get, .{ h, url, path, limit, expected });
        try events.concurrent(.timeout, Io.sleep, .{ h.io, time_limit, .awake });
        return switch (try events.await()) {
            .done => |result| result,
            .timeout => |result| {
                try result;
                return error.DownloadTimeout;
            },
        };
    }

    fn get(
        h: *Https,
        url: []const u8,
        path: []const u8,
        limit: u64,
        expected: ?prebuilt.Artifact,
    ) anyerror!void {
        var location = try h.gpa.dupe(u8, url);
        defer h.gpa.free(location);
        var redirects: usize = 0;
        while (true) {
            if (location.len > 8192) return error.RedirectChangesTransport;
            const uri = std.Uri.parse(location) catch return error.RedirectChangesTransport;
            if (!mem.eql(u8, uri.scheme, "https") or uri.host == null or uri.user != null or
                uri.password != null) return error.RedirectChangesTransport;
            var req = try h.client.request(.GET, uri, .{
                .redirect_behavior = .unhandled,
                .headers = .{
                    .user_agent = .{ .override = user_agent },
                    .accept_encoding = .{ .override = "identity" },
                },
            });
            defer req.deinit();
            try req.sendBodiless();
            var head_buffer: [8192]u8 = undefined;
            var response = try req.receiveHead(&head_buffer);
            const status: u16 = @backingInt(response.head.status);
            switch (status) {
                200 => {},
                301, 302, 303, 307, 308 => {
                    // The client follows nothing itself: each Location is checked here.
                    if (redirects == 5) return error.BadRedirect;
                    redirects += 1;
                    const next = try resolve(h.gpa, uri, response.head.location orelse
                        return error.BadRedirect);
                    h.gpa.free(location);
                    location = next;
                    continue;
                },
                404 => return error.NotPublished,
                else => {
                    h.status = status;
                    return error.MirrorRefused;
                },
            }
            if (response.head.content_encoding != .identity) return error.UnexpectedResponse;
            if (response.head.content_length) |n| if (n > limit or
                (expected != null and n != expected.?.size)) return error.SizeMismatch;
            return save(h.io, &response, path, limit, expected);
        }
    }
};

/// resolve is location relative to base, as a URL.
fn resolve(gpa: Allocator, base: std.Uri, location: []const u8) ![]u8 {
    if (location.len > 8192) return error.BadRedirect;
    const aux = try gpa.alloc(u8, location.len * 2 + 8192);
    defer gpa.free(aux);
    @memcpy(aux[0..location.len], location);
    var rest = aux;
    const uri = std.Uri.resolveInPlace(base, location.len, &rest) catch return error.BadRedirect;
    return gpa.print("{f}", .{uri});
}

fn save(
    io: Io,
    response: *std.http.Client.Response,
    path: []const u8,
    limit: u64,
    expected: ?prebuilt.Artifact,
) !void {
    const file = try Dir.cwd().createFile(io, path, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    var transfer: [64 << 10]u8 = undefined;
    const body = response.reader(&transfer);
    var digest = Sha256.init(.{});
    var total: u64 = 0;
    var buf: [64 << 10]u8 = undefined;
    while (true) {
        const n = body.readSliceShort(&buf) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr() orelse err,
        };
        if (n == 0) break;
        total += n;
        if (total > limit) return error.TooLarge;
        digest.update(buf[0..n]);
        try file.writeStreamingAll(io, buf[0..n]);
        if (n < buf.len) break;
    }
    if (expected) |e| if (total != e.size or
        !mem.eql(u8, &std.fmt.bytesToHex(digest.finalResult(), .lower), e.sha256))
        return error.ArtifactMismatch;
    try file.sync(io);
}

const testing = std.testing;

fn testRequest() Request {
    return .{
        .source = "https://vendor.test/boot/v1",
        .cache = "/cache",
        .boot_certificate = "/boot.crt",
        .image_certificate = "/image.crt",
        .channel = "https://vendor.test/boot/v1/playground/lima",
        .form = "playground",
        .arch = "aarch64",
        .provider = "lima",
    };
}

test "image versions are release tags, never paths or URLs" {
    try testing.expect(validVersion("protected-20261014T232908Z"));
    try testing.expect(validVersion("base-images-20261014T232908Z"));
    try testing.expect(validVersion("20261014T232908Z"));
    for ([_][]const u8{ "", "latest", "protected-../x", "protected-20261014T232908Z/a" }) |v|
        try testing.expect(!validVersion(v));
}

test "requests name an HTTPS mirror, a published form and its channel" {
    try validate(testRequest());
    var r = testRequest();
    r.version = "base-images-20261012T000000Z";
    try validate(r);
    r.version = "20261012T000000Z";
    try validate(r);
    for ([_][]const u8{
        "",
        "latest",
        "../older",
        "https://foreign.test/image",
        "base-images-20261013T000000Z/../other",
    }) |v| {
        r.version = v;
        try testing.expect(std.meta.isError(validate(r)));
    }
    for ([_][]const u8{
        "http://vendor.test/",
        "https://user:pass@vendor.test/",
        "https://vendor.test/?key=secret",
        "https://vendor.test/#part",
    }) |source| {
        r = testRequest();
        r.source = source;
        try testing.expectError(error.BadDownloadSource, validate(r));
    }
    for ([_][]const u8{
        "https://vendor.test/boot/v1/playground/qemu",
        "https://vendor.test/boot/v1/other/lima",
        "https://vendor.test/boot/v1/xplayground/lima",
        "http://vendor.test/boot/v1/playground/lima",
        "https://vendor.test/boot/v1/playground/lima/",
    }) |channel| {
        r = testRequest();
        r.channel = channel;
        try testing.expectError(error.WrongProtectedChannel, validate(r));
    }
    r = testRequest();
    r.form = "../prod";
    try testing.expectError(error.NotAPublishedForm, validate(r));
    r = testRequest();
    r.provider = "gcp";
    try testing.expectError(error.UnsupportedDownloadTarget, validate(r));
    r = testRequest();
    r.cache = "";
    try testing.expectError(error.BadDownloadRequest, validate(r));
}

test "the release floor never lowers and one serial names one build" {
    const now = try policy.parseSerial("20261013T010000Z");
    const a: []const u8 = &@as([64]u8, @splat('a'));
    const b: []const u8 = &@as([64]u8, @splat('b'));
    const floor = try freshness("20261013T000000Z", a, b, null, now);
    try testing.expectEqualStrings("20261013T000000Z", floor.serial);
    _ = try freshness("20261013T000000Z", a, b, floor, now);
    _ = try freshness("20261013T000001Z", b, a, floor, now);
    try testing.expectError(
        error.OlderBootRelease,
        freshness("20261012T000000Z", a, b, floor, now),
    );
    try testing.expectError(
        error.ReusedBootSerial,
        freshness("20261013T000000Z", b, b, floor, now),
    );
    try testing.expectError(
        error.ReusedBootSerial,
        freshness("20261013T000000Z", a, a, floor, now),
    );
    try testing.expectError(
        error.FutureBootRelease,
        freshness("20261015T000000Z", a, b, null, now),
    );
    try testing.expectError(
        error.BadBootRelease,
        freshness("20261301T000000Z", a, b, null, now),
    );
    try testing.expectError(
        error.BadBootIdentity,
        freshness("20261013T000000Z", &@as([64]u8, @splat('A')), b, null, now),
    );
    var corrupt = floor;
    corrupt.descriptor = &@as([63]u8, @splat('0'));
    try testing.expectError(
        error.BadSavedFloor,
        freshness("20261014T000000Z", a, b, corrupt, now),
    );
}

test "channel state keeps the Python downloader's identity" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "boot.crt", .data = "boot\n" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "image.crt", .data = "image\n" });
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", gpa);
    var r = testRequest();
    r.boot_certificate = try gpa.print("{s}/boot.crt", .{root});
    r.image_certificate = try gpa.print("{s}/image.crt", .{root});
    try testing.expectEqualStrings(
        "a4d18f3e4a74101913b1aa73eea727084c000675ed2ad96339fade8e81740505",
        &try identity(testing.io, gpa, r),
    );
    r.version = "base-images-20261012T000000Z";
    try testing.expectEqualStrings(
        "d4511bbc01b0905a66e67cc971067e5202870d388d04a666c26317eeacd9508b",
        &try identity(testing.io, gpa, r),
    );
    // The mirror and the cache are not what a floor trusts.
    r.source = "https://other-mirror.test/boot";
    r.cache = "/elsewhere";
    try testing.expectEqualStrings(
        "d4511bbc01b0905a66e67cc971067e5202870d388d04a666c26317eeacd9508b",
        &try identity(testing.io, gpa, r),
    );
}

/// Pages serves GitHub release pages from memory, in order.
const Pages = struct {
    pages: []const []const u8,
    urls: std.ArrayList([]const u8) = .empty,
    gpa: Allocator,

    fn fetch(
        context: *anyopaque,
        url: []const u8,
        path: []const u8,
        limit: u64,
        expected: ?prebuilt.Artifact,
    ) anyerror!void {
        const p: *Pages = @ptrCast(@alignCast(context));
        _ = limit;
        _ = expected;
        try p.urls.append(p.gpa, try p.gpa.dupe(u8, url));
        try Dir.cwd().writeFile(testing.io, .{
            .sub_path = path,
            .data = p.pages[p.urls.items.len - 1],
        });
    }
};

test "version discovery pages through GitHub and keeps complete, final releases" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var assets: std.ArrayList(u8) = .empty;
    const wanted = [_][]const u8{
        "boot.json", "boot.json.sig", "latest.json", "latest.json.sig", "disk.img.zst",
    } ++ names;
    for (wanted, 0..) |name, i|
        try assets.print(gpa, "{s}{{\"name\":\"playground-lima-aarch64-{s}\"}}", .{
            if (i == 0) "" else ",", name,
        });
    const all = assets.items;
    const partial = all[0..mem.findScalarLast(u8, all, ',').?];
    const release = "{{\"tag_name\":\"{s}\",\"draft\":{s},\"prerelease\":{s},\"assets\":[{s}]}}";
    var first: std.ArrayList(u8) = .empty;
    try first.appendSlice(gpa, "[");
    for ([_][4][]const u8{
        .{ "base-images-20261013T000000Z", "false", "false", all },
        .{ "protected-20261012T000000Z", "false", "false", all },
        .{ "base-images-20261014T000000Z", "true", "false", all },
        .{ "base-images-20261015T000000Z", "false", "true", all },
        .{ "base-images-20261011T000000Z", "false", "false", partial },
        .{ "20261010T000000Z", "false", "false", all },
    }) |r| try first.print(gpa, release ++ ",", .{ r[0], r[1], r[2], r[3] });
    for (0..94) |i| try first.print(gpa, release ++ "{s}", .{
        "legacy", "false", "false", all, if (i == 93) "]" else ",",
    });
    const second = try gpa.print("[" ++ release ++ "]", .{
        "base-images-20261016T000000Z", "false", "false", all,
    });
    var pages: Pages = .{ .pages = &.{ first.items, second }, .gpa = gpa };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const found = try versions(
        testing.io,
        gpa,
        .{ .context = &pages, .fetch = Pages.fetch },
        try tmp.dir.realPathFileAlloc(testing.io, ".", gpa),
        "playground",
        "lima",
        "aarch64",
    );
    try testing.expectEqual(3, found.len);
    try testing.expectEqualStrings("base-images-20261016T000000Z", found[0]);
    try testing.expectEqualStrings("base-images-20261013T000000Z", found[1]);
    try testing.expectEqualStrings("protected-20261012T000000Z", found[2]);
    try testing.expectEqual(2, pages.urls.items.len);
    try testing.expect(mem.endsWith(u8, pages.urls.items[1], "page=2"));
}

/// Mirror answers Https's tests, and keeps the headers each request sent.
const Mirror = struct {
    port: u16 = 0,
    io: Io,
    mutex: Io.Mutex = .init,
    gpa: Allocator,
    agents: std.ArrayList([]const u8) = .empty,

    const http = @import("host").http;

    fn serve(
        context: *anyopaque,
        gpa: Allocator,
        request: *const http.Request,
        response: *http.Response,
    ) !void {
        const m: *Mirror = @ptrCast(@alignCast(context));
        {
            m.mutex.lockUncancelable(m.io);
            defer m.mutex.unlock(m.io);
            try m.agents.append(m.gpa, try m.gpa.print("{s} {s} {s}", .{
                request.path(),
                request.header("user-agent") orelse "-",
                request.header("accept-encoding") orelse "-",
            }));
        }
        const path = request.path();
        const here = try gpa.print("https://127.0.0.1:{d}", .{m.port});
        if (mem.eql(u8, path, "/object")) return response.send(200, &.{}, "ab");
        if (mem.eql(u8, path, "/redirect")) return response.send(302, &.{
            .{ .name = "Location", .value = try gpa.print("{s}/object", .{here}) },
        }, "");
        if (mem.eql(u8, path, "/relative")) return response.send(301, &.{
            .{ .name = "Location", .value = "redirect" },
        }, "");
        if (mem.eql(u8, path, "/downgrade")) return response.send(302, &.{
            .{ .name = "Location", .value = "http://127.0.0.1/object" },
        }, "");
        if (mem.eql(u8, path, "/credentials")) return response.send(302, &.{
            .{
                .name = "Location",
                .value = try gpa.print("https://secret@127.0.0.1:{d}/object", .{m.port}),
            },
        }, "");
        if (mem.eql(u8, path, "/loop")) return response.send(302, &.{
            .{ .name = "Location", .value = "/loop" },
        }, "");
        if (mem.eql(u8, path, "/denied")) return response.send(403, &.{}, "");
        if (mem.eql(u8, path, "/promise")) {
            response.close = true;
            return response.send(200, &.{.{ .name = "Content-Length", .value = "3" }}, "ab");
        }
        if (mem.eql(u8, path, "/gzip"))
            return response.send(200, &.{.{ .name = "Content-Encoding", .value = "gzip" }}, "ab");
        if (mem.cutPrefix(u8, path, "/raw/")) |body| {
            // No Content-Length: the body ends when the connection does.
            response.sent = true;
            response.close = true;
            return response.out.print("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{s}", .{body});
        }
        if (mem.eql(u8, path, "/negative")) {
            response.sent = true;
            response.close = true;
            return response.out.writeAll("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nab");
        }
        return response.send(404, &.{}, "");
    }
};

test "HTTPS fetches identify howl, follow only HTTPS and keep their bounds" {
    const host = @import("host");
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const ca = try host.tls.Authority.init(io, gpa, "werewolf download test");
    const identity_ = try ca.issue(io, gpa, &.{"127.0.0.1"});
    const ca_file = try gpa.print("{s}/ca.pem", .{root});
    try Dir.cwd().writeFile(io, .{ .sub_path = ca_file, .data = try ca.pem(gpa) });
    var mirror: Mirror = .{ .io = io, .gpa = gpa };
    var server: host.http.Server = undefined;
    try server.start(io, testing.allocator, .{
        .identity = &identity_,
        .handler = .{ .context = &mirror, .serve = Mirror.serve },
    });
    defer server.stop();
    mirror.port = server.port();
    var https: Https = undefined;
    try https.init(io, testing.allocator, .{ .ca_file = ca_file });
    defer https.deinit();
    const ab: prebuilt.Artifact = .{
        .size = 2,
        .sha256 = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603",
    };
    var n: usize = 0;
    const Case = struct { []const u8, u64, ?prebuilt.Artifact, ?anyerror };
    for ([_]Case{
        .{ "/object", 2, ab, null },
        .{ "/relative", 2, ab, null },
        .{ "/raw/ab", 2, ab, null },
        .{ "/raw/a", 2, ab, error.ArtifactMismatch },
        .{ "/raw/abc", 2, ab, error.TooLarge },
        .{ "/raw/abc", 2, null, error.TooLarge },
        .{ "/promise", 2, null, error.SizeMismatch },
        .{ "/object", 3, .{ .size = 3, .sha256 = ab.sha256 }, error.SizeMismatch },
        .{
            "/object",
            2,
            .{ .size = 2, .sha256 = &@as([64]u8, @splat('0')) },
            error.ArtifactMismatch,
        },
        .{ "/negative", 2, null, error.HttpHeadersInvalid },
        .{ "/gzip", 2, null, error.UnexpectedResponse },
        .{ "/downgrade", 2, null, error.RedirectChangesTransport },
        .{ "/credentials", 2, null, error.RedirectChangesTransport },
        .{ "/loop", 2, null, error.BadRedirect },
        .{ "/missing", 2, null, error.NotPublished },
        .{ "/denied", 2, null, error.MirrorRefused },
    }) |case| {
        n += 1;
        const path, const limit, const expected, const failure = case;
        const out = try gpa.print("{s}/out-{d}", .{ root, n });
        const result = https.fetch(
            try gpa.print("https://127.0.0.1:{d}{s}", .{ mirror.port, path }),
            out,
            limit,
            expected,
        );
        if (failure) |err| {
            try testing.expectError(err, result);
        } else {
            try result;
            try testing.expectEqualStrings("ab", try read(io, gpa, out, 2));
        }
        // A refused response before its body creates no file.
        if (failure != null and (failure.? == error.NotPublished or
            failure.? == error.MirrorRefused))
            try testing.expectError(error.FileNotFound, Dir.cwd().access(io, out, .{}));
    }
    try testing.expectEqual(403, https.status);
    mirror.mutex.lockUncancelable(io);
    defer mirror.mutex.unlock(io);
    for (mirror.agents.items) |line| try testing.expect(mem.endsWith(
        u8,
        line,
        " " ++ user_agent ++ " identity",
    ));
    // The redirect's target is asked with the same identity.
    try testing.expectEqualStrings("/relative", mirror.agents.items[1][0.."/relative".len]);
    try testing.expectEqualStrings("/redirect", mirror.agents.items[2][0.."/redirect".len]);
    try testing.expectEqualStrings("/object", mirror.agents.items[3][0.."/object".len]);
}
