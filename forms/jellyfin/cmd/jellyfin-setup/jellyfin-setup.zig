//! jellyfin-setup prepares Jellyfin before each start. It writes the
//! network settings the form holds Jellyfin to, and on the first start
//! completes Jellyfin's startup wizard with the administrator from the
//! config and adds its libraries, so no visitor ever meets the wizard.
//!
//!     jellyfin-setup
//!
//! leash runs it as the jellyfin user, with SETUP_ADMIN and SETUP_METADATA
//! from the machine's settings (forms/jellyfin/form.yaml). See
//! forms/jellyfin/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const jellyfin = "/usr/lib/jellyfin/jellyfin";
const home = "/data/svc/jellyfin";
const config_dir = home ++ "/config";
const media_dir = home ++ "/media";
/// done records that the wizard was completed and the libraries made.
const done = home ++ "/setup-done";
/// password is leash's copy of the config's.
const password_file = "/run/svc/jellyfin/admin-password";
/// port is where Jellyfin serves Caddy; setup_port is where it runs during
/// setup, which Caddy cannot reach, so the wizard is never served.
const port = 8096;
const setup_port = 8097;
/// argv is how Jellyfin runs, here and in form.yaml's exec line alike.
const argv = [_][]const u8{
    jellyfin,
    "--datadir",
    home ++ "/data",
    "--configdir",
    config_dir,
    "--cachedir",
    home ++ "/cache",
    "--logdir",
    home ++ "/log",
    "--webdir",
    "/usr/lib/jellyfin/jellyfin-web",
    "--ffmpeg",
    "/usr/bin/ffmpeg",
    "--nonetchange",
};
const auth_header = "MediaBrowser Client=\"jellyfin-setup\", Device=\"werewolf\", " ++
    "DeviceId=\"jellyfin-setup\", Version=\"1\"";
/// local_images are the image fetchers that read the media itself, the
/// ones a library without internet metadata keeps.
const local_images = [_][]const u8{ "Embedded Image Extractor", "Screen Grabber" };

const Library = struct { name: []const u8, kind: []const u8, dir: []const u8 };
const libraries = [_]Library{
    .{ .name = "Movies", .kind = "movies", .dir = media_dir ++ "/movies" },
    .{ .name = "Shows", .kind = "tvshows", .dir = media_dir ++ "/shows" },
    .{ .name = "Music", .kind = "music", .dir = media_dir ++ "/music" },
};

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    for ([_][]const u8{ config_dir, home ++ "/cache/tmp", home ++ "/log" }) |d|
        try Dir.cwd().createDirPath(io, d);
    for (libraries) |l| try Dir.cwd().createDirPath(io, l.dir);
    if (exists(io, done)) {
        try replace(io, config_dir ++ "/network.xml", networkXml(port));
        say(io, "set up already; the administrator and libraries are Jellyfin's to change", .{});
        return;
    }

    const admin = environ.getAlloc(gpa, "SETUP_ADMIN") catch return error.NoAdmin;
    if (!name(admin)) return error.AdminNotAName;
    const metadata = if (environ.getAlloc(gpa, "SETUP_METADATA")) |m|
        std.mem.eql(u8, m, "true")
    else |_|
        false;
    const text = Dir.cwd().readFileAlloc(io, password_file, gpa, .limited(4 << 10)) catch
        return error.NoAdminPassword;
    const password = std.mem.trimEnd(u8, text, "\r\n");
    if (password.len < 12) return error.AdminPasswordTooShort;

    try replace(io, config_dir ++ "/network.xml", networkXml(setup_port));
    var child = try std.process.spawn(io, .{ .argv = &argv, .stdin = .ignore });
    const pid = child.id.?;
    defer stop(io, pid);

    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    const j: Api = .{ .io = io, .gpa = gpa, .client = &client };
    const info = try j.waitUp(pid);
    if (!info.StartupWizardCompleted) {
        // The wizard's own steps: the first user is made when asked for,
        // then named, given the password, and the wizard closed.
        _ = try j.call(.GET, "/Startup/User", null, null);
        _ = try j.call(.POST, "/Startup/User", try json(gpa, .{
            .Name = admin,
            .Password = password,
        }), null);
        _ = try j.call(.POST, "/Startup/Complete", null, null);
        say(io, "made administrator {s} and closed the startup wizard", .{admin});
    }

    const auth = try json(gpa, .{ .Username = admin, .Pw = password });
    const session = try std.json.parseFromSliceLeaky(
        struct { AccessToken: []const u8 },
        gpa,
        try j.call(.POST, "/Users/AuthenticateByName", auth, null),
        .{ .ignore_unknown_fields = true },
    );
    const token = try std.fmt.allocPrint(gpa, "{s}, Token=\"{s}\"", .{
        auth_header,
        session.AccessToken,
    });
    const have = try j.call(.GET, "/Library/VirtualFolders", null, token);
    for (libraries) |l| {
        if (std.mem.indexOf(u8, have, try std.fmt.allocPrint(gpa, "\"Name\":\"{s}\"", .{l.name})) != null)
            continue;
        try j.addLibrary(l, metadata, token);
        say(io, "added library {s} at {s}, {s}", .{
            l.name,
            l.dir,
            if (metadata) "with metadata from the internet" else "with local metadata alone",
        });
    }
    _ = try j.call(.POST, "/Sessions/Logout", null, token);

    stop(io, pid);
    try replace(io, config_dir ++ "/network.xml", networkXml(port));
    try replace(io, done, "werewolf: Jellyfin's startup wizard was completed by jellyfin-setup\n");
    // The password is no longer needed; leash copies it again at each start.
    Dir.cwd().deleteFile(io, password_file) catch |err|
        say(io, "{s} not removed: {s}", .{ password_file, @errorName(err) });
}

/// Api calls Jellyfin's HTTP API on the setup port.
const Api = struct {
    io: Io,
    gpa: Allocator,
    client: *std.http.Client,

    const Info = struct { StartupWizardCompleted: bool = false };

    /// waitUp waits for Jellyfin to answer, which its first start, making
    /// its database, may take minutes to do.
    fn waitUp(j: Api, pid: linux.pid_t) !Info {
        var i: u32 = 0;
        while (i < 600) : (i += 1) {
            var status: u32 = 0;
            if (linux.wait4(pid, &status, linux.W.NOHANG, null) == pid) return error.JellyfinExited;
            if (j.call(.GET, "/System/Info/Public", null, null)) |body| {
                return std.json.parseFromSliceLeaky(Info, j.gpa, body, .{
                    .ignore_unknown_fields = true,
                });
            } else |_| {}
            j.io.sleep(.fromSeconds(1), .awake) catch {};
        }
        return error.JellyfinNotUp;
    }

    /// call sends one request and returns the body of a 2xx answer.
    fn call(
        j: Api,
        method: std.http.Method,
        path: []const u8,
        body: ?[]const u8,
        token: ?[]const u8,
    ) ![]const u8 {
        const url = try std.fmt.allocPrint(j.gpa, "http://127.0.0.1:{d}{s}", .{ setup_port, path });
        var out: Io.Writer.Allocating = .init(j.gpa);
        const res = try j.client.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = body,
            .keep_alive = false,
            .headers = .{ .content_type = .{ .override = "application/json" } },
            .extra_headers = &.{.{ .name = "Authorization", .value = token orelse auth_header }},
            .response_writer = &out.writer,
        });
        const code = @intFromEnum(res.status);
        if (code < 200 or code > 299) {
            // The path alone: the body may hold the password.
            say(j.io, "{s} {s}: HTTP {d}", .{ @tagName(method), path, code });
            return error.JellyfinRefused;
        }
        return out.written();
    }

    /// addLibrary makes library l. Without metadata, each kind of item it
    /// holds gets no internet metadata fetcher and only the image fetchers
    /// that read the files.
    fn addLibrary(j: Api, l: Library, metadata: bool, token: []const u8) !void {
        var opts: std.ArrayList(TypeOption) = .empty;
        if (!metadata) {
            const avail = try std.json.parseFromSliceLeaky(Available, j.gpa, try j.call(
                .GET,
                try std.fmt.allocPrint(
                    j.gpa,
                    "/Libraries/AvailableOptions?libraryContentType={s}&isNewLibrary=true",
                    .{l.kind},
                ),
                null,
                token,
            ), .{ .ignore_unknown_fields = true });
            for (avail.TypeOptions) |t| {
                var images: std.ArrayList([]const u8) = .empty;
                for (t.ImageFetchers) |f| for (local_images) |li| {
                    if (std.mem.eql(u8, f.Name, li)) try images.append(j.gpa, f.Name);
                };
                try opts.append(j.gpa, .{
                    .Type = t.Type,
                    .ImageFetchers = images.items,
                    .ImageFetcherOrder = images.items,
                });
            }
        }
        const path = try std.fmt.allocPrint(
            j.gpa,
            "/Library/VirtualFolders?name={s}&collectionType={s}&paths={s}&refreshLibrary=false",
            .{ l.name, l.kind, try escape(j.gpa, l.dir) },
        );
        _ = try j.call(.POST, path, try json(j.gpa, .{ .LibraryOptions = .{
            .EnableRealtimeMonitor = true,
            .SaveLocalMetadata = false,
            .TypeOptions = opts.items,
        } }), token);
    }
};

const Available = struct {
    TypeOptions: []const struct {
        Type: []const u8,
        ImageFetchers: []const struct { Name: []const u8 } = &.{},
    } = &.{},
};

const TypeOption = struct {
    Type: []const u8,
    MetadataFetchers: []const []const u8 = &.{},
    MetadataFetcherOrder: []const []const u8 = &.{},
    ImageFetchers: []const []const u8,
    ImageFetcherOrder: []const []const u8,
};

/// stop ends Jellyfin: SIGTERM, then SIGKILL if it has not exited within a
/// minute. It does nothing once Jellyfin has been reaped.
fn stop(io: Io, pid: linux.pid_t) void {
    var status: u32 = 0;
    if (linux.wait4(pid, &status, linux.W.NOHANG, null) != 0) return;
    _ = linux.kill(pid, linux.SIG.TERM);
    var i: u32 = 0;
    while (i < 60) : (i += 1) {
        if (linux.wait4(pid, &status, linux.W.NOHANG, null) != 0) return;
        io.sleep(.fromSeconds(1), .awake) catch {};
    }
    say(io, "Jellyfin did not stop in 60 s; killed", .{});
    _ = linux.kill(pid, linux.SIG.KILL);
    _ = linux.wait4(pid, &status, 0, null);
}

/// networkXml returns Jellyfin's network settings as the form holds them:
/// serving on loopback at p behind Caddy, whose forwarded address it
/// trusts, with no UPnP, no discovery and no IPv6.
fn networkXml(comptime p: u16) []const u8 {
    return std.fmt.comptimePrint(
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<!-- Written by jellyfin-setup at each start (forms/jellyfin/README.md). -->
        \\<NetworkConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        \\  <EnableHttps>false</EnableHttps>
        \\  <RequireHttps>false</RequireHttps>
        \\  <InternalHttpPort>{d}</InternalHttpPort>
        \\  <PublicHttpPort>{d}</PublicHttpPort>
        \\  <AutoDiscovery>false</AutoDiscovery>
        \\  <EnableUPnP>false</EnableUPnP>
        \\  <EnableIPv4>true</EnableIPv4>
        \\  <EnableIPv6>false</EnableIPv6>
        \\  <EnableRemoteAccess>true</EnableRemoteAccess>
        \\  <LocalNetworkAddresses>
        \\    <string>127.0.0.1</string>
        \\  </LocalNetworkAddresses>
        \\  <KnownProxies>
        \\    <string>127.0.0.1</string>
        \\  </KnownProxies>
        \\  <EnablePublishedServerUriByRequest>false</EnablePublishedServerUriByRequest>
        \\</NetworkConfiguration>
        \\
    , .{ p, p });
}

/// json returns v as JSON.
fn json(gpa: Allocator, v: anytype) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    try std.json.Stringify.value(v, .{}, &out.writer);
    return out.written();
}

/// escape percent-encodes s for a query string.
fn escape(gpa: Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (s) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.', '~' => try out.append(gpa, c),
        else => try out.print(gpa, "%{X:0>2}", .{c}),
    };
    return out.items;
}

/// name reports whether s is a plain user name: lower-case ASCII letters
/// and digits, with dots, hyphens and underscores between them.
fn name(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s, 0..) |c, i| switch (c) {
        'a'...'z', '0'...'9' => {},
        '.', '-', '_' => if (i == 0 or i == s.len - 1) return false,
        else => return false,
    };
    return true;
}

fn exists(io: Io, p: []const u8) bool {
    Dir.cwd().access(io, p, .{}) catch return false;
    return true;
}

/// replace writes p whole or not at all: a temporary file, synced, then
/// renamed over it.
fn replace(io: Io, p: []const u8, data: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(p).?, .{ .iterate = true });
    defer dir.close(io);
    const base = std.fs.path.basename(p);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buf, ".{s}.tmp", .{base});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, base, io);
}

/// say prints one line to the console. Jellyfin's answers are never
/// quoted, so nothing from it reaches the log.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "jellyfin-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "networkXml serves loopback at the port it is given" {
    const x = networkXml(setup_port);
    try testing.expect(std.mem.indexOf(u8, x, "<InternalHttpPort>8097</InternalHttpPort>") != null);
    try testing.expect(std.mem.indexOf(u8, x, "<EnableUPnP>false</EnableUPnP>") != null);
    try testing.expect(std.mem.indexOf(u8, x, "<string>127.0.0.1</string>") != null);
}

test "escape encodes a path for a query" {
    const e = try escape(testing.allocator, "/data/svc/jellyfin/media/movies");
    defer testing.allocator.free(e);
    try testing.expectEqualStrings("%2Fdata%2Fsvc%2Fjellyfin%2Fmedia%2Fmovies", e);
}

test "name takes plain user names" {
    try testing.expect(name("alice"));
    for ([_][]const u8{ "", "Alice", "a b", "a\"", "-a" }) |bad| try testing.expect(!name(bad));
}
