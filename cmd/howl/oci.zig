//! oci pulls an OCI image with crane and unpacks it into a form's root at
//! /oci/NAME, so the machine never pulls or mounts anything. See README.md
//! and docs/design/oci.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const sandbox = @import("sandbox");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const json = std.json;
const Why = howl.Why;

// The unpacker's limits are fixed by docs/design/oci.md, not configurable.
const max_entries = 500_000;
const max_bytes: u64 = 8 << 30;
const max_name = 4096;
const max_component = 255;
const max_pax = 64 << 10;
const max_config = 4 << 20;
const max_links = 40;

pub const default_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// devices are the device nodes init binds into an image's root.
pub const devices = [_][]const u8{ "null", "zero", "full", "random", "urandom" };

/// platform returns crane's --platform for the machine's architecture.
pub fn platform(arch: []const u8) []const u8 {
    return if (std.mem.eql(u8, arch, "aarch64")) "linux/arm64" else "linux/amd64";
}

/// isRef reports whether s can be an image reference: up to 512 letters,
/// digits and ._:/@-, starting with a letter or digit, so it is never a flag.
pub fn isRef(s: []const u8) bool {
    if (s.len == 0 or s.len > 512 or !std.ascii.isAlphanumeric(s[0])) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._:/@-", c) == null)
        return false;
    return true;
}

/// resolve returns ref pinned as REPO@sha256:HEX. A tag, or no tag, is resolved
/// once with crane, so the form records bytes rather than a name that may move.
pub fn resolve(io: Io, gpa: Allocator, ref: []const u8, why: *Why) ![]const u8 {
    if (std.mem.find(u8, ref, "@sha256:")) |at| {
        if (ref.len != at + "@sha256:".len + 64) return why.refuse(
            "{s}: a digest is sha256: and 64 hex digits",
            .{ref},
        );
        return ref;
    }
    const said = try crane(io, gpa, &.{ "digest", ref }, why);
    const digest = std.mem.trim(u8, said, " \r\n");
    if (!std.mem.startsWith(u8, digest, "sha256:") or digest.len != "sha256:".len + 64)
        return why.refuse("crane digest {s}: said {s}", .{ ref, digest });
    // Strip the tag: a colon after the last slash. A colon before it is a
    // registry port.
    const slash = std.mem.findScalarLast(u8, ref, '/') orelse 0;
    const repo = if (std.mem.findScalarLast(u8, ref, ':')) |c|
        (if (c > slash) ref[0..c] else ref)
    else
        ref;
    return gpa.print("{s}@{s}", .{ repo, digest });
}

/// Config is what the image's config says to run, as crane reports it.
pub const Config = struct {
    entrypoint: []const []const u8 = &.{},
    cmd: []const []const u8 = &.{},
    env: []const []const u8 = &.{},
    workdir: []const u8 = "",
    user: []const u8 = "",
    /// exposed holds ports as declared, such as "8080/tcp".
    exposed: []const []const u8 = &.{},
    volumes: []const []const u8 = &.{},

    /// path returns the image's PATH, or default_path if it sets none.
    pub fn path(c: Config) []const u8 {
        for (c.env) |e| if (std.mem.startsWith(u8, e, "PATH=")) return e["PATH=".len..];
        return default_path;
    }
};

pub fn config(io: Io, gpa: Allocator, ref: []const u8, arch: []const u8, why: *Why) !Config {
    const text = try crane(io, gpa, &.{ "--platform", platform(arch), "config", ref }, why);
    const v = json.parseFromSliceLeaky(json.Value, gpa, text, .{}) catch
        return why.refuse("crane config {s}: not JSON", .{ref});
    const c = (if (v == .object) v.object.get("config") else null) orelse
        return why.refuse("{s}: its image config has no config", .{ref});
    if (c != .object) return why.refuse("{s}: its image config has no config", .{ref});
    return .{
        .entrypoint = try strings(gpa, c.object.get("Entrypoint")),
        .cmd = try strings(gpa, c.object.get("Cmd")),
        .env = try strings(gpa, c.object.get("Env")),
        .workdir = string(c.object.get("WorkingDir")),
        .user = string(c.object.get("User")),
        .exposed = try keys(gpa, c.object.get("ExposedPorts")),
        .volumes = try keys(gpa, c.object.get("Volumes")),
    };
}

fn strings(gpa: Allocator, v: ?json.Value) ![]const []const u8 {
    const a = v orelse return &.{};
    if (a != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (a.array.items) |item| if (item == .string) try out.append(gpa, item.string);
    return out.items;
}

fn string(v: ?json.Value) []const u8 {
    const s = v orelse return "";
    return if (s == .string) s.string else "";
}

fn keys(gpa: Allocator, v: ?json.Value) ![]const []const u8 {
    const o = v orelse return &.{};
    if (o != .object) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (o.object.keys()) |k| try out.append(gpa, k);
    std.mem.sortUnstable([]const u8, out.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    return out.items;
}

/// crane runs crane with args and returns its standard output. On failure it
/// refuses with the last line crane wrote to standard error.
fn crane(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) ![]const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(gpa, "crane");
    try argv.appendSlice(gpa, args);
    const r = std.process.run(gpa, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(max_config),
        .stderr_limit = .limited(64 << 10),
    }) catch |err| return why.refuse(
        "crane: {s}; crane pulls images, and tools/install-deps installs it",
        .{@errorName(err)},
    );
    if (r.term != .exited or r.term.exited != 0) return why.refuse(
        "crane {s} {s}: {s}",
        .{ args[args.len - 2], args[args.len - 1], lastLine(r.stderr) },
    );
    return r.stdout;
}

fn lastLine(text: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, text, " \r\n");
    const start = if (std.mem.findScalarLast(u8, t, '\n')) |n| n + 1 else 0;
    return if (t.len == 0) "failed" else t[start..];
}

/// Unpacked counts the entries and bytes unpacked, and the device nodes, FIFOs
/// and sockets left out.
pub const Unpacked = struct { files: usize = 0, bytes: u64 = 0, left_out: usize = 0 };

/// pull unpacks the image's root filesystem into dir, creating it. crane export
/// pipes the flattened layers into `howl _unpack`, which runs with no
/// environment so it cannot see the operator's credentials.
pub fn pull(
    io: Io,
    gpa: Allocator,
    ref: []const u8,
    arch: []const u8,
    dir: []const u8,
    why: *Why,
) !Unpacked {
    const self = try std.process.executablePathAlloc(io, gpa);
    var puller = std.process.spawn(io, .{
        .argv = &.{ "crane", "--platform", platform(arch), "export", ref, "-" },
        .stdin = .ignore,
        .stdout = .pipe,
    }) catch |err| return why.refuse(
        "crane: {s}; crane pulls images, and tools/install-deps installs it",
        .{@errorName(err)},
    );
    const from = puller.stdout.?;
    var none: std.process.Environ.Map = .init(gpa);
    var unpack_child = std.process.spawn(io, .{
        .argv = &.{ self, "_unpack", dir },
        .stdin = .{ .file = from },
        .stdout = .pipe,
        .environ_map = &none,
    }) catch |err| {
        from.close(io);
        _ = puller.wait(io) catch {};
        return why.refuse("howl _unpack: {s}", .{@errorName(err)});
    };
    from.close(io);
    var said_buf: [256]u8 = undefined;
    var rd = unpack_child.stdout.?.readerStreaming(io, &said_buf);
    const said = rd.interface.allocRemaining(gpa, .limited(4096)) catch "";
    const ut = unpack_child.wait(io) catch |err| return why.refuse(
        "howl _unpack: {s}",
        .{@errorName(err)},
    );
    const pt = puller.wait(io) catch |err| return why.refuse(
        "crane export: {s}",
        .{@errorName(err)},
    );
    // Check the unpacker first: when it refuses, crane dies of a broken
    // pipe and would otherwise be blamed.
    if (ut != .exited or ut.exited != 0) return why.refuse(
        "{s}: the image was refused, as said above",
        .{ref},
    );
    if (pt != .exited or pt.exited != 0) return why.refuse(
        "crane export {s} failed; what it said is above",
        .{ref},
    );
    var words = std.mem.tokenizeAny(u8, said, " \n");
    return .{
        .files = std.fmt.parseInt(usize, words.next() orelse "0", 10) catch 0,
        .bytes = std.fmt.parseInt(u64, words.next() orelse "0", 10) catch 0,
        .left_out = std.fmt.parseInt(usize, words.next() orelse "0", 10) catch 0,
    };
}

/// unpackMain is `howl _unpack DIR`: it unpacks a tar from standard input into
/// DIR and prints one line, "FILES BYTES LEFT_OUT". Refusals go to standard error.
pub fn unpackMain(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    if (args.len != 1) return why.refuse("_unpack DIR", .{});
    const dir = args[0];
    Dir.cwd().createDirPath(io, dir) catch |err|
        return why.refuse("{s}: {s}", .{ dir, @errorName(err) });
    var root = Dir.cwd().openDir(io, dir, .{}) catch |err|
        return why.refuse("{s}: {s}", .{ dir, @errorName(err) });
    defer root.close(io);
    // Confine to DIR before reading a byte, so a hostile tar cannot write
    // anywhere else or reach the network.
    if (builtin.os.tag == .linux) sandbox.landlock(&.{.{
        .fd = @intCast(root.handle),
        .access = sandbox.own_dir | 0x1000 | 0x2000, // and MAKE_SYM, REFER
    }}, &.{}) catch |err| return why.refuse("sealing: {s}", .{@errorName(err)});
    var buf: [64 << 10]u8 = undefined;
    var in = Io.File.stdin().readerStreaming(io, &buf);
    const u = try unpack(io, gpa, &in.interface, root, why);
    var out = Io.File.stdout().writerStreaming(io, &.{});
    try out.interface.print("{d} {d} {d}\n", .{ u.files, u.bytes, u.left_out });
    try out.interface.flush();
}

/// unpack writes the tar on r beneath root. It refuses the whole image at the
/// first unclean name, path through a link, or hard link to anything but a file
/// already unpacked. Device nodes, FIFOs and sockets are counted and skipped.
/// Only the execute bit of a mode survives, so setuid bits are dropped.
pub fn unpack(io: Io, gpa: Allocator, r: *Io.Reader, root: Dir, why: *Why) !Unpacked {
    var tar: Tar = .{ .r = r };
    var u: Unpacked = .{};
    while (try tar.next(why)) |e| {
        const name = clean(e.name) orelse
            return why.refuse("{s}: not a clean name: .., an empty part, or a whiteout", .{e.name});
        if (name.len == 0) continue;
        u.files += 1;
        if (u.files > max_entries) return why.refuse("more than {d} entries", .{max_entries});
        try throughNoLink(io, gpa, root, name, why);
        switch (e.kind) {
            .dir => root.createDirPath(io, name) catch |err|
                return why.refuse("{s}: {s}", .{ name, @errorName(err) }),
            .file => {
                u.bytes += e.size;
                if (u.bytes > max_bytes) return why.refuse("more than {d} bytes", .{max_bytes});
                try parentOf(io, root, name, why);
                root.deleteTree(io, name) catch {};
                var f = root.createFile(io, name, .{
                    .exclusive = true,
                    .permissions = .fromMode(if (e.mode & 0o111 != 0) 0o755 else 0o644),
                }) catch |err| return why.refuse("{s}: {s}", .{ name, @errorName(err) });
                defer f.close(io);
                var wbuf: [64 << 10]u8 = undefined;
                var w = f.writerStreaming(io, &wbuf);
                tar.r.streamExact64(&w.interface, e.size) catch |err|
                    return why.refuse("{s}: {s}: the tar ends early", .{ name, @errorName(err) });
                w.interface.flush() catch |err|
                    return why.refuse("{s}: {s}", .{ name, @errorName(err) });
                tar.left = 0;
            },
            .symlink => {
                if (e.link.len == 0 or e.link.len > max_name)
                    return why.refuse("{s}: a link to nothing", .{name});
                try parentOf(io, root, name, why);
                root.deleteTree(io, name) catch {};
                root.symLink(io, e.link, name, .{}) catch |err|
                    return why.refuse("{s}: {s}", .{ name, @errorName(err) });
            },
            .hardlink => {
                const target = clean(e.link) orelse
                    return why.refuse(
                        "{s}: a hard link to {s}, not a clean name",
                        .{ name, e.link },
                    );
                const st = root.statFile(io, target, .{}) catch
                    return why.refuse(
                        "{s}: a hard link to {s}, which is not in the tree yet",
                        .{ name, target },
                    );
                if (st.kind != .file)
                    return why.refuse("{s}: a hard link to {s}, not a file", .{ name, target });
                try parentOf(io, root, name, why);
                root.deleteTree(io, name) catch {};
                Dir.hardLink(root, target, root, name, io, .{}) catch |err|
                    return why.refuse("{s}: {s}", .{ name, @errorName(err) });
            },
            // Root images often hold device nodes, such as apko's
            // /dev/console. Skipping them is safe: init binds in the
            // devices the service gets.
            .other => u.left_out += 1,
        }
    }
    return u;
}

/// clean strips leading ./ and /, and trailing /. It returns "" for the root,
/// and null if any part is empty, too long, . or .., or a whiteout.
fn clean(name: []const u8) ?[]const u8 {
    var s = name;
    while (std.mem.startsWith(u8, s, "./")) s = s[2..];
    s = std.mem.trimStart(u8, s, "/");
    s = std.mem.trimEnd(u8, s, "/");
    if (std.mem.eql(u8, s, ".")) return "";
    if (s.len > max_name) return null;
    var parts = std.mem.splitScalar(u8, s, '/');
    while (parts.next()) |p| {
        if (s.len == 0) break;
        if (p.len == 0 or p.len > max_component or std.mem.eql(u8, p, ".") or
            std.mem.eql(u8, p, "..") or std.mem.startsWith(u8, p, ".wh.")) return null;
    }
    return s;
}

/// throughNoLink refuses name if any directory above it is a symbolic link,
/// which could redirect the write outside the tree.
fn throughNoLink(io: Io, gpa: Allocator, root: Dir, name: []const u8, why: *Why) !void {
    var buf: [max_name]u8 = undefined;
    var at: usize = 0;
    while (std.mem.findScalarPos(u8, name, at, '/')) |slash| : (at = slash + 1) {
        const prefix = name[0..slash];
        if (root.readLink(io, prefix, &buf)) |_| return why.refuse(
            "{s}: through {s}, a link",
            .{ name, prefix },
        ) else |_| {}
    }
    _ = gpa;
}

fn parentOf(io: Io, root: Dir, name: []const u8, why: *Why) !void {
    if (std.fs.path.dirname(name)) |d| root.createDirPath(io, d) catch |err|
        return why.refuse("{s}: {s}", .{ d, @errorName(err) });
}

/// Tar reads ustar entries, with PAX path, linkpath and size records and GNU
/// long names. That covers what crane writes; nothing else is understood.
const Tar = struct {
    r: *Io.Reader,
    /// left is the unread part of the current entry's body, and pad is the
    /// padding after it to the next 512-byte block.
    left: u64 = 0,
    pad: usize = 0,
    name_buf: [max_name]u8 = undefined,
    link_buf: [max_name]u8 = undefined,
    pax_buf: [max_pax]u8 = undefined,

    const Kind = enum { file, dir, symlink, hardlink, other };
    const Entry = struct {
        name: []const u8,
        link: []const u8,
        size: u64,
        mode: u32,
        kind: Kind,
        /// what names an .other entry's type, for messages.
        what: []const u8 = "",
    };

    fn next(t: *Tar, why: *Why) !?Entry {
        t.r.discardAll64(t.left) catch return why.refuse("the tar ends early", .{});
        t.r.discardAll(t.pad) catch return why.refuse("the tar ends early", .{});
        t.left = 0;
        t.pad = 0;
        var name: []const u8 = "";
        var link: []const u8 = "";
        var pax_size: ?u64 = null;
        var hdr: [512]u8 = undefined;
        while (true) {
            const n = t.r.readSliceShort(&hdr) catch return why.refuse("the tar ends early", .{});
            if (n == 0) return null;
            if (n < hdr.len) return why.refuse("the tar ends inside a header", .{});
            if (std.mem.allEqual(u8, &hdr, 0)) return null;
            if (!checksumOk(&hdr)) return why.refuse(
                "not a tar, or damaged: a header's checksum is wrong",
                .{},
            );
            const size = number(hdr[124..136]) orelse return why.refuse(
                "a header's size is not a number",
                .{},
            );
            const typeflag = hdr[156];
            switch (typeflag) {
                'x' => {
                    if (size > max_pax) return why.refuse(
                        "an extended header of {d} bytes",
                        .{size},
                    );
                    const pax = t.pax_buf[0..@intCast(size)];
                    t.r.readSliceAll(pax) catch return why.refuse("the tar ends early", .{});
                    t.r.discardAll(padding(size)) catch return why.refuse(
                        "the tar ends early",
                        .{},
                    );
                    var at: usize = 0;
                    while (at < pax.len) {
                        // Each record is "LEN key=value\n"; LEN counts the whole record.
                        const sp = std.mem.findScalarPos(u8, pax, at, ' ') orelse break;
                        const len = std.fmt.parseInt(usize, pax[at..sp], 10) catch
                            return why.refuse("an extended header record is malformed", .{});
                        if (len == 0 or at + len > pax.len or pax[at + len - 1] != '\n')
                            return why.refuse("an extended header record is malformed", .{});
                        const rec = pax[sp + 1 .. at + len - 1];
                        at += len;
                        const eq = std.mem.findScalar(u8, rec, '=') orelse continue;
                        const key = rec[0..eq];
                        const value = rec[eq + 1 ..];
                        if (std.mem.eql(u8, key, "path")) {
                            name = value;
                        } else if (std.mem.eql(u8, key, "linkpath")) {
                            link = value;
                        } else if (std.mem.eql(u8, key, "size")) {
                            pax_size = std.fmt.parseInt(u64, value, 10) catch
                                return why.refuse("an extended header's size is not a number", .{});
                        }
                    }
                },
                'g' => t.r.discardAll64(size + padding(size)) catch
                    return why.refuse("the tar ends early", .{}),
                'L', 'K' => {
                    if (size == 0 or
                        size > max_name) return why.refuse("a long name of {d} bytes", .{size});
                    const into = if (typeflag == 'L') &t.name_buf else &t.link_buf;
                    const s = into[0..@intCast(size)];
                    t.r.readSliceAll(s) catch return why.refuse("the tar ends early", .{});
                    t.r.discardAll(padding(size)) catch return why.refuse(
                        "the tar ends early",
                        .{},
                    );
                    const text = std.mem.sliceTo(s, 0);
                    if (typeflag == 'L') name = text else link = text;
                },
                else => {
                    if (name.len == 0) name = ustarName(&hdr, &t.name_buf);
                    if (link.len == 0) {
                        const l = std.mem.sliceTo(hdr[157..257], 0);
                        @memcpy(t.link_buf[0..l.len], l);
                        link = t.link_buf[0..l.len];
                    }
                    const body = pax_size orelse size;
                    t.left = body;
                    t.pad = padding(body);
                    return .{
                        .name = name,
                        .link = link,
                        .size = body,
                        .mode = @intCast(number(hdr[100..108]) orelse 0),
                        .kind = switch (typeflag) {
                            '0', 0, '7' => .file,
                            '5' => .dir,
                            '2' => .symlink,
                            '1' => .hardlink,
                            else => .other,
                        },
                        .what = switch (typeflag) {
                            '3' => "character device",
                            '4' => "block device",
                            '6' => "FIFO",
                            else => "kind of entry this does not know",
                        },
                    };
                },
            }
        }
    }
};

fn padding(size: u64) usize {
    return @intCast((512 - size % 512) % 512);
}

/// number parses a header's numeric field: octal, or base-256 when the first
/// bit is set, as GNU tar writes sizes past 8 GiB.
fn number(field: []const u8) ?u64 {
    if (field[0] & 0x80 != 0) {
        var v: u64 = 0;
        for (field[1..]) |b| v = (v << 8) | b;
        return v;
    }
    const s = std.mem.trim(u8, std.mem.sliceTo(field, 0), " ");
    if (s.len == 0) return 0;
    return std.fmt.parseInt(u64, s, 8) catch null;
}

fn checksumOk(hdr: *const [512]u8) bool {
    const want = number(hdr[148..156]) orelse return false;
    var sum: u64 = 0;
    for (hdr, 0..) |b, i| sum += if (i >= 148 and i < 156) ' ' else b;
    return sum == want;
}

/// ustarName joins the ustar prefix and name fields with a slash.
fn ustarName(hdr: *const [512]u8, buf: *[max_name]u8) []const u8 {
    const name = std.mem.sliceTo(hdr[0..100], 0);
    const prefix = if (std.mem.eql(u8, hdr[257..262], "ustar"))
        std.mem.sliceTo(hdr[345..500], 0)
    else
        "";
    if (prefix.len == 0) {
        @memcpy(buf[0..name.len], name);
        return buf[0..name.len];
    }
    @memcpy(buf[0..prefix.len], prefix);
    buf[prefix.len] = '/';
    @memcpy(buf[prefix.len + 1 .. prefix.len + 1 + name.len], name);
    return buf[0 .. prefix.len + 1 + name.len];
}

/// prepare creates, empty, every path init binds into the root (cmd/init/oci.zig):
/// /proc, the CPU directory, /tmp, /run, /data, each path in writes, the devices,
/// resolv.conf and hosts. It replaces whatever the image had there, links too,
/// and writes a hosts file naming the service.
pub fn prepare(
    io: Io,
    gpa: Allocator,
    dir: []const u8,
    name: []const u8,
    writes: []const []const u8,
    why: *Why,
) !void {
    var root = Dir.cwd().openDir(io, dir, .{}) catch |err|
        return why.refuse("{s}: {s}", .{ dir, @errorName(err) });
    defer root.close(io);
    for ([_][]const u8{ "proc", "sys/devices/system/cpu", "tmp", "run", "data" }) |d|
        try place(io, root, d, .dir, why);
    for (writes) |w| try place(io, root, std.mem.trimStart(u8, w, "/"), .dir, why);
    for (devices) |d| try place(io, root, try gpa.print("dev/{s}", .{d}), .file, why);
    // Images log to /dev/stdout and friends, so link them as devtmpfs
    // does, through the procfs init mounts in the root.
    for ([_][2][]const u8{
        .{ "stdin", "/proc/self/fd/0" },
        .{ "stdout", "/proc/self/fd/1" },
        .{ "stderr", "/proc/self/fd/2" },
        .{ "fd", "/proc/self/fd" },
    }) |l| {
        const at = try gpa.print("dev/{s}", .{l[0]});
        root.deleteTree(io, at) catch {};
        root.symLink(io, l[1], at, .{}) catch |err|
            return why.refuse("{s}/{s}: {s}", .{ dir, at, @errorName(err) });
    }
    try place(io, root, "etc/resolv.conf", .file, why);
    try place(io, root, "etc/hosts", .file, why);
    root.writeFile(io, .{
        .sub_path = "etc/hosts",
        .data = try gpa.print("127.0.0.1 localhost {s}\n::1 localhost\n", .{name}),
    }) catch |err| return why.refuse("{s}/etc/hosts: {s}", .{ dir, @errorName(err) });
}

/// place creates an empty directory or file at path. It replaces any link
/// above path with a directory, so a bind mount cannot land outside the image.
fn place(io: Io, root: Dir, path: []const u8, kind: enum { dir, file }, why: *Why) !void {
    var buf: [max_name]u8 = undefined;
    var at: usize = 0;
    while (std.mem.findScalarPos(u8, path, at, '/')) |slash| : (at = slash + 1) {
        const prefix = path[0..slash];
        if (root.readLink(io, prefix, &buf)) |_| {
            root.deleteFile(io, prefix) catch |err|
                return why.refuse("{s}: {s}", .{ prefix, @errorName(err) });
        } else |_| {}
        root.createDirPath(io, prefix) catch |err|
            return why.refuse("{s}: {s}", .{ prefix, @errorName(err) });
    }
    root.deleteTree(io, path) catch {};
    switch (kind) {
        .dir => root.createDirPath(io, path) catch |err|
            return why.refuse("{s}: {s}", .{ path, @errorName(err) }),
        .file => {
            var f = root.createFile(io, path, .{ .exclusive = true }) catch |err|
                return why.refuse("{s}: {s}", .{ path, @errorName(err) });
            f.close(io);
        },
    }
}

/// entrypoint returns the service's argv: override, or the image's entrypoint
/// and command. The program is looked up on the image's PATH, following links
/// only inside the tree, and must be ELF. A `#!` script is refused because its
/// interpreter would have to run too.
pub fn entrypoint(
    io: Io,
    gpa: Allocator,
    dir: []const u8,
    name: []const u8,
    cfg: Config,
    override: ?[]const []const u8,
    why: *Why,
) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    if (override) |o| try argv.appendSlice(gpa, o) else {
        try argv.appendSlice(gpa, cfg.entrypoint);
        try argv.appendSlice(gpa, cfg.cmd);
    }
    if (argv.items.len == 0) return why.refuse(
        "{s}: the image names no entrypoint or command: say --{s}.exec '/PROGRAM ARGS'",
        .{ name, name },
    );
    const prog = argv.items[0];
    var path: ?[]const u8 = null;
    if (std.mem.findScalar(u8, prog, '/') != null) {
        if (prog[0] != '/') return why.refuse(
            "{s}: {s} is a relative path; name the program from the image's root",
            .{ name, prog },
        );
        if (try resolveIn(io, gpa, dir, prog) != null) path = prog;
    } else {
        var dirs = std.mem.tokenizeScalar(u8, cfg.path(), ':');
        while (dirs.next()) |d| {
            const candidate = try gpa.print("{s}/{s}", .{ std.mem.trimEnd(u8, d, "/"), prog });
            if (try resolveIn(io, gpa, dir, candidate) != null) {
                path = candidate;
                break;
            }
        }
    }
    const p = path orelse return why.refuse(
        "{s}: no {s} in the image (PATH {s}); say --{s}.exec '/PROGRAM ARGS'",
        .{ name, prog, cfg.path(), name },
    );
    const real = (try resolveIn(io, gpa, dir, p)).?;
    var head: [4]u8 = undefined;
    const f = Dir.cwd().openFile(io, real, .{}) catch
        return why.refuse("{s}: {s}: cannot read it", .{ name, p });
    defer f.close(io);
    var rd = f.readerStreaming(io, &.{});
    const n = rd.interface.readSliceShort(&head) catch 0;
    if (n >= 2 and std.mem.eql(u8, head[0..2], "#!")) return why.refuse(
        "{s}: {s} is a script, and werewolf runs an ELF entrypoint alone: its interpreter " ++
            "would have to run too. A form that runs this (howl --with ...) needs no script; " ++
            "else --{s}.exec '/PROGRAM ARGS' names the program",
        .{ name, p, name },
    );
    if (n < 4 or !std.mem.eql(u8, &head, "\x7fELF")) return why.refuse(
        "{s}: {s} is not an ELF program",
        .{ name, p },
    );
    argv.items[0] = p;
    return argv.items;
}

/// resolveIn maps path, absolute in the image, to a host path beneath dir. It
/// follows links inside the tree, treating absolute targets as relative to dir.
/// It returns null if nothing is there or it follows more than max_links links.
fn resolveIn(io: Io, gpa: Allocator, dir: []const u8, path: []const u8) !?[]const u8 {
    var todo: std.ArrayList([]const u8) = .empty;
    try pushParts(gpa, &todo, path);
    var cur: std.ArrayList(u8) = .empty;
    var followed: usize = 0;
    var buf: [max_name]u8 = undefined;
    while (todo.pop()) |part| {
        if (std.mem.eql(u8, part, ".") or part.len == 0) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (std.mem.findScalarLast(u8, cur.items, '/')) |s| cur.shrinkRetainingCapacity(s);
            continue;
        }
        try cur.append(gpa, '/');
        try cur.appendSlice(gpa, part);
        const host = try gpa.print("{s}{s}", .{ dir, cur.items });
        if (Dir.cwd().readLink(io, host, &buf)) |n| {
            followed += 1;
            if (followed > max_links) return null;
            const target = buf[0..n];
            if (std.mem.findScalarLast(u8, cur.items, '/')) |s| cur.shrinkRetainingCapacity(s);
            if (target.len > 0 and target[0] == '/') cur.clearRetainingCapacity();
            try pushParts(gpa, &todo, target);
        } else |_| {}
    }
    const host = try gpa.print("{s}{s}", .{ dir, cur.items });
    Dir.cwd().access(io, host, .{}) catch return null;
    return host;
}

/// pushParts pushes path's parts last first, so they pop in order.
fn pushParts(gpa: Allocator, todo: *std.ArrayList([]const u8), path: []const u8) !void {
    var parts = std.mem.splitScalar(u8, path, '/');
    var list: std.ArrayList([]const u8) = .empty;
    while (parts.next()) |p| try list.append(gpa, p);
    var i = list.items.len;
    while (i > 0) : (i -= 1) try todo.append(gpa, list.items[i - 1]);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test clean {
    try testing.expectEqualStrings("usr/bin/x", clean("./usr/bin/x").?);
    try testing.expectEqualStrings("usr/bin", clean("/usr/bin/").?);
    try testing.expectEqualStrings("", clean("./").?);
    try testing.expectEqualStrings("", clean(".").?);
    for ([_][]const u8{
        "a/../b",
        "a//b",
        "a/./b",
        ".wh.x",
        "etc/.wh..wh..opq",
        "a/..",
        "..",
    }) |bad|
        try testing.expectEqual(null, clean(bad));
}

test "numbers and checksums" {
    try testing.expectEqual(@as(u64, 0o644), number("0000644\x00").?);
    try testing.expectEqual(@as(u64, 0), number("        ").?);
    try testing.expectEqual(null, number("12x\x00"));
    var big: [12]u8 = @splat(0);
    big[0] = 0x80;
    big[11] = 7;
    try testing.expectEqual(@as(u64, 7), number(&big).?);
}

test isRef {
    for ([_][]const u8{ "nginx", "ghcr.io/acme/web:1.4", "localhost:5000/x@sha256:ab" }) |ok|
        try testing.expect(isRef(ok));
    for ([_][]const u8{ "", "-x", "a b", "/etc", "a;b" }) |bad| try testing.expect(!isRef(bad));
}

/// tarOf builds a tar in memory from (name, type, body, link) entries.
fn tarOf(
    gpa: Allocator,
    entries: []const struct { []const u8, u8, []const u8, []const u8 },
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (entries) |e| {
        var hdr: [512]u8 = @splat(0);
        @memcpy(hdr[0..e[0].len], e[0]);
        _ = try std.mem.print(
            hdr[100..108],
            "{o:0>7}",
            .{@as(u32, if (e[1] == '5') 0o755 else 0o644)},
        );
        _ = try std.mem.print(hdr[124..136], "{o:0>11}", .{e[2].len});
        hdr[156] = e[1];
        @memcpy(hdr[157 .. 157 + e[3].len], e[3]);
        @memcpy(hdr[257..263], "ustar\x00");
        @memset(hdr[148..156], ' ');
        var sum: u64 = 0;
        for (hdr) |b| sum += b;
        _ = try std.mem.print(hdr[148..155], "{o:0>6}\x00", .{sum});
        try out.appendSlice(gpa, &hdr);
        try out.appendSlice(gpa, e[2]);
        try out.appendNTimes(gpa, 0, padding(e[2].len));
    }
    try out.appendNTimes(gpa, 0, 1024);
    return out.items;
}

test "unpack: files, directories, links; refusals" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var why: Why = .{};
    const good = try tarOf(gpa, &.{
        .{ "./", '5', "", "" },
        .{ "bin/", '5', "", "" },
        .{ "bin/server", '0', "\x7fELF....", "" },
        .{ "bin/alias", '1', "", "bin/server" },
        .{ "lib", '2', "", "usr/lib" },
        .{ "etc/hostname", '0', "web\n", "" },
        .{ "dev/console", '3', "", "" },
        .{ "run/fifo", '6', "", "" },
    });
    var r: Io.Reader = .fixed(good);
    const u = try unpack(io, gpa, &r, tmp.dir, &why);
    try testing.expectEqual(7, u.files);
    try testing.expectEqual(12, u.bytes);
    try testing.expectEqual(2, u.left_out);
    try testing.expectEqualStrings(
        "web\n",
        try tmp.dir.readFileAlloc(io, "etc/hostname", gpa, .limited(16)),
    );
    try testing.expectEqualStrings(
        "\x7fELF....",
        try tmp.dir.readFileAlloc(io, "bin/alias", gpa, .limited(16)),
    );
    var lbuf: [64]u8 = undefined;
    try testing.expectEqualStrings("usr/lib", lbuf[0..try tmp.dir.readLink(io, "lib", &lbuf)]);
    for ([_]struct { []const u8, u8, []const u8, []const u8 }{
        .{ "../etc/passwd", '0', "x", "" },
        .{ "lib/x", '0', "x", "" }, // through the link made above
        .{ "a/.wh.b", '0', "", "" },
        .{ "stray", '1', "", "nowhere" },
    }) |bad| {
        var bw: Why = .{};
        var br: Io.Reader = .fixed(try tarOf(gpa, &.{bad}));
        try testing.expectError(error.Refused, unpack(io, gpa, &br, tmp.dir, &bw));
    }
}
