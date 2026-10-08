//! cloud-metadata: werewolf's config, from a cloud's metadata server.
//!
//!     cloud     on a cloud werewolf knows, fetch the instance's user data,
//!               and if it is a werewolf config tar, leave it for init in
//!               /run/werewolf/cloud/config.tar
//!
//! init runs it once at boot, after the network is up, when no config tar
//! was found on a disk or beside the victim. It exits 0 with nothing written
//! where there is no known cloud, no user data, or user data that is not
//! werewolf's (someone's #cloud-config, say), and 1 on an error.
//!
//! The user data is the config tar, base64-encoded: on GCP the instance's
//! `user-data` attribute, on AWS its user data, on Hetzner Cloud its
//! user_data, on Azure its userData. The cloud is known from the firmware's DMI strings before any
//! packet is sent, so nothing is asked of 169.254.169.254 on a network
//! where a neighbour might answer for it.
//!
//! Two processes, as werewolf's programs are written (docs/programs.md):
//!
//!   fetcher   runs as _cloud (uid 68), chrooted to the empty /var/empty,
//!             with no capabilities, under Landlock, which lets it reach
//!             no file and connect over TCP to port 80 alone, and a seccomp
//!             filter that allows a TCP socket and little else: no UDP. It
//!             runs before fence sets the network policy, so these are what
//!             hold it. It makes the HTTP requests, reads at most 128 KiB,
//!             and sends the parent the response's body.
//!   parent    stays root's uid with no capabilities at all, under Landlock,
//!             which confines its writes to /run/werewolf/cloud, and seccomp.
//!             It never touches the network. It decodes the body, checks the
//!             tar entry by entry (regular files and directories, names of a
//!             few safe characters, no absolute paths, no "..", sizes in
//!             bounds), and writes a new tar of what passed, every entry
//!             owned by root, so init extracts only what werewolf wrote.
//!
//! Every event is one JSON line on stdout, from the parent.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const sandbox = @import("sandbox");
const sys = sandbox.sys;

const out_dir = "/run/werewolf/cloud";
const empty_dir = "/var/empty";
/// _cloud, in prod.yaml's accounts.
const fetcher_id: u32 = 68;
const metadata_ip = [4]u8{ 169, 254, 169, 254 };

const max_response = 128 << 10;
const max_config = 48 << 10;
const max_file = 32 << 10;
const max_entries = 32;

/// The clouds werewolf knows: how the firmware names them, and where each
/// keeps an instance's user data.
const Provider = struct {
    name: []const u8,
    /// DMI sys_vendor, exactly.
    vendor: []const u8,
    /// DMI product_name, exactly, where the vendor alone is not enough.
    product: ?[]const u8 = null,
    /// DMI chassis_asset_tag, exactly, where the product is not enough.
    asset: ?[]const u8 = null,
    path: []const u8,
    /// One extra request header, if the server insists on it.
    header: []const u8 = "",
    /// AWS's IMDSv2: a session token from a PUT before the GET.
    token: bool = false,
    /// GCP's server says `Metadata-Flavor: Google` on every answer; one that
    /// does not is not it.
    flavor: bool = false,
};

const providers = [_]Provider{
    .{
        .name = "gcp",
        .vendor = "Google",
        .product = "Google Compute Engine",
        .path = "/computeMetadata/v1/instance/attributes/user-data",
        .header = "Metadata-Flavor: Google",
        .flavor = true,
    },
    .{ .name = "aws", .vendor = "Amazon EC2", .path = "/latest/user-data", .token = true },
    .{ .name = "hetzner", .vendor = "Hetzner", .path = "/hetzner/v1/userdata" },
    // Hyper-V on a desktop names itself as Azure does; only Azure sets
    // this asset tag.
    .{
        .name = "azure",
        .vendor = "Microsoft Corporation",
        .product = "Virtual Machine",
        .asset = "7783-7084-3265-9085-8269-3286-77",
        .path = "/metadata/instance/compute/userData?api-version=2021-01-01&format=text",
        .header = "Metadata: true",
    },
};

pub fn main(init: std.process.Init) !void {
    _ = init;
    // Speculative Store Bypass mitigated for this process and all it starts,
    // which werewolf leaves to each program, so workloads do not pay
    // (docs/security.md). Where the CPU has no control, the kernel refuses
    // and nothing changes.
    _ = linux.prctl(
        @backingInt(linux.PR.SET_SPECULATION_CTRL),
        linux.PR.SPEC_STORE_BYPASS,
        linux.PR.SPEC_FORCE_DISABLE,
        0,
        0,
    );
    var log: Log = .{};
    run(&log) catch |err| {
        log.event(
            "error",
            .{
                .step = step,
                .@"error" = @errorName(err),
                .detail = sandbox.failed,
                .errno = sandbox.errnoName(sandbox.failed_errno),
            },
        );
        linux.exit_group(1);
    };
    // Straight out: the runtime's cleanup would make system calls the
    // seccomp filter does not allow, and be killed for them.
    linux.exit_group(0);
}

/// What failed, and how, for the error event.
var step: []const u8 = "start";

/// Why the fetcher's last try failed, as the error event's detail.
var why_buf: [96]u8 = undefined;

/// The fetcher's failure, msg's kind and number, in the parent's own
/// words: nothing of the server's is passed on, only a byte it maps and
/// a number it prints.
fn failureText(buf: []u8, msg: []const u8) []const u8 {
    if (msg.len != 4) return "the fetcher failed and said no more";
    const n = std.mem.readInt(u16, msg[2..4], .big);
    const kind = std.enums.fromInt(Failure, msg[1]) orelse return "the fetcher said nonsense";
    const errno = std.enums.tagName(linux.E, @fromBackingInt(n)) orelse "unknown";
    return switch (kind) {
        .connect => std.mem.print(buf, "connecting to 169.254.169.254:80: {s}", .{errno}),
        .io => std.mem.print(buf, "talking to the metadata server: {s}", .{errno}),
        .timeout => "no answer from the metadata server within 5 s",
        .too_long => "the metadata server's answer is too long to be a config",
        .malformed => "the metadata server's answer is not HTTP as expected",
        .token => std.mem.print(buf, "no IMDSv2 token: HTTP {d}", .{n}),
        .status => std.mem.print(buf, "the user data: HTTP {d}", .{n}),
        .not_google => "the answer lacks Metadata-Flavor: Google; not GCP's server, refused",
        .request => "the request could not be made",
    } catch "the fetcher's failure, too long to say";
}

/// As root: which cloud, then the fork.
fn run(log: *Log) !void {
    var vendor_buf: [128]u8 = undefined;
    var product_buf: [128]u8 = undefined;
    var asset_buf: [128]u8 = undefined;
    const vendor = dmi("/sys/class/dmi/id/sys_vendor", &vendor_buf);
    const product = dmi("/sys/class/dmi/id/product_name", &product_buf);
    const asset = dmi("/sys/class/dmi/id/chassis_asset_tag", &asset_buf);
    const p = identify(vendor, product, asset) orelse {
        log.event(
            "skip",
            .{
                .reason = "not a cloud werewolf knows",
                .vendor = printable(vendor),
                .product = printable(product),
            },
        );
        return;
    };

    step = "setup";
    _ = linux.mkdirat(linux.AT.FDCWD, "/run/werewolf", 0o755);
    const made = linux.mkdirat(linux.AT.FDCWD, out_dir, 0o700);
    if (linux.errno(made) != .SUCCESS and linux.errno(made) != .EXIST) _ = try sys(
        made,
        "mkdir " ++ out_dir,
    );
    const dir: i32 = @intCast(try sys(
        linux.openat(
            linux.AT.FDCWD,
            out_dir,
            .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true },
            0,
        ),
        "open " ++ out_dir,
    ));
    var pipe: [2]i32 = undefined;
    _ = try sys(linux.pipe2(&pipe, .{ .CLOEXEC = true }), "pipe");
    const parent_pid = linux.getpid();

    const pid = try sys(linux.fork(), "fork");
    if (pid == 0) {
        _ = linux.close(pipe[0]);
        _ = linux.close(dir);
        fetcher(p, pipe[1], parent_pid);
    }
    _ = linux.close(pipe[1]);

    step = "sandbox";
    try sandboxParent(dir, pipe[0]);
    step = "fetch";
    var buf: [max_response + 8]u8 = undefined;
    const msg = try readAll(pipe[0], &buf);
    if (msg.len < 1) return error.FetcherFailed;
    switch (msg[0]) {
        result_body => {},
        result_none => return log.event("none", .{ .provider = p.name, .reason = "no user data" }),
        else => {
            sandbox.failed = failureText(&why_buf, msg);
            return error.Unreachable;
        },
    }

    step = "check";
    var raw: [max_config]u8 = undefined;
    const tar = decodeBase64(msg[1..], &raw) orelse
        return log.event(
            "none",
            .{
                .provider = p.name,
                .reason = "the user data is not a werewolf config (base64 of a tar)",
            },
        );
    var files: [max_entries]Entry = undefined;
    const n = checkTar(tar, &files) catch |err|
        return log.event("refused", .{ .provider = p.name, .reason = @errorName(err) });

    step = "write";
    var out: [max_config + (max_entries + 2) * 512]u8 = undefined;
    try writeFile(dir, "config.tar", writeTar(&out, files[0..n]));
    var names: [max_entries][]const u8 = undefined;
    for (files[0..n], 0..) |*f, i| names[i] = f.name();
    log.event("config", .{ .provider = p.name, .files = names[0..n] });
}

fn identify(vendor: []const u8, product: []const u8, asset: []const u8) ?Provider {
    for (providers) |p| {
        if (!std.mem.eql(u8, vendor, p.vendor)) continue;
        if (p.product) |want| if (!std.mem.eql(u8, product, want)) continue;
        if (p.asset) |want| if (!std.mem.eql(u8, asset, want)) continue;
        return p;
    }
    return null;
}

/// A DMI string, trimmed; empty where the firmware has none.
fn dmi(path: [*:0]const u8, buf: *[128]u8) []const u8 {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return "";
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const n = linux.read(fd, buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return "";
    return std.mem.trim(u8, buf[0..n], " \n\t");
}

/// For logging DMI strings, which are the firmware's: letters, digits and
/// a little punctuation, or nothing.
fn printable(s: []const u8) []const u8 {
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and
        std.mem.findScalar(u8, " .-_()", c) == null) return "?";
    return s;
}

// --- the fetcher -------------------------------------------------------------

const result_body: u8 = 0;
const result_none: u8 = 1;
const result_failed: u8 = 2;

/// Why a try failed: after result_failed, a byte of this and a u16, an
/// errno (connect, io) or an HTTP status (token, status), else 0.
const Failure = enum(u8) {
    connect,
    io,
    timeout,
    too_long,
    malformed,
    token,
    status,
    not_google,
    request,
};

/// The fetcher's last failure, which it says when it gives up.
var failure: Failure = .timeout;
var failure_n: u16 = 0;

/// A failure, kept to say, and null: the caller tries again.
fn miss(comptime T: type, f: Failure, n: u16) ?T {
    failure = f;
    failure_n = n;
    return null;
}

/// As _cloud: ask the metadata server, and hand back what it said. Errors
/// are said to the parent only as a Failure and a number, which it maps
/// to words of its own: it trusts nothing from here.
fn fetcher(p: Provider, out: i32, parent_pid: linux.pid_t) noreturn {
    sandbox.tieTo(parent_pid);
    sandbox.dropTo(fetcher_id, empty_dir) catch linux.exit_group(1);
    // No file, and TCP to port 80 alone: fence's policy is not set yet.
    sandbox.landlock(&.{}, &.{80}) catch linux.exit_group(1);
    var f: sandbox.Filter = .{};
    // A stream socket, exactly as exchange makes one: TCP, never UDP, which
    // Landlock does not hold to a port.
    f.allowArg("socket", 1, socket_type);
    inline for (.{
        "connect",         "getsockopt", "write",         "read",      "poll",
        "ppoll",           "close",      "clock_gettime", "nanosleep", "clock_nanosleep",
        "restart_syscall", "exit_group", "exit",
    }) |call| f.allow(call);
    f.install() catch linux.exit_group(1);

    var buf: [max_response]u8 = undefined;
    const r = fetch(p, &buf);
    switch (r) {
        .body => |body| {
            writeAll(out, &.{result_body});
            writeAll(out, body);
        },
        .none => writeAll(out, &.{result_none}),
        .failed => {
            var said: [4]u8 = .{ result_failed, @backingInt(failure), 0, 0 };
            std.mem.writeInt(u16, said[2..4], failure_n, .big);
            writeAll(out, &said);
        },
    }
    linux.exit_group(0);
}

const Fetched = union(enum) { body: []const u8, none, failed };

/// The provider's user data, in four tries 1, 2 and 4 seconds apart, as the
/// metadata server may not answer the moment the network is up: at most 27
/// seconds, or 47 where a token is asked for first (5 an exchange).
fn fetch(p: Provider, buf: *[max_response]u8) Fetched {
    var wait: u32 = 1;
    var tries: u32 = 0;
    while (true) {
        if (fetchOnce(p, buf)) |r| return r;
        tries += 1;
        if (tries == 4) return .failed;
        _ = linux.nanosleep(&.{ .sec = wait, .nsec = 0 }, null);
        wait *= 2;
    }
}

/// A failure, kept to say: no trying again.
fn failedFor(f: Failure, n: u16) Fetched {
    _ = miss(Fetched, f, n);
    return .failed;
}

/// One attempt: null to try again.
fn fetchOnce(p: Provider, buf: *[max_response]u8) ?Fetched {
    var req: [512]u8 = undefined;
    var extra: []const u8 = p.header;
    var token_header: [256]u8 = undefined;
    if (p.token) {
        const resp = exchange(
            request(
                &req,
                "PUT",
                "/latest/api/token",
                "X-aws-ec2-metadata-token-ttl-seconds: 60",
            ) orelse return failedFor(.request, 0),
            buf,
        ) orelse return null;
        const r = parseResponse(resp) orelse return miss(Fetched, .malformed, 0);
        if (r.status != 200 or !validToken(r.body)) return miss(Fetched, .token, r.status);
        extra = std.mem.print(
            &token_header,
            "X-aws-ec2-metadata-token: {s}",
            .{r.body},
        ) catch return failedFor(.request, 0);
    }
    const resp = exchange(
        request(&req, "GET", p.path, extra) orelse return failedFor(.request, 0),
        buf,
    ) orelse return null;
    const r = parseResponse(resp) orelse return miss(Fetched, .malformed, 0);
    if (p.flavor and !r.google) return failedFor(.not_google, 0);
    return switch (r.status) {
        200 => if (r.body.len == 0) .none else .{ .body = r.body },
        404 => .none,
        else => miss(Fetched, .status, r.status),
    };
}

/// An HTTP/1.1 request that closes the connection after the response. The
/// path and header are ours, or a token checked by validToken: nothing in
/// them can end a line.
fn request(buf: []u8, method: []const u8, path: []const u8, header: []const u8) ?[]const u8 {
    for ([_][]const u8{ path, header }) |s| {
        for (s) |c| if (c < 0x20 or c > 0x7e) return null;
    }
    return std.mem.print(buf, "{s} {s} HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: " ++
        "close\r\nContent-Length: 0\r\n{s}{s}\r\n", .{
        method, path, header, if (header.len > 0) "\r\n" else "",
    }) catch null;
}

/// IMDSv2's tokens are base64-ish: anything else is not put in a header.
fn validToken(t: []const u8) bool {
    if (t.len == 0 or t.len > 200) return false;
    for (t) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '=' and
        c != '+' and c != '/') return false;
    return true;
}

/// The only socket the fetcher makes, and so the only one its filter allows.
const socket_type: u32 = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;

/// Send `req` to the metadata server and read its whole response, within
/// 5 seconds; null on any failure, kept to say (miss). The response ends where its length says,
/// or with its last chunk, or when the server closes.
fn exchange(req: []const u8, buf: *[max_response]u8) ?[]u8 {
    const deadline = nowMs() + 5_000;
    const rc = linux.socket(linux.AF.INET, socket_type, 0);
    if (linux.errno(rc) != .SUCCESS) return miss([]u8, .io, @backingInt(linux.errno(rc)));
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const addr: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, 80),
        .addr = @bitCast(metadata_ip),
    };
    const c = linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    if (linux.errno(c) != .SUCCESS and linux.errno(c) != .INPROGRESS)
        return miss([]u8, .connect, @backingInt(linux.errno(c)));
    if (!waitFor(fd, linux.POLL.OUT, deadline)) return miss([]u8, .timeout, 0);
    var err: i32 = 0;
    var len: linux.socklen_t = @sizeOf(i32);
    if (linux.errno(linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.ERROR,
        @ptrCast(&err),
        &len,
    )) != .SUCCESS or err != 0) return miss([]u8, .connect, @intCast(err));

    var off: usize = 0;
    while (off < req.len) {
        if (!waitFor(fd, linux.POLL.OUT, deadline)) return miss([]u8, .timeout, 0);
        const n = linux.write(fd, req[off..].ptr, req.len - off);
        if (linux.errno(n) == .AGAIN) continue;
        if (linux.errno(n) != .SUCCESS) return miss([]u8, .io, @backingInt(linux.errno(n)));
        off += n;
    }
    var got: usize = 0;
    while (true) {
        if (got == buf.len) return miss([]u8, .too_long, 0); // too long to be ours
        if (!waitFor(fd, linux.POLL.IN, deadline)) return miss([]u8, .timeout, 0);
        const n = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (linux.errno(n) == .AGAIN) continue;
        if (linux.errno(n) != .SUCCESS) return miss([]u8, .io, @backingInt(linux.errno(n)));
        if (n == 0) return buf[0..got];
        got += n;
        if (complete(buf[0..got])) return buf[0..got];
    }
}

/// Whether `resp` holds a whole response: its headers, and all of a body
/// whose last chunk has come or whose length is given, read as
/// parseResponse reads them, chunks first.
fn complete(resp: []const u8) bool {
    const end = std.mem.find(u8, resp, "\r\n\r\n") orelse return false;
    const h = parseHead(resp[0..end]) orelse return false;
    if (h.chunked) return std.mem.endsWith(u8, resp, "\r\n0\r\n\r\n");
    const l = h.length orelse return false;
    return resp.len - end - 4 >= l;
}

fn waitFor(fd: i32, events: i16, deadline: i64) bool {
    while (true) {
        const left = deadline - nowMs();
        if (left <= 0) return false;
        var fds = [1]linux.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        const n = linux.poll(&fds, 1, @intCast(left));
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return false;
        return true;
    }
}

const Response = struct { status: u16, body: []const u8, google: bool };

/// What werewolf reads of a response's head: its status, how its body
/// ends, and GCP's mark.
const Head = struct {
    status: u16,
    length: ?usize = null,
    chunked: bool = false,
    /// Metadata-Flavor: Google, as GCP's server says on every answer.
    google: bool = false,
};

/// An HTTP/1.x response's head, the status line and headers before the
/// blank line. Null for anything malformed, or a body encoded other than
/// in chunks.
fn parseHead(head: []const u8) ?Head {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return null;
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.") or status_line.len < 12 or
        status_line[8] != ' ' or (status_line.len > 12 and status_line[12] != ' ')) return null;
    var h: Head = .{ .status = std.math.cast(u16, digits(status_line[9..12], 10) orelse
        return null) orelse return null };
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse return null;
        const name = std.mem.trim(u8, line[0..colon], " ");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            h.length = digits(value, 10) orelse return null;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return null;
            h.chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "metadata-flavor")) {
            h.google = std.mem.eql(u8, value, "Google");
        }
    }
    return h;
}

/// An HTTP/1.x response: its status and body, the body decoded from
/// chunks, in place, or cut to Content-Length where the server says so.
/// Null for anything malformed.
fn parseResponse(resp: []u8) ?Response {
    const end = std.mem.find(u8, resp, "\r\n\r\n") orelse return null;
    const h = parseHead(resp[0..end]) orelse return null;
    const raw = resp[end + 4 ..];
    if (h.chunked) return .{
        .status = h.status,
        .body = dechunk(raw) orelse return null,
        .google = h.google,
    };
    const l = h.length orelse raw.len;
    if (l > raw.len) return null;
    return .{ .status = h.status, .body = raw[0..l], .google = h.google };
}

/// text as digits in base and nothing else: no sign and no _ between them,
/// which std.fmt.parseInt would take. Null for anything else, or too large.
fn digits(text: []const u8, base: u8) ?usize {
    if (text.len == 0) return null;
    var v: usize = 0;
    for (text) |c| {
        const d = std.fmt.charToDigit(c, base) catch return null;
        v = std.math.mul(usize, v, base) catch return null;
        v = std.math.add(usize, v, d) catch return null;
    }
    return v;
}

/// A chunked body, its chunks moved together in place: the decoded body is
/// never longer than the encoded one, and always behind it. Null if
/// malformed.
fn dechunk(body: []u8) ?[]const u8 {
    const out = body.ptr;
    var in: usize = 0;
    var n: usize = 0;
    while (true) {
        const eol = std.mem.findPos(u8, body, in, "\r\n") orelse return null;
        const size_text = std.mem.trim(u8, body[in..eol], " ");
        const semi = std.mem.findScalar(u8, size_text, ';') orelse size_text.len;
        const size = digits(size_text[0..semi], 16) orelse return null;
        in = eol + 2;
        if (size == 0) return out[0..n];
        if (size > body.len - in or body.len - in - size < 2) return null;
        @memmove(out[n .. n + size], body[in .. in + size]);
        n += size;
        in += size;
        if (!std.mem.eql(u8, body[in .. in + 2], "\r\n")) return null;
        in += 2;
    }
}

// --- the parent's checks -----------------------------------------------------

/// Standard base64, whitespace allowed between characters; null if it is
/// not, or decodes to more than `out` holds.
fn decodeBase64(text: []const u8, out: *[max_config]u8) ?[]const u8 {
    var clean: [max_response]u8 = undefined;
    var n: usize = 0;
    for (text) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        if (n == clean.len) return null;
        clean[n] = c;
        n += 1;
    }
    const d = std.base64.standard.Decoder;
    const size = d.calcSizeForSlice(clean[0..n]) catch return null;
    if (size == 0 or size > out.len) return null;
    d.decode(out[0..size], clean[0..n]) catch return null;
    return out[0..size];
}

const Entry = struct {
    /// ustar's name field holds 100 bytes, and only names that fit pass.
    name_buf: [100]u8,
    name_len: u8,
    dir: bool,
    /// The file's contents, within the tar checked.
    data: []const u8,

    fn name(e: *const Entry) []const u8 {
        return e.name_buf[0..e.name_len];
    }
};

/// Check a tar entry by entry. Only regular files and directories pass,
/// under names of letters, digits and . _ - /, relative, without . or ..
/// components, each at most 32 KiB, at most 32 of them, and no name twice
/// or beneath a file. A POSIX ustar or a
/// GNU tar, as tar and bsdtar write them. pax headers, which macOS's tar
/// adds for extended attributes, are skipped and never applied: what they
/// say about the next entry is ignored, since the tar init extracts is
/// written anew from the plain fields alone.
fn checkTar(tar: []const u8, out: *[max_entries]Entry) !usize {
    var n: usize = 0;
    var off: usize = 0;
    var total: usize = 0;
    while (true) {
        if (off + 512 > tar.len) return error.Truncated;
        const h = tar[off..][0..512];
        if (std.mem.allEqual(u8, h, 0)) return n; // the end
        if (!checksumOk(h)) return error.BadChecksum;
        const posix = std.mem.eql(u8, h[257..263], "ustar\x00") and
            std.mem.eql(u8, h[263..265], "00");
        const gnu = std.mem.eql(u8, h[257..265], "ustar  \x00");
        if (!posix and !gnu) return error.NotUstar;
        const dir = switch (h[156]) {
            '0', 0 => false,
            '5' => true,
            'x', 'g' => {
                const size = octal(h[124..136]) orelse return error.BadSize;
                if (size > max_file) return error.FileTooLarge;
                const blocks = (size + 511) / 512;
                if (blocks * 512 > tar.len - off - 512) return error.Truncated;
                off += 512 + blocks * 512;
                continue;
            },
            else => return error.NotAFileOrDirectory,
        };
        // The name, with ustar's prefix where there is one.
        var name_buf: [256]u8 = undefined;
        const short = std.mem.sliceTo(h[0..100], 0);
        const prefix = if (posix) std.mem.sliceTo(h[345..500], 0) else "";
        const full = if (prefix.len == 0)
            short
        else
            std.mem.print(&name_buf, "{s}/{s}", .{ prefix, short }) catch return error.BadName;
        const size = octal(h[124..136]) orelse return error.BadSize;
        if (dir and size != 0) return error.BadSize;
        if (size > max_file) return error.FileTooLarge;
        total += size;
        if (total > max_config) return error.FileTooLarge;
        const blocks = (size + 511) / 512;
        if (blocks * 512 > tar.len - off - 512) return error.Truncated;
        off += 512;
        const name = cleanName(full) orelse return error.BadName;
        if (name.len > 100) return error.BadName;
        if (name.len > 0) {
            if (n == max_entries) return error.TooManyEntries;
            // The same name twice, a name beneath a file, or a file above a
            // name: a config that says two things is refused, not settled by
            // whichever init meets last.
            for (out[0..n]) |*e| {
                if (std.mem.eql(u8, e.name(), name) or (!e.dir and beneath(name, e.name())) or
                    (!dir and beneath(e.name(), name))) return error.NameClash;
            }
            out[n] = .{
                .name_buf = undefined,
                .name_len = @intCast(name.len),
                .dir = dir,
                .data = tar[off..][0..size],
            };
            @memcpy(out[n].name_buf[0..name.len], name);
            n += 1;
        }
        off += blocks * 512;
    }
}

/// Whether path lies beneath the directory parent.
fn beneath(path: []const u8, parent: []const u8) bool {
    return path.len > parent.len and std.mem.startsWith(u8, path, parent) and
        path[parent.len] == '/';
}

/// A name werewolf will extract, without a leading ./ or a trailing /: ""
/// for the archive's own root, null for anything else.
fn cleanName(raw: []const u8) ?[]const u8 {
    var name = raw;
    while (std.mem.startsWith(u8, name, "./")) name = name[2..];
    while (name.len > 0 and name[name.len - 1] == '/') name = name[0 .. name.len - 1];
    if (name.len == 0 or std.mem.eql(u8, name, ".")) return "";
    if (name[0] == '/') return null;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '_' and c != '-' and
        c != '/') return null;
    var parts = std.mem.splitScalar(u8, name, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return null;
    }
    return name;
}

fn octal(field: []const u8) ?usize {
    const t = std.mem.trim(u8, std.mem.sliceTo(field, 0), " ");
    if (t.len == 0) return 0;
    return digits(t, 8);
}

fn checksumOk(h: *const [512]u8) bool {
    const want = octal(h[148..156]) orelse return false;
    var sum: usize = 0;
    for (h, 0..) |b, i| sum += if (i >= 148 and i < 156) ' ' else b;
    return sum == want;
}

/// A new tar of the entries checked: POSIX ustar, every entry owned by
/// root, files 0600 and directories 0700, dated 1970, then the end.
fn writeTar(out: []u8, entries: []const Entry) []const u8 {
    var off: usize = 0;
    for (entries) |*e| {
        const h = out[off..][0..512];
        @memset(h, 0);
        @memcpy(h[0..e.name_len], e.name());
        _ = std.mem.print(
            h[100..108],
            "{o:0>7}\x00",
            .{@as(u32, if (e.dir) 0o700 else 0o600)},
        ) catch unreachable;
        _ = std.mem.print(h[108..116], "0000000\x00", .{}) catch unreachable;
        _ = std.mem.print(h[116..124], "0000000\x00", .{}) catch unreachable;
        _ = std.mem.print(
            h[124..136],
            "{o:0>11}\x00",
            .{if (e.dir) 0 else e.data.len},
        ) catch unreachable;
        _ = std.mem.print(h[136..148], "00000000000\x00", .{}) catch unreachable;
        h[156] = if (e.dir) '5' else '0';
        @memcpy(h[257..265], "ustar\x0000");
        var sum: usize = 0;
        @memset(h[148..156], ' ');
        for (h) |b| sum += b;
        _ = std.mem.print(h[148..156], "{o:0>6}\x00 ", .{sum}) catch unreachable;
        off += 512;
        if (!e.dir) {
            @memcpy(out[off..][0..e.data.len], e.data);
            const padded = (e.data.len + 511) / 512 * 512;
            @memset(out[off + e.data.len .. off + padded], 0);
            off += padded;
        }
    }
    @memset(out[off..][0..1024], 0);
    return out[0 .. off + 1024];
}

// --- sandboxes ---------------------------------------------------------------

/// The parent: no capabilities, never to gain any, writing only in
/// /run/werewolf/cloud, and any system call beyond these fatal.
fn sandboxParent(dir: i32, in: i32) !void {
    try sandbox.keepOnly(0);
    try sandbox.landlock(&.{.{ .fd = dir, .access = sandbox.own_files }}, &.{});
    var f: sandbox.Filter = .{};
    f.allowArg("read", 0, @intCast(in));
    inline for (.{
        "write",         "openat",          "close",      "renameat", "renameat2",
        "clock_gettime", "restart_syscall", "exit_group", "exit",
    }) |call| f.allow(call);
    try f.install();
}

// --- files, pipes, time, logging ----------------------------------------------

/// Write a file whole beneath `dir`: to a new name, then renamed over the old.
fn writeFile(dir: i32, comptime name: [:0]const u8, data: []const u8) !void {
    const tmp = std.fmt.comptimePrint("{s}.new", .{name});
    const fd = try sys(
        linux.openat(
            dir,
            tmp,
            .{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .TRUNC = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            },
            0o600,
        ),
        "open " ++ name,
    );
    defer _ = linux.close(@intCast(fd));
    var off: usize = 0;
    while (off < data.len) off += try sys(
        linux.write(@intCast(fd), data[off..].ptr, data.len - off),
        "write " ++ name,
    );
    _ = try sys(linux.renameat(dir, tmp, dir, name), "rename " ++ name);
}

/// Everything from `fd` until it closes; an error if more than fits.
fn readAll(fd: i32, buf: []u8) ![]const u8 {
    var got: usize = 0;
    while (true) {
        if (got == buf.len) return error.TooMuch;
        const n = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (linux.errno(n) == .INTR) continue;
        _ = try sys(n, "read from the fetcher");
        if (n == 0) return buf[0..got];
        got += n;
    }
}

fn writeAll(fd: i32, data: []const u8) void {
    var off: usize = 0;
    while (off < data.len) {
        const n = linux.write(fd, data[off..].ptr, data.len - off);
        if (linux.errno(n) != .SUCCESS) linux.exit_group(1);
        off += n;
    }
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.BOOTTIME, &ts);
    return ts.sec * 1000 + @divFloor(ts.nsec, std.time.ns_per_ms);
}

/// JSON lines on stdout: `cloud-metadata: {"time":...,"event":...,...}`, built in a
/// fixed buffer.
const Log = struct {
    buf: [8 << 10]u8 = undefined,

    fn event(l: *Log, name: []const u8, fields: anytype) void {
        var w: Io.Writer = .fixed(&l.buf);
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &ts);
        var time: [20]u8 = undefined;
        w.print(
            "cloud-metadata: {{\"time\":\"{s}\",\"event\":\"{s}\",",
            .{ rfc3339(&time, @intCast(ts.sec)), name },
        ) catch return;
        const mark = w.end;
        std.json.Stringify.value(fields, .{}, &w) catch return;
        @memmove(l.buf[mark .. w.end - 1], l.buf[mark + 1 .. w.end]);
        w.end -= 1;
        w.writeByte('\n') catch return;
        _ = linux.write(1, w.buffered().ptr, w.buffered().len);
    }
};

fn rfc3339(buf: *[20]u8, secs: u64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.mem.print(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

// --- tests -------------------------------------------------------------------

/// A tar as tar(1) would write one: `entries` of name, typeflag, contents.
fn testTar(buf: []u8, entries: []const struct { []const u8, u8, []const u8 }) []const u8 {
    var off: usize = 0;
    for (entries) |e| {
        const h = buf[off..][0..512];
        @memset(h, 0);
        @memcpy(h[0..e[0].len], e[0]);
        _ = std.mem.print(h[100..108], "0000644\x00", .{}) catch unreachable;
        _ = std.mem.print(
            h[108..116],
            "0000765\x00",
            .{},
        ) catch unreachable; // the builder's uid
        _ = std.mem.print(h[116..124], "0000024\x00", .{}) catch unreachable;
        _ = std.mem.print(h[124..136], "{o:0>11}\x00", .{e[2].len}) catch unreachable;
        _ = std.mem.print(h[136..148], "15052301457\x00", .{}) catch unreachable;
        h[156] = e[1];
        @memcpy(h[257..265], "ustar\x0000");
        @memset(h[148..156], ' ');
        var sum: usize = 0;
        for (h) |b| sum += b;
        _ = std.mem.print(h[148..156], "{o:0>6}\x00 ", .{sum}) catch unreachable;
        off += 512;
        @memcpy(buf[off..][0..e[2].len], e[2]);
        const padded = (e[2].len + 511) / 512 * 512;
        @memset(buf[off + e[2].len .. off + padded], 0);
        off += padded;
    }
    @memset(buf[off..][0..1024], 0);
    return buf[0 .. off + 1024];
}

const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0wmN/Cr3JXqmLW7u+g9pTh+wyqqkgOEH7fJiXfj0lJ " ++
    "root@laptop\n";

test "a config as tar -C config . writes it" {
    var buf: [8192]u8 = undefined;
    const tar = testTar(
        &buf,
        &.{
            .{ "./", '5', "" },
            .{ "./authorized_keys", '0', key },
            .{ "./hostname", '0', "web-1\n" },
            .{ "./cloudflared/", '5', "" },
            .{ "./cloudflared/token", '0', "eyJh" },
        },
    );
    var files: [max_entries]Entry = undefined;
    const n = try checkTar(tar, &files);
    try std.testing.expectEqual(4, n);
    try std.testing.expectEqualStrings("authorized_keys", files[0].name());
    try std.testing.expectEqualStrings(key, files[0].data);
    try std.testing.expectEqualStrings("cloudflared", files[2].name());
    try std.testing.expect(files[2].dir);

    // Written again, owned by root: and it checks the same.
    var out: [16384]u8 = undefined;
    const again = writeTar(&out, files[0..n]);
    var files2: [max_entries]Entry = undefined;
    try std.testing.expectEqual(4, try checkTar(again, &files2));
    try std.testing.expectEqualStrings("0000000\x00", again[108..116]);
    try std.testing.expectEqualStrings("0000600\x00", again[100..108]);
    try std.testing.expectEqualStrings(key, files2[0].data);
}

test "pax headers, as macOS's tar writes, are skipped" {
    var buf: [8192]u8 = undefined;
    const tar = testTar(
        &buf,
        &.{
            .{ "./PaxHeader/hostname", 'x', "30 path=../../etc/shadow\n" },
            .{ "./hostname", '0', "web-1\n" },
        },
    );
    var files: [max_entries]Entry = undefined;
    try std.testing.expectEqual(1, try checkTar(tar, &files));
    try std.testing.expectEqualStrings("hostname", files[0].name());
}

test "entries that are refused" {
    var buf: [8192]u8 = undefined;
    var files: [max_entries]Entry = undefined;
    const cases = .{
        .{ "../etc/passwd", '0', error.BadName },
        .{ "/etc/passwd", '0', error.BadName },
        .{ "a/../../b", '0', error.BadName },
        .{ "keys;rm", '0', error.BadName },
        .{ "link", '2', error.NotAFileOrDirectory },
        .{ "hard", '1', error.NotAFileOrDirectory },
        .{ "dev", '3', error.NotAFileOrDirectory },
        .{ "././@LongLink", 'L', error.NotAFileOrDirectory },
    };
    inline for (cases) |c| {
        try std.testing.expectError(
            c[2],
            checkTar(testTar(&buf, &.{.{ c[0], c[1], "x" }}), &files),
        );
    }
    // The same name twice, a name beneath a file, a file above a name.
    const clashes = .{
        .{ .{ "hostname", '0', "a" }, .{ "hostname", '0', "b" } },
        .{ .{ "keys", '0', "a" }, .{ "keys/x", '0', "b" } },
        .{ .{ "keys/x", '0', "a" }, .{ "keys", '0', "b" } },
        .{ .{ "d/", '5', "" }, .{ "d", '5', "" } },
    };
    inline for (clashes) |c| {
        try std.testing.expectError(
            error.NameClash,
            checkTar(testTar(&buf, &.{ c[0], c[1] }), &files),
        );
    }
    // A directory, then what is in it, passes.
    try std.testing.expectEqual(2, try checkTar(
        testTar(&buf, &.{ .{ "d/", '5', "" }, .{ "d/x", '0', "a" } }),
        &files,
    ));
    // A bad checksum, a truncated archive, and a file larger than allowed.
    var tar = testTar(&buf, &.{.{ "hostname", '0', "web-1\n" }});
    var bad: [8192]u8 = undefined;
    @memcpy(bad[0..tar.len], tar);
    bad[0] = 'H';
    try std.testing.expectError(error.BadChecksum, checkTar(bad[0..tar.len], &files));
    try std.testing.expectError(error.Truncated, checkTar(tar[0..600], &files));
    var big: [max_file + 2048]u8 = undefined;
    var huge: [max_file + 1]u8 = @splat('a');
    tar = testTar(&big, &.{.{ "big", '0', &huge }});
    try std.testing.expectError(error.FileTooLarge, checkTar(tar, &files));
}

test "base64" {
    var out: [max_config]u8 = undefined;
    try std.testing.expectEqualStrings("hello", decodeBase64("aGVs\nbG8=\n", &out).?);
    try std.testing.expectEqual(null, decodeBase64("#cloud-config\nusers: []\n", &out));
    try std.testing.expectEqual(null, decodeBase64("", &out));
}

/// parseResponse of a literal, through a copy it may rewrite.
fn parseText(comptime text: []const u8) ?Response {
    const S = struct {
        var buf: [text.len]u8 = text[0..text.len].*;
    };
    return parseResponse(&S.buf);
}

test "HTTP responses" {
    var r = parseText(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhelloEXTRA",
    ).?;
    try std.testing.expectEqual(200, r.status);
    try std.testing.expectEqualStrings("hello", r.body);
    r = parseText("HTTP/1.0 404 Not Found\r\n\r\n").?;
    try std.testing.expectEqual(404, r.status);
    // Without a length, the body runs to the close.
    try std.testing.expectEqualStrings(
        "token",
        parseText("HTTP/1.1 200 OK\r\nServer: EC2ws\r\n\r\ntoken").?.body,
    );

    var chunked = ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwere\r\n4;x=y\r\nw" ++
        "olf\r\n0\r\n\r\n").*;
    try std.testing.expectEqualStrings("werewolf", parseResponse(&chunked).?.body);

    try std.testing.expectEqual(
        null,
        parseText("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort"),
    );
    try std.testing.expectEqual(null, parseText("HTTP/1.1 200 OK\r\nno colon here\r\n\r\n"));
    try std.testing.expectEqual(null, parseText("SSH-2.0-OpenSSH\r\n\r\n"));
    try std.testing.expectEqual(
        null,
        parseText("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nx"),
    );
    // Numbers are digits alone: no sign, no _ between them.
    try std.testing.expectEqual(
        null,
        parseText("HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello"),
    );
    try std.testing.expectEqual(
        null,
        parseText("HTTP/1.1 200 OK\r\nContent-Length: 0_5\r\n\r\nhello"),
    );
    try std.testing.expectEqual(null, parseText("HTTP/1.1 +20 OK\r\n\r\n"));
    try std.testing.expectEqual(
        null,
        parseText("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+4\r\nwere\r\n0\r\n\r\n"),
    );
    // GCP's mark, and its absence.
    try std.testing.expect(
        parseText("HTTP/1.1 200 OK\r\nMetadata-Flavor: Google\r\n\r\nx").?.google,
    );
    try std.testing.expect(!parseText("HTTP/1.1 200 OK\r\n\r\nx").?.google);

    var bad_chunk = ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffff\r\nshort\r\n0\r" ++
        "\n\r\n").*;
    try std.testing.expectEqual(null, parseResponse(&bad_chunk));
}

test "a response is whole when its length or last chunk says so" {
    try std.testing.expect(!complete("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"));
    try std.testing.expect(complete("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
    try std.testing.expect(
        !complete("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwere\r\n"),
    );
    try std.testing.expect(
        complete("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwere\r\n0\r\n\r\n"),
    );
    try std.testing.expect(!complete("HTTP/1.1 200 OK\r\n\r\nuntil the close"));
    // Both: the chunks rule, whichever header comes first.
    try std.testing.expect(!complete(
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n",
    ));
}

test "requests carry no smuggled lines" {
    var buf: [512]u8 = undefined;
    const r = request(
        &buf,
        "GET",
        "/computeMetadata/v1/instance/attributes/user-data",
        "Metadata-Flavor: Google",
    ).?;
    try std.testing.expect(std.mem.endsWith(u8, r, "Metadata-Flavor: Google\r\n\r\n"));
    try std.testing.expectEqual(
        null,
        request(&buf, "GET", "/x", "X-aws-ec2-metadata-token: a\r\nEvil: 1"),
    );
    try std.testing.expect(validToken("AQAEAOfVfS3tA0Ys4Q_XprM-HDQ=="));
    try std.testing.expect(!validToken("abc\r\nEvil: 1"));
    try std.testing.expect(!validToken(""));
}

test "clouds by their firmware's names" {
    const azure_tag = "7783-7084-3265-9085-8269-3286-77";
    try std.testing.expectEqualStrings(
        "gcp",
        identify("Google", "Google Compute Engine", "").?.name,
    );
    try std.testing.expectEqualStrings("aws", identify("Amazon EC2", "m7g.large", "").?.name);
    try std.testing.expectEqualStrings("hetzner", identify("Hetzner", "vServer", "").?.name);
    try std.testing.expectEqualStrings(
        "azure",
        identify("Microsoft Corporation", "Virtual Machine", azure_tag).?.name,
    );
    try std.testing.expectEqual(null, identify("QEMU", "Standard PC (Q35 + ICH9, 2009)", ""));
    try std.testing.expectEqual(null, identify("Google", "Pixel", ""));
    // Hyper-V on a desktop: Azure's names, without Azure's asset tag.
    try std.testing.expectEqual(null, identify("Microsoft Corporation", "Virtual Machine", "None"));
    try std.testing.expectEqualStrings("?", printable("Evil\"vendor"));
}

test "fuzz: responses and tars" {
    try std.testing.fuzz({}, fuzzInput, .{});
}

fn fuzzInput(_: void, smith: *std.testing.Smith) anyerror!void {
    var in: [4096]u8 = undefined;
    const n = smith.slice(&in);
    _ = parseResponse(in[0..n]);
    var files: [max_entries]Entry = undefined;
    if (checkTar(in[0..n], &files)) |count| {
        var out: [max_config + (max_entries + 2) * 512]u8 = undefined;
        _ = writeTar(&out, files[0..count]);
    } else |_| {}
    var raw: [max_config]u8 = undefined;
    _ = decodeBase64(in[0..n], &raw);
}

test failureText {
    var buf: [96]u8 = undefined;
    try std.testing.expectEqualStrings(
        "connecting to 169.254.169.254:80: CONNREFUSED",
        failureText(&buf, &.{ result_failed, @backingInt(Failure.connect), 0, 111 }),
    );
    try std.testing.expectEqualStrings(
        "the user data: HTTP 403",
        failureText(&buf, &.{ result_failed, @backingInt(Failure.status), 1, 147 }),
    );
    try std.testing.expectEqualStrings(
        "the fetcher said nonsense",
        failureText(&buf, &.{ result_failed, 200, 0, 0 }),
    );
    try std.testing.expectEqualStrings(
        "the fetcher failed and said no more",
        failureText(&buf, &.{result_failed}),
    );
}
