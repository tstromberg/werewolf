//! cloud-metadata fetches werewolf's config tar from a cloud's metadata server
//! and leaves a checked copy for init in /run/werewolf/cloud/config.tar.
//! See README.md.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const sandbox = @import("sandbox");
const settings = @import("settings");
const people = @import("people");
const sys = sandbox.sys;

const out_dir = "/run/werewolf/cloud";
const empty_dir = "/var/empty";
/// fetcher_id is the _cloud account in forms/prod/form.yaml.
const fetcher_id: u32 = 68;
const metadata_ip = [4]u8{ 169, 254, 169, 254 };

const max_response = 128 << 10;
const max_config = 48 << 10;
const max_file = 32 << 10;
const max_entries = 32;

/// Provider is a cloud werewolf knows: how its firmware names it, and where
/// it keeps an instance's user data.
const Provider = struct {
    name: []const u8,
    /// vendor must equal DMI sys_vendor.
    vendor: []const u8,
    /// product must equal DMI product_name, when the vendor is not enough.
    product: ?[]const u8 = null,
    /// asset must equal DMI chassis_asset_tag, when the product is not enough.
    asset: ?[]const u8 = null,
    path: []const u8,
    /// header is one extra request header the server requires, if any.
    header: []const u8 = "",
    /// token asks for an IMDSv2 session token with a PUT before the GET (AWS).
    token: bool = false,
    /// flavor refuses an answer without `Metadata-Flavor: Google`, which GCP's
    /// server always sends; anything else is an impostor.
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
    // Desktop Hyper-V uses Azure's vendor and product; only Azure sets
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
    // Disable Speculative Store Bypass for this process and its children.
    // werewolf leaves this to each program so workloads do not pay for it
    // (docs/security.md). On a CPU without the control, the call just fails.
    _ = linux.prctl(
        @backingInt(linux.PR.SET_SPECULATION_CTRL),
        linux.PR.SPEC_STORE_BYPASS,
        linux.PR.SPEC_FORCE_DISABLE,
        0,
        0,
    );
    var log: Log = .{};
    // `once`, as init runs it at boot: fetch, check, write, exit. With no
    // argument it is the cloud-metadata service, which polls (poll).
    const args = init.minimal.args.toSlice(std.heap.page_allocator) catch &.{};
    if (args.len < 2 or !std.mem.eql(u8, args[1], "once")) poll(&log);
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
    // Exit directly: the runtime's cleanup makes system calls the seccomp
    // filter would kill the process for.
    linux.exit_group(0);
}

/// poll_every is how often the service asks the metadata server again.
const poll_every: u32 = 60;

/// poll is the cloud-metadata service: on a machine whose config came from
/// the cloud at boot, every poll_every seconds it fetches the user data
/// again, as `once` does, in a child confined as that is, and when the
/// config has changed writes it and makes its people's accounts anew
/// (lib/people.zig): the account files, each person's keys and home, an
/// admin's keys in root's, the gone removed. Elsewhere it stays down. It
/// holds CAP_CHOWN, for the homes, and what its children spend becoming
/// _cloud in /var/empty; Landlock lets it write only
/// the cloud's directory, the account and keys files and /data/home, and
/// read root's keys from the config; no seccomp filter, since its children
/// must install their own and a filter only ever narrows.
fn poll(log: *Log) noreturn {
    const gpa = std.heap.page_allocator;
    if (linux.faccessat(linux.AT.FDCWD, out_dir ++ "/config.tar", linux.F_OK, 0) != 0)
        park(log, "no config came from the cloud at boot, staying down");
    _ = linux.mkdirat(linux.AT.FDCWD, "/data/home", 0o755);
    const cloud = openDir(out_dir) catch park(log, "cannot open " ++ out_dir);
    const run_dir = openDir("/run/werewolf") catch park(log, "cannot open /run/werewolf");
    const keys_dir = openDir("/run/werewolf/keys") catch park(
        log,
        "cannot open /run/werewolf/keys",
    );
    const home_dir = openDir("/data/home") catch park(log, "cannot open /data/home");
    const config_dir = openDir("/run/config") catch park(log, "cannot open /run/config");
    // /sys/class/dmi/id is a link to this directory, which Landlock rules on.
    const dmi_dir = openDir("/sys/devices/virtual/dmi/id") catch park(
        log,
        "cannot open the DMI directory",
    );
    // CAP_CHOWN for the homes, and what each round's child spends on its
    // fetcher: CAP_SETGID and CAP_SETUID to become _cloud, CAP_SYS_CHROOT
    // for /var/empty (lib/sandbox.zig dropTo). The child keeps none after.
    // CAP_SETPCAP too, which the child spends dropping its own (keepOnly).
    const chown: u32 = 1 << 0;
    const setgid: u32 = 1 << 6;
    const setuid: u32 = 1 << 7;
    const setpcap: u32 = 1 << 8;
    const sys_chroot: u32 = 1 << 18;
    sandbox.keepOnly(chown | setgid | setuid | setpcap | sys_chroot) catch
        park(log, "cannot drop capabilities");
    // What the children inherit: once's child identifies the cloud by DMI
    // and writes the cloud's directory, and its fetcher connects to port 80.
    sandbox.landlock(&.{
        .{ .fd = cloud, .access = sandbox.own_files },
        .{ .fd = run_dir, .access = sandbox.own_files },
        .{ .fd = keys_dir, .access = sandbox.own_files },
        .{ .fd = home_dir, .access = sandbox.make_dir | sandbox.read_dir },
        .{ .fd = config_dir, .access = sandbox.read_file },
        .{ .fd = dmi_dir, .access = sandbox.read_file },
    }, &.{80}) catch park(log, "cannot confine the service");
    var last = readFrom(gpa, cloud, "config.tar") catch "";
    log.event(
        "poll",
        .{ .every = poll_every, .people = countLines(readFrom(gpa, run_dir, "people") catch "") },
    );
    while (true) {
        var ts: linux.timespec = .{ .sec = poll_every, .nsec = 0 };
        _ = linux.nanosleep(&ts, null);
        const pid = linux.fork();
        if (pid == 0) {
            run(log) catch |err| {
                log.event("error", .{ .step = step, .@"error" = @errorName(err) });
                linux.exit_group(1);
            };
            linux.exit_group(0);
        }
        var status: i32 = 0;
        _ = linux.wait4(@intCast(pid), &status, 0, null);
        const now = readFrom(gpa, cloud, "config.tar") catch continue;
        if (std.mem.eql(u8, now, last)) {
            gpa.free(now);
            continue;
        }
        if (last.len > 0) gpa.free(last);
        last = now;
        apply(gpa, log, now, run_dir, keys_dir, home_dir, config_dir);
    }
}

/// apply makes the people of a changed config their accounts, as init did
/// at boot, and logs what changed.
fn apply(
    gpa: std.mem.Allocator,
    log: *Log,
    tar: []const u8,
    run_dir: i32,
    keys_dir: i32,
    home_dir: i32,
    config_dir: i32,
) void {
    var files: [max_entries]Entry = undefined;
    const n = checkTar(
        tar,
        &files,
    ) catch |err| return log.event("refused", .{ .reason = @errorName(err) });
    var text: []const u8 = "";
    for (files[0..n]) |*f| if (std.mem.eql(u8, f.name(), "users")) {
        text = f.data;
    };
    const shell: []const u8 = if (linux.faccessat(linux.AT.FDCWD, "/bin/ash", linux.X_OK, 0) == 0)
        "/bin/ash"
    else
        "/sbin/nologin";
    const c = people.apply(gpa, .{
        .passwd = readFrom(gpa, run_dir, "passwd") catch "",
        .group = readFrom(gpa, run_dir, "group") catch "",
        .shadow = readFrom(gpa, run_dir, "shadow") catch "",
        .made = readFrom(gpa, run_dir, "people") catch "",
    }, text, shell) catch return log.event(
        "error",
        .{ .step = "people", .@"error" = "OutOfMemory" },
    );
    putFile(
        run_dir,
        "passwd",
        c.passwd,
        0o644,
    ) catch return log.event("error", .{ .step = "passwd" });
    putFile(run_dir, "group", c.group, 0o644) catch return log.event("error", .{ .step = "group" });
    putFile(
        run_dir,
        "shadow",
        c.shadow,
        0o600,
    ) catch return log.event("error", .{ .step = "shadow" });
    putFile(
        run_dir,
        "people",
        c.made,
        0o600,
    ) catch return log.event("error", .{ .step = "people" });
    for (c.removed) |name| _ = linux.unlinkat(keys_dir, nameZ(name), 0);
    for (c.keys) |k| {
        const name = nameZ(k.name);
        putFile(keys_dir, name, k.text, 0o600) catch continue;
        const id = people.userId(k.name);
        _ = linux.fchownat(keys_dir, name, id, id, 0);
        _ = linux.mkdirat(home_dir, name, 0o700);
        _ = linux.fchownat(home_dir, name, id, id, 0);
        _ = linux.fchmodat(home_dir, name, 0o700);
    }
    const base = readFrom(gpa, config_dir, "authorized_keys") catch "";
    const root_keys = std.mem.concat(gpa, u8, &.{ base, c.root_keys }) catch return;
    putFile(
        keys_dir,
        "root",
        root_keys,
        0o600,
    ) catch return log.event("error", .{ .step = "root keys" });
    log.event("people", .{
        .made = countLines(c.made),
        .removed = c.removed.len,
        .refused = c.refused,
    });
}

/// park says why and marks the service down, so runsv does not start it again.
fn park(log: *Log, why: []const u8) noreturn {
    log.event("down", .{ .reason = why });
    const argv = [_:null]?[*:0]const u8{ "/usr/bin/sv", "down", "." };
    const envp = [_:null]?[*:0]const u8{};
    _ = linux.execve("/usr/bin/sv", &argv, &envp);
    linux.exit_group(1);
}

fn openDir(path: [*:0]const u8) !i32 {
    return @intCast(try sys(linux.openat(
        linux.AT.FDCWD,
        path,
        .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true },
        0,
    ), "open directory"));
}

/// readFrom reads the file name under dir, at most max_file bytes.
fn readFrom(gpa: std.mem.Allocator, dir: i32, name: [*:0]const u8) ![]u8 {
    const fd: i32 = @intCast(try sys(
        linux.openat(dir, name, .{ .CLOEXEC = true, .NOFOLLOW = true }, 0),
        "open",
    ));
    defer _ = linux.close(fd);
    const buf = try gpa.alloc(u8, max_file);
    errdefer gpa.free(buf);
    var n: usize = 0;
    while (n < buf.len) {
        const got = try sys(linux.read(fd, buf[n..].ptr, buf.len - n), "read");
        if (got == 0) break;
        n += got;
    }
    return buf[0..n];
}

/// putFile writes data to name.new under dir, mode as given, and renames it
/// over name, so a reader never sees a partial file.
fn putFile(dir: i32, name: [*:0]const u8, data: []const u8, mode: u32) !void {
    var tmp_buf: [64]u8 = undefined;
    const n = std.mem.len(name);
    if (n + 5 > tmp_buf.len) return error.NameTooLong;
    @memcpy(tmp_buf[0..n], name[0..n]);
    @memcpy(tmp_buf[n .. n + 4], ".new");
    tmp_buf[n + 4] = 0;
    const tmp: [*:0]const u8 = tmp_buf[0 .. n + 4 :0];
    const fd: i32 = @intCast(try sys(linux.openat(
        dir,
        tmp,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .NOFOLLOW = true },
        mode,
    ), "create"));
    writeAll(fd, data);
    _ = linux.fchmod(fd, mode);
    _ = linux.close(fd);
    _ = try sys(linux.renameat(dir, tmp, dir, name), "rename");
}

/// nameZ returns name as a C string, in a buffer that holds a person's name.
fn nameZ(name: []const u8) [*:0]const u8 {
    const S = struct {
        var buf: [40]u8 = undefined;
    };
    const n = @min(name.len, S.buf.len - 1);
    @memcpy(S.buf[0..n], name[0..n]);
    S.buf[n] = 0;
    return S.buf[0..n :0];
}

fn countLines(text: []const u8) usize {
    var n: usize = 0;
    for (text) |c| if (c == '\n') {
        n += 1;
    };
    return n;
}

/// step names the stage that failed, for the error event.
var step: []const u8 = "start";

/// why_buf holds why the fetcher's last try failed, for the error event.
var why_buf: [96]u8 = undefined;

/// failureText puts the fetcher's failure message, a kind byte and a number,
/// into the parent's own words. No text from the fetcher reaches the log,
/// since a compromised fetcher could write anything.
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

/// run identifies the cloud as root, then forks the fetcher and checks
/// what it returns.
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

/// dmi returns the trimmed DMI string at path, or "" if the firmware has none.
fn dmi(path: [*:0]const u8, buf: *[128]u8) []const u8 {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return "";
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const n = linux.read(fd, buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return "";
    return std.mem.trim(u8, buf[0..n], " \n\t");
}

/// printable returns s if it holds only letters, digits and a little
/// punctuation, else "?", so odd firmware strings never reach the log.
fn printable(s: []const u8) []const u8 {
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and
        std.mem.findScalar(u8, " .-_()", c) == null) return "?";
    return s;
}

// --- the fetcher -------------------------------------------------------------

const result_body: u8 = 0;
const result_none: u8 = 1;
const result_failed: u8 = 2;

/// Failure says why a try failed. The fetcher sends result_failed, a Failure
/// byte and a u16: an errno (connect, io), an HTTP status (token, status),
/// or 0.
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

/// failure and failure_n hold the fetcher's last failure, sent when it gives up.
var failure: Failure = .timeout;
var failure_n: u16 = 0;

/// miss records a failure and returns null, so the caller tries again.
fn miss(comptime T: type, f: Failure, n: u16) ?T {
    failure = f;
    failure_n = n;
    return null;
}

/// fetcher drops to _cloud, asks the metadata server, and writes the result
/// to out. It reports errors only as a Failure and a number, since the
/// parent trusts no text from here.
fn fetcher(p: Provider, out: i32, parent_pid: linux.pid_t) noreturn {
    sandbox.tieTo(parent_pid);
    sandbox.dropTo(fetcher_id, empty_dir) catch linux.exit_group(1);
    // Allow no files and only TCP to port 80: fence's policy is not set yet.
    sandbox.landlock(&.{}, &.{80}) catch linux.exit_group(1);
    var f: sandbox.Filter = .{};
    // Allow only the stream socket exchange makes. Landlock cannot limit UDP
    // to a port, so UDP must be refused here.
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

/// fetch gets the provider's user data in up to four tries, 1, 2 and 4
/// seconds apart, since the server may not answer as soon as the network is
/// up. With 5 s per exchange, that is at most 27 s, or 47 s with a token.
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

/// failedFor records a failure that is not worth retrying.
fn failedFor(f: Failure, n: u16) Fetched {
    _ = miss(Fetched, f, n);
    return .failed;
}

/// fetchOnce makes one attempt. It returns null when a retry may help.
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

/// request formats an HTTP/1.1 request that closes the connection after the
/// response. It refuses control characters in path and header, so neither
/// can end a line and inject headers.
fn request(buf: []u8, method: []const u8, path: []const u8, header: []const u8) ?[]const u8 {
    for ([_][]const u8{ path, header }) |s| {
        for (s) |c| if (c < 0x20 or c > 0x7e) return null;
    }
    return std.mem.print(buf, "{s} {s} HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: " ++
        "close\r\nContent-Length: 0\r\n{s}{s}\r\n", .{
        method, path, header, if (header.len > 0) "\r\n" else "",
    }) catch null;
}

/// validToken reports whether t looks like an IMDSv2 token (base64-ish), so
/// it is safe to put in a header.
fn validToken(t: []const u8) bool {
    if (t.len == 0 or t.len > 200) return false;
    for (t) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '=' and
        c != '+' and c != '/') return false;
    return true;
}

/// socket_type is the only socket the fetcher makes, and the only one its
/// filter allows.
const socket_type: u32 = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;

/// exchange sends req to the metadata server and reads the whole response
/// within 5 seconds. The response ends at its length, its last chunk, or the
/// server's close. It returns null on failure, recorded by miss.
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

/// complete reports whether resp holds a whole response: the head, and a
/// body whose last chunk or full length has arrived. It reads the head as
/// parseResponse does, so chunked encoding wins over Content-Length.
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

/// Head is what werewolf reads of a response's head: the status, how the
/// body ends, and GCP's mark.
const Head = struct {
    status: u16,
    length: ?usize = null,
    chunked: bool = false,
    /// google is set by `Metadata-Flavor: Google`, which GCP sends on every answer.
    google: bool = false,
};

/// parseHead parses an HTTP/1.x status line and headers. It returns null if
/// they are malformed or the body has an encoding other than chunked.
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

/// parseResponse parses an HTTP/1.x response. It dechunks the body in place,
/// or cuts it to Content-Length if given. It returns null if malformed.
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

/// digits parses text as digits in base and nothing else. Unlike
/// std.fmt.parseInt, it refuses a sign or _. It returns null on overflow.
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

/// dechunk decodes a chunked body in place, which is safe because the
/// output never overtakes the input. It returns null if malformed.
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

/// decodeBase64 decodes standard base64, ignoring whitespace. It returns null
/// if text is not base64 or decodes to more than out holds.
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
    /// name_buf is 100 bytes, ustar's name field, so writeTar needs no prefix.
    name_buf: [100]u8,
    name_len: u8,
    dir: bool,
    /// data is the file's contents, a slice of the checked tar.
    data: []const u8,

    fn name(e: *const Entry) []const u8 {
        return e.name_buf[0..e.name_len];
    }
};

/// checkTar checks a POSIX or GNU ustar entry by entry into out and returns
/// the count. It passes only regular files and directories with safe relative
/// names (settings.entryName), at most 32 entries of 32 KiB and 48 KiB in all,
/// and no name twice or beneath a file. It skips pax headers, which macOS's tar adds: writeTar
/// rebuilds the tar from plain fields, so nothing they say is applied.
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
        const name = settings.entryName(full) orelse return error.BadName;
        if (name.len > 100) return error.BadName;
        if (name.len > 0) {
            if (n == max_entries) return error.TooManyEntries;
            // Refuse a name twice, a name beneath a file, or a file above a
            // name. A config that says two things must not be settled by
            // whichever entry init extracts last.
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

/// beneath reports whether path lies under the directory parent.
fn beneath(path: []const u8, parent: []const u8) bool {
    return path.len > parent.len and std.mem.startsWith(u8, path, parent) and
        path[parent.len] == '/';
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

/// writeTar writes entries as a new POSIX ustar into out: every entry owned
/// by root, files 0600 and directories 0700, dated 1970.
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

/// sandboxParent drops every capability, limits writes to dir with Landlock,
/// and kills the process on any system call beyond the few it needs.
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

/// writeFile writes data to name.new beneath dir and renames it over name,
/// so init never sees a partial file.
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

/// readAll reads fd until it closes. It fails if buf fills first.
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

/// Log writes events as JSON lines on stdout, built in a fixed buffer:
/// `cloud-metadata: {"time":...,"event":...,...}`.
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

/// testTar builds a tar as tar(1) writes one from entries of name, typeflag
/// and contents.
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

    // The rewritten tar, owned by root, passes the same checks.
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
    // A directory followed by its contents passes.
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

/// parseText runs parseResponse on a writable copy of text.
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
    // Without a length, the body runs until the server closes.
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
    // With both headers, chunked wins, whichever comes first.
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
    // Desktop Hyper-V has Azure's names but not Azure's asset tag.
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
