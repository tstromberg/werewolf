//! Early domain-age authority. Init starts it before fence removes mount
//! privilege, then covers its database and socket directories with read-only
//! binds in the main namespace. This process keeps a private writable view.
//! The production age marker stays absent until the full path passes.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const dns = @import("dns");
const age = @import("age.zig");
const db_mod = @import("age_db.zig");
const evidence = @import("age_evidence.zig");
const http = @import("age_http.zig");
const ipc = @import("age_ipc.zig");
const Policy = @import("policy.zig").Policy;
const wire = @import("wire.zig");
const sys = sandbox.sys;
extern "c" fn alarm(c_uint) c_uint;

pub const id: u32 = 55;
pub const control: i32 = 3;
pub const socket_dir = dns.age_socket_dir;
pub const socket_path = dns.age_socket_path;
pub const durable_dir = "/data/svc/unwound-age";
pub const temporary_dir = "/run/werewolf-age-cache";
const durable_db = durable_dir ++ "/age.db";
const temporary_db = temporary_dir ++ "/age.db";
const max_policy = 256 * 1024;

var policy: Policy = .{};
var policy_text: [max_policy]u8 = undefined;

pub fn main() void {
    run() catch |err| {
        var buf: [256]u8 = undefined;
        const line = std.mem.print(&buf, "unwound-age: {s} ({s}: {t})\n", .{
            @errorName(err), sandbox.failed, sandbox.failed_errno,
        }) catch "unwound-age: failed\n";
        _ = linux.write(2, line.ptr, line.len);
        linux.exit_group(1);
    };
}

fn run() !void {
    if (linux.getuid() != 0) return error.RootSetupRequired;
    try policy.parse(try readPolicy());
    const ephemeral = linux.errno(linux.access("/run/werewolf/nodata", linux.F_OK)) == .SUCCESS;
    const db_dir: [:0]const u8 = if (ephemeral) temporary_dir else durable_dir;
    const db_path: [:0]const u8 = if (ephemeral) temporary_db else durable_db;
    _ = try sys(linux.unshare(linux.CLONE.NEWNS), "private age mount namespace");
    _ = try sys(
        linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0),
        "private age mount propagation",
    );
    const listener = try listen();
    // Init does not let runit start until it has made the main namespace's
    // view read-only. This handshake keeps the writable view private.
    if (linux.write(control, "R", 1) != 1) return error.InitClosed;
    var go: [1]u8 = undefined;
    if (linux.read(control, &go, 1) != 1 or go[0] != 'G') return error.InitClosed;
    _ = linux.close(control);
    try sandbox.limit(.NOFILE, 32);
    try sandbox.dropTo(id, null);
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0), "dumpable");
    const data: i32 = @intCast(try sys(
        linux.open(
            db_dir,
            .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        ),
        "open age directory",
    ));
    defer _ = linux.close(data);
    const etc: i32 = @intCast(try sys(
        linux.open("/etc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open /etc",
    ));
    defer _ = linux.close(etc);
    const network: i32 = @intCast(try sys(
        linux.open(dns.network_dir, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open resolver directory",
    ));
    defer _ = linux.close(network);
    const random: i32 = @intCast(try sys(
        linux.open("/dev/urandom", .{ .PATH = true, .CLOEXEC = true }, 0),
        "open randomness",
    ));
    defer _ = linux.close(random);
    try sandbox.landlock(&.{
        .{ .fd = data, .access = sandbox.read_file | sandbox.read_dir |
            sandbox.write_file | sandbox.truncate | sandbox.make_reg | sandbox.remove_file },
        .{ .fd = etc, .access = sandbox.read_file | sandbox.read_dir },
        .{ .fd = network, .access = sandbox.read_file | sandbox.read_dir },
        .{ .fd = random, .access = sandbox.read_file },
    }, &.{ 53, 443 });
    // A small supervisor keeps the private mount view across writer crashes.
    // It has no database connection; each child opens its own WAL handle.
    while (true) {
        const parent = linux.getpid();
        const pid = try sys(linux.fork(), "fork age writer");
        if (pid == 0) {
            sandbox.tieTo(parent);
            _ = linux.close(data);
            writer(listener, db_path);
        }
        var status: i32 = 0;
        _ = linux.waitpid(@intCast(pid), &status, 0);
        var delay: linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = linux.nanosleep(&delay, null);
    }
}

fn readPolicy() ![]const u8 {
    const fd: i32 = @intCast(try sys(
        linux.open(dns.policy_path, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0),
        "open age policy",
    ));
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    _ = try sys(
        linux.statx(
            fd,
            "",
            linux.AT.EMPTY_PATH,
            .{ .TYPE = true, .MODE = true, .UID = true, .SIZE = true },
            &st,
        ),
        "stat age policy",
    );
    if (st.uid != 0 or st.mode & 0o022 != 0 or st.mode & linux.S.IFMT != linux.S.IFREG or
        st.size >= max_policy) return error.UnsafePolicy;
    var have: usize = 0;
    while (have < policy_text.len) {
        const n = try sys(
            linux.read(fd, policy_text[have..].ptr, policy_text.len - have),
            "read age policy",
        );
        if (n == 0) break;
        have += n;
    }
    if (have != st.size) return error.UnsafePolicy;
    return policy_text[0..have];
}

fn listen() !i32 {
    const fd: i32 = @intCast(try sys(
        linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0),
        "age socket",
    ));
    errdefer _ = linux.close(fd);
    const unlinked = linux.unlink(socket_path);
    if (linux.errno(unlinked) != .SUCCESS and linux.errno(unlinked) != .NOENT)
        return error.UnsafeSocketPath;
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..socket_path.len], socket_path);
    _ = try sys(
        linux.bind(fd, @ptrCast(&address), @intCast(2 + socket_path.len + 1)),
        "bind age socket",
    );
    _ = try sys(
        linux.fchmodat2(linux.AT.FDCWD, socket_path, 0o600, linux.AT.SYMLINK_NOFOLLOW),
        "age socket permissions",
    );
    _ = try sys(linux.listen(fd, 8), "listen age socket");
    return fd;
}

fn writer(listener: i32, db_path: [:0]const u8) noreturn {
    var db = db_mod.Db.open(db_path) catch @panic("age database");
    defer db.close();
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    var client: std.http.Client = .{ .allocator = std.heap.page_allocator, .io = threaded.io() };
    defer client.deinit();
    const psl = @embedFile("data/public_suffix_list.ascii.dat");
    while (true) {
        const accepted = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(accepted) == .INTR) continue;
        if (linux.errno(accepted) != .SUCCESS) @panic("age accept");
        const channel: i32 = @intCast(accepted);
        var packet: [ipc.max_len + 1]u8 = undefined;
        while (true) {
            const n = linux.recvfrom(channel, &packet, packet.len, linux.MSG.TRUNC, null, null);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS or n == 0) break;
            if (n > ipc.max_len) continue;
            const request = ipc.decode(packet[0..n]) orelse continue;
            if (request.policy_generation != policy.generation or
                request.service >= policy.users.len)
                continue;
            const domain = switch (age.boundary(request.name.text(), psl)) {
                .registered => |value| value,
                else => "",
            };
            const decision = if (domain.len > 0)
                checkAge(&db, &client, &request, domain)
            else
                age.Decision{ .source = .none, .verdict = .unknown };
            const reply: ipc.Response = .{
                .request_id = request.request_id,
                .verdict = switch (decision.verdict) {
                    .unknown => .unknown,
                    .young => .young,
                    .mature => .mature,
                },
                .source = switch (decision.source) {
                    .none => .none,
                    .rdap => .rdap,
                    .crtsh => .crtsh,
                },
                .domain = if (domain.len > 0) wire.Name.fromText(domain) catch null else null,
            };
            var out: [ipc.response_max]u8 = undefined;
            const sent = ipc.encodeResponse(&out, &reply);
            const rc = linux.sendto(channel, sent.ptr, sent.len, linux.MSG.NOSIGNAL, null, 0);
            if (linux.errno(rc) != .SUCCESS or rc != sent.len) break;
        }
        _ = linux.close(channel);
    }
}

fn checkAge(
    db: *db_mod.Db,
    client: *std.http.Client,
    request: *const ipc.Request,
    domain: []const u8,
) age.Decision {
    const unknown: age.Decision = .{ .source = .none, .verdict = .unknown };
    const now = realtime();
    const cached = db.probe(domain, now) catch return unknown;
    if (!cached.due(now)) return cached.decision;
    if (request.request_id > std.math.maxInt(i64)) return unknown;

    // The alarm kills this single writer if DNS, TLS or SQLite stalls. The
    // supervisor starts a fresh writer and Unwound refuses the closed request.
    _ = alarm(10);
    defer _ = alarm(0);
    const label = dns.label(request.service);
    var label_text: [15]u8 = undefined;
    const source = std.mem.print(&label_text, "{d}.{d}.{d}.{d}", .{
        label[0], label[1], label[2], label[3],
    }) catch return unknown;
    var namespace: [24]u8 = undefined;
    const uid = policy.uid(request.service);
    const policy_namespace = std.mem.print(&namespace, "uid:{d}", .{uid}) catch return unknown;
    const check_id = db.beginCheck(.{
        .domain = domain,
        .started_at = now,
        .cause = if (cached.retry_after == 0) .miss else .retry,
        .request_id = @intCast(request.request_id),
        .dns_id = request.dns_id,
        .qname = request.name.text(),
        .qtype = @backingInt(request.qtype),
        .transport = switch (request.transport) {
            .udp => .udp,
            .tcp => .tcp,
        },
        .source_label = source,
        .service_uid = uid,
        .policy_namespace = policy_namespace,
        .policy_generation = request.policy_generation,
    }) catch return unknown;

    var url: [512]u8 = undefined;
    var rdap_body: [http.rdap_max]u8 = undefined;
    var ct_body: [http.crtsh_max]u8 = undefined;
    const rdap = http.rdap(client, domain, &url, &rdap_body);
    const ct = if (rdap.lookup == .unavailable) http.crtsh(client, domain, &ct_body) else null;
    const psl_generation = generation(@embedFile("data/public_suffix_list.ascii.dat"));
    const bootstrap_generation = generation(@embedFile("data/rdap-dns.json"));
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const result = evidence.result(
        arena.allocator(),
        domain,
        rdap.lookup,
        rdap.url,
        ct,
        realtime(),
        &psl_generation,
        &bootstrap_generation,
    );
    db.finishCheck(check_id, result) catch return unknown;
    return db.decision(domain, realtime()) catch unknown;
}

fn generation(comptime contents: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(contents, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn realtime() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return ts.sec;
}
