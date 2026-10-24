//! One domain-age fetch, in a child that holds nothing worth stealing: no
//! database, no DNS channel, no cached evidence. It reads RDAP, and crt.sh
//! after an RDAP outage, parses both, and writes the dates it found as one
//! fixed record. The supervisor kills it at its deadline, and the writer
//! checks the record before it trusts a byte.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const dns = @import("dns");
const evidence = @import("age_evidence.zig");
const http = @import("age_http.zig");

/// run fetches evidence for domain, writes it to out and exits.
pub fn run(out: i32, domain: []const u8) noreturn {
    confine(out) catch linux.exit_group(1);
    var threaded: std.Io.Threaded = .init_single_threaded;
    var client: std.http.Client = .{ .allocator = std.heap.page_allocator, .io = threaded.io() };
    var url: [512]u8 = undefined;
    var rdap_body: [http.rdap_max]u8 = undefined;
    var ct_body: [http.crtsh_max]u8 = undefined;
    const rdap = http.rdap(&client, domain, &url, &rdap_body);
    const ct = if (rdap.lookup == .unavailable) http.crtsh(&client, domain, &ct_body) else null;
    const f = evidence.found(std.heap.page_allocator, domain, rdap.lookup, ct, realtime());
    var record: [evidence.found_len]u8 = undefined;
    evidence.encode(&record, f);
    _ = linux.write(out, &record, record.len);
    linux.exit_group(0);
}

/// confine keeps only out, and narrows the supervisor's Landlock domain to
/// reading /etc (resolver, hosts and CA files) and the network state its
/// resolver file links to, with TCP connects to 53 and 443 alone. Its filter
/// then allows DNS and HTTPS and writing out, nothing else.
fn confine(out: i32) !void {
    try sandbox.closeAllButAnonymous(&.{out});
    try sandbox.limit(.NOFILE, 16);
    const etc: i32 = @intCast(try sandbox.sys(
        linux.open("/etc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open /etc",
    ));
    const network: i32 = @intCast(try sandbox.sys(
        linux.open(dns.network_dir, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open resolver directory",
    ));
    try sandbox.landlock(&.{
        .{ .fd = etc, .access = sandbox.read_file | sandbox.read_dir },
        .{ .fd = network, .access = sandbox.read_file | sandbox.read_dir },
    }, &.{ 53, 443 });
    _ = linux.close(etc);
    _ = linux.close(network);
    var f: sandbox.Filter = .{};
    allowBasics(&f);
    allowFetch(&f);
    f.allowArg("write", 0, @intCast(out));
    try f.install();
}

/// allowBasics allows what every age process does: memory, clocks, and
/// leaving.
pub fn allowBasics(f: *sandbox.Filter) void {
    inline for (.{
        "mmap",
        "munmap",
        "mremap",
        "madvise",
        "clock_gettime",
        "close",
        "getpid",
        "getppid",
        "rt_sigreturn",
        "restart_syscall",
        "exit",
        "exit_group",
    }) |call| f.allow(call);
}

/// allowFetch allows DNS and HTTPS over IPv4 or IPv6, and reading files.
/// Landlock decides which files, and which TCP ports.
pub fn allowFetch(f: *sandbox.Filter) void {
    f.allowArg("socket", 0, linux.AF.INET);
    f.allowArg("socket", 0, linux.AF.INET6);
    // Zig's DNS resolver makes its IPv6 UDP socket dual-stack.
    f.allowTwo("setsockopt", 1, linux.IPPROTO.IPV6, 2, linux.IPV6.V6ONLY);
    inline for (.{
        "bind",
        "connect",
        "getsockname",
        "sendmsg",
        "recvmsg",
        "sendto",
        "recvfrom",
        "poll",
        "ppoll",
        "openat",
        "read",
        "readv",
        "preadv",
        "pread64",
        "lseek",
        "fstat",
        "newfstatat",
        "fstatat64",
        "statx",
        "getrandom",
    }) |call| f.allow(call);
}

pub fn realtime() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return ts.sec;
}
