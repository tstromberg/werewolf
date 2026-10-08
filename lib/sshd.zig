//! sshd: what form.yaml writes into an image's sshd (forms/README.md), as
//! the build checks and writes it (lib/form.zig, tools/form.zig).
//!
//! `sshd:` is sshd_config keywords, each named as sshd_config names it but
//! in lowercase words joined by -, as howl's --sshd.KEYWORD VALUE sets them:
//!
//!     sshd:
//!       pubkey-accepted-algorithms: ssh-ed25519,sk-ssh-ed25519@openssh.com
//!
//! The build writes them to etc/ssh/sshd_config.d/form.conf. sshd takes a
//! keyword's first value, and form.conf sorts before the sshd form's
//! werewolf.conf, so a value here wins over the policy. A keyword is one
//! of a closed list: those that set how sshd lets people in and what a
//! session may do. None names a file or a program to run
//! (AuthorizedKeysCommand, ForceCommand, Subsystem, HostKey), or changes the
//! file's shape (Match, Include). A value is printable ASCII without
//! sshd_config's quotes, comments or escapes, so it is one line and ends
//! where the keyword's value does.
//!
//! `bastion: users:` is the bastion's users, each with keys and the
//! destinations they may reach:
//!
//!     bastion:
//!       users:
//!         alice:
//!           keys:
//!             - sk-ssh-ed25519@openssh.com AAAA... alice@laptop
//!           destinations: [10.20.0.10:22]
//!
//! The build writes them as the bastion's authorized_keys, a line a key,
//! each held to its user's destinations (permitopen), and the bastion's
//! PermitOpen, every user's destinations: a key reaches its own user's and
//! no other's. A key is a public key and nothing more: the options are the
//! build's to write. It is a security key's, as sshd takes no other,
//! unless the form's `sshd:` says sshd takes key files too.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const settings = @import("settings");

pub const max_value = 1 << 10;
pub const max_users = 256;
pub const max_keys = 32;
pub const max_destinations = 32;

const header =
    \\# From form.yaml's sshd: (forms/README.md). sshd takes a keyword's first
    \\# value, and this file sorts before werewolf.conf.
    \\
;

/// One keyword sshd_config takes from form.yaml, and the posture check its
/// value can fail: a form that changes it says so in its weaknesses.
const Keyword = struct { []const u8, []const u8, []const u8 };

const keys_check = "network-ssh-security-keys";
const config_check = "network-ssh-config";
const crypto_check = "network-ssh-crypto";

const keywords = [_]Keyword{
    .{ "pubkey-accepted-algorithms", "PubkeyAcceptedAlgorithms", keys_check },
    .{ "pubkey-auth-options", "PubkeyAuthOptions", keys_check },
    .{ "authentication-methods", "AuthenticationMethods", config_check },
    .{ "permit-root-login", "PermitRootLogin", config_check },
    .{ "allow-users", "AllowUsers", config_check },
    .{ "deny-users", "DenyUsers", config_check },
    .{ "allow-groups", "AllowGroups", config_check },
    .{ "deny-groups", "DenyGroups", config_check },
    .{ "max-auth-tries", "MaxAuthTries", config_check },
    .{ "max-sessions", "MaxSessions", config_check },
    .{ "max-startups", "MaxStartups", config_check },
    .{ "login-grace-time", "LoginGraceTime", config_check },
    .{ "client-alive-interval", "ClientAliveInterval", config_check },
    .{ "client-alive-count-max", "ClientAliveCountMax", config_check },
    .{ "log-level", "LogLevel", config_check },
    .{ "permit-tty", "PermitTTY", config_check },
    .{ "allow-tcp-forwarding", "AllowTcpForwarding", config_check },
    .{ "allow-stream-local-forwarding", "AllowStreamLocalForwarding", config_check },
    .{ "allow-agent-forwarding", "AllowAgentForwarding", config_check },
    .{ "permit-open", "PermitOpen", config_check },
    .{ "permit-listen", "PermitListen", config_check },
    .{ "gateway-ports", "GatewayPorts", config_check },
    .{ "permit-tunnel", "PermitTunnel", config_check },
    .{ "ciphers", "Ciphers", crypto_check },
    .{ "macs", "MACs", crypto_check },
    .{ "kex-algorithms", "KexAlgorithms", crypto_check },
    .{ "host-key-algorithms", "HostKeyAlgorithms", crypto_check },
};

/// One of `sshd:`'s keywords and its value: form.yaml's KEYWORD: VALUE,
/// or howl's --sshd.KEYWORD=VALUE.
pub const Pair = struct { flag: []const u8, value: []const u8 };

pub const Fragment = struct {
    /// The file's text: a line a keyword, in the order given.
    text: []const u8,
    /// The posture checks the values may fail, each once, for the form's
    /// weaknesses as `?ID`: whether one does is the value's to say, and
    /// the boot's posture line says it.
    checks: []const []const u8,
};

/// The fragment from pairs, or error.Invalid with why saying which keyword
/// and what is wrong, never the value.
pub fn fragment(gpa: Allocator, pairs: []const Pair, why: *[]const u8) !Fragment {
    var text: std.ArrayList(u8) = .empty;
    var checks: std.ArrayList([]const u8) = .empty;
    try text.appendSlice(gpa, header);
    for (pairs, 0..) |p, i| {
        const name, const check = for (keywords) |k| {
            if (std.mem.eql(u8, k[0], p.flag)) break .{ k[1], k[2] };
        } else return fail(gpa, why, "sshd {s}: sshd takes {s}", .{ p.flag, flagList() });
        for (pairs[0..i]) |seen| if (std.mem.eql(u8, seen.flag, p.flag))
            return fail(gpa, why, "sshd {s}: twice; sshd would take the first alone", .{p.flag});
        const value = std.mem.trim(u8, p.value, " ");
        if (value.len == 0) return fail(gpa, why, "sshd {s}: an empty value", .{p.flag});
        if (value.len > max_value)
            return fail(gpa, why, "sshd {s}: longer than {d} bytes", .{ p.flag, max_value });
        for (value) |c| if (!valueByte(c)) return fail(
            gpa,
            why,
            "sshd {s}: a value is letters, digits, spaces and @ . _ , : + * ^ ! ? / [ ] -",
            .{p.flag},
        );
        try text.print(gpa, "{s} {s}\n", .{ name, value });
        for (checks.items) |c| {
            if (std.mem.eql(u8, c, check)) break;
        } else try checks.append(gpa, check);
    }
    return .{ .text = text.items, .checks = checks.items };
}

/// Whether pairs let sshd take a key file, not a security key's alone:
/// a pubkey-accepted-algorithms naming an algorithm without the sk- of a
/// FIDO authenticator's, or changing OpenSSH's default list (+, -, ^),
/// which holds key files.
pub fn takesKeyFiles(pairs: []const Pair) bool {
    for (pairs) |p| if (std.mem.eql(u8, p.flag, "pubkey-accepted-algorithms")) {
        const v = std.mem.trim(u8, p.value, " ");
        if (v.len > 0 and std.mem.findScalar(u8, "+-^", v[0]) != null) return true;
        var it = std.mem.tokenizeScalar(u8, v, ',');
        while (it.next()) |alg| if (!std.mem.startsWith(u8, alg, "sk-")) return true;
    };
    return false;
}

/// What a value may hold: none of sshd_config's quotes ("), comment (#),
/// escape (\), = (a keyword's other separator), % (a path's tokens), a
/// tab or a line's end.
fn valueByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or std.mem.findScalar(u8, " @._,:+*^!?/[]-", c) != null;
}

fn flagList() []const u8 {
    comptime var s: []const u8 = "";
    inline for (keywords, 0..) |k, i| s = s ++ (if (i > 0) " " else "") ++ k[0];
    return s;
}

/// A bastion's user, as form.yaml names it.
pub const User = struct {
    name: []const u8,
    keys: []const []const u8,
    destinations: []const []const u8,
};

/// The key types sshd may be given, security keys' first.
const security_key_types = [_][]const u8{
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
};
const key_file_types = [_][]const u8{
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
};

/// The bastion's authorized_keys from users: a line a key, its options
/// `restrict,port-forwarding` and a permitopen for each of its user's
/// destinations, its comment the user's name. key_files: whether sshd
/// takes key files (takesKeyFiles), or security keys' alone. Refused, with
/// why naming the user and what is wrong: a name that is not one, a user
/// with no key or no destination, a line that is not a public key, a key
/// file sshd would refuse, a key twice, a destination that is not a
/// literal address and port.
pub fn authorizedKeys(
    gpa: Allocator,
    users: []const User,
    key_files: bool,
    why: *[]const u8,
) ![]const u8 {
    if (users.len > max_users) return fail(gpa, why, "bastion: more than {d} users", .{max_users});
    var out: std.ArrayList(u8) = .empty;
    var seen: std.ArrayList([]const u8) = .empty;
    for (users, 0..) |u, i| {
        if (!isUserName(u.name)) return fail(
            gpa,
            why,
            "bastion: user {s}: a name is a-z, 0-9 and -, starting with a letter, at most 32",
            .{u.name},
        );
        for (users[0..i]) |other| if (std.mem.eql(u8, other.name, u.name))
            return fail(gpa, why, "bastion: user {s}: named twice", .{u.name});
        if (u.keys.len == 0 or u.keys.len > max_keys)
            return fail(gpa, why, "bastion: user {s}: 1 to {d} keys", .{ u.name, max_keys });
        if (u.destinations.len == 0 or u.destinations.len > max_destinations) return fail(
            gpa,
            why,
            "bastion: user {s}: 1 to {d} destinations",
            .{ u.name, max_destinations },
        );
        var options: std.ArrayList(u8) = .empty;
        try options.appendSlice(gpa, "restrict,port-forwarding");
        for (u.destinations) |d| {
            if (settings.reason(.addrport, .{ .string = d })) |r| return fail(
                gpa,
                why,
                "bastion: user {s}: destination {s}: {s}, as 10.20.0.10:22 or [fd00::1]:22",
                .{ u.name, d, r },
            );
            try options.print(gpa, ",permitopen=\"{s}\"", .{d});
        }
        for (u.keys) |line| {
            const k = try publicKey(gpa, u.name, line, key_files, why);
            for (seen.items) |s| if (std.mem.eql(u8, s, k.body))
                return fail(gpa, why, "bastion: user {s}: a key given twice", .{u.name});
            try seen.append(gpa, k.body);
            try out.print(gpa, "{s} {s} {s} {s}\n", .{ options.items, k.type, k.body, u.name });
        }
    }
    return out.items;
}

/// The bastion's PermitOpen: every user's destinations, each once, as one
/// sshd_config line, or "" for none, leaving its PermitOpen none.
pub fn permitOpen(gpa: Allocator, users: []const User) ![]const u8 {
    var all: std.ArrayList([]const u8) = .empty;
    for (users) |u| for (u.destinations) |d| {
        for (all.items) |have| {
            if (std.mem.eql(u8, have, d)) break;
        } else try all.append(gpa, d);
    };
    if (all.items.len == 0) return "";
    return gpa.print("PermitOpen {s}\n", .{try std.mem.join(gpa, " ", all.items)});
}

/// A destination's port: what is after its last colon. Only for one
/// authorizedKeys took.
pub fn port(destination: []const u8) u16 {
    const colon = std.mem.findScalarLast(u8, destination, ':') orelse return 0;
    return std.fmt.parseInt(u16, destination[colon + 1 ..], 10) catch 0;
}

const Key = struct { type: []const u8, body: []const u8 };

/// line as TYPE BASE64 [COMMENT], the comment dropped.
fn publicKey(
    gpa: Allocator,
    user: []const u8,
    line: []const u8,
    key_files: bool,
    why: *[]const u8,
) !Key {
    var words = std.mem.tokenizeScalar(u8, std.mem.trim(u8, line, " \t"), ' ');
    const t = words.next() orelse "";
    const body = words.next() orelse "";
    const security = for (security_key_types) |s| {
        if (std.mem.eql(u8, s, t)) break true;
    } else false;
    const file = for (key_file_types) |s| {
        if (std.mem.eql(u8, s, t)) break true;
    } else false;
    if (!security and !file) return fail(
        gpa,
        why,
        "bastion: user {s}: a key is TYPE BASE64 [COMMENT], as ssh-keygen writes a .pub, " ++
            "without options: the build writes those",
        .{user},
    );
    if (file and !key_files) return fail(
        gpa,
        why,
        "bastion: user {s}: a {s} key is a key file, and sshd takes security keys alone " ++
            "(ssh-keygen -t ed25519-sk); sshd: pubkey-accepted-algorithms names what else it takes",
        .{ user, t },
    );
    const base64 = body.len >= 16 and body.len <= 16 << 10 and for (body) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '/' and c != '=') break false;
    } else true;
    if (!base64) return fail(gpa, why, "bastion: user {s}: a key's body is base64", .{user});
    for (line) |c| if (c < ' ' or c == 0x7f)
        return fail(gpa, why, "bastion: user {s}: a key is one line", .{user});
    return .{ .type = t, .body = body };
}

fn isUserName(s: []const u8) bool {
    if (s.len == 0 or s.len > 32 or !std.ascii.isLower(s[0])) return false;
    for (s) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

fn fail(
    gpa: Allocator,
    why: *[]const u8,
    comptime fmt: []const u8,
    args: anytype,
) error{ Invalid, OutOfMemory } {
    why.* = try gpa.print(fmt, args);
    return error.Invalid;
}

test fragment {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const f = try fragment(a, &.{
        .{
            .flag = "pubkey-accepted-algorithms",
            .value = "ssh-ed25519,sk-ssh-ed25519@openssh.com",
        },
        .{ .flag = "pubkey-auth-options", .value = "none" },
        .{ .flag = "max-startups", .value = " 10:30:60 " },
        .{ .flag = "permit-open", .value = "10.0.0.1:22 [fd00::1]:22" },
    }, &why);
    try testing.expectEqualStrings(
        header ++ "PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com\n" ++
            "PubkeyAuthOptions none\nMaxStartups 10:30:60\nPermitOpen 10.0.0.1:22 [fd00::1]:22\n",
        f.text,
    );
    try testing.expectEqual(2, f.checks.len);
    try testing.expectEqualStrings("network-ssh-security-keys", f.checks[0]);
    try testing.expectEqualStrings("network-ssh-config", f.checks[1]);
}

test "fragment refuses what is not one keyword's value" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    for ([_]struct { Pair, []const u8 }{
        // A program run as root, a new block, a file read.
        .{ .{ .flag = "authorized-keys-command", .value = "/bin/sh" }, "sshd takes" },
        .{ .{ .flag = "match", .value = "all" }, "sshd takes" },
        .{ .{ .flag = "include", .value = "/data/x" }, "sshd takes" },
        .{ .{ .flag = "PubkeyAuthOptions", .value = "none" }, "sshd takes" },
        // A second line, a comment, a quote, an escape, a token.
        .{ .{ .flag = "allow-users", .value = "root\nForceCommand /bin/sh" }, "a value is" },
        .{ .{ .flag = "allow-users", .value = "root # x" }, "a value is" },
        .{ .{ .flag = "allow-users", .value = "\"root\"" }, "a value is" },
        .{ .{ .flag = "allow-users", .value = "root\\" }, "a value is" },
        .{ .{ .flag = "allow-users", .value = "root=x" }, "a value is" },
        .{ .{ .flag = "allow-users", .value = "%u" }, "a value is" },
        .{ .{ .flag = "allow-users", .value = "root\tx" }, "a value is" },
        .{ .{ .flag = "allow-users", .value = "rööt" }, "a value is" },
        .{ .{ .flag = "allow-users", .value = "  " }, "an empty value" },
    }) |c| {
        try testing.expectError(error.Invalid, fragment(a, &.{c[0]}, &why));
        try testing.expect(std.mem.indexOf(u8, why, c[1]) != null);
    }
    try testing.expectError(error.Invalid, fragment(a, &.{
        .{ .flag = "log-level", .value = "INFO" },
        .{ .flag = "log-level", .value = "DEBUG3" },
    }, &why));
    try testing.expectEqualStrings("sshd log-level: twice; sshd would take the first alone", why);
    const long = try a.alloc(u8, max_value + 1);
    @memset(long, 'a');
    try testing.expectError(
        error.Invalid,
        fragment(a, &.{.{ .flag = "allow-users", .value = long }}, &why),
    );
}

test takesKeyFiles {
    try testing.expect(!takesKeyFiles(&.{}));
    try testing.expect(!takesKeyFiles(&.{.{ .flag = "log-level", .value = "INFO" }}));
    try testing.expect(!takesKeyFiles(&.{.{
        .flag = "pubkey-accepted-algorithms",
        .value = "sk-ssh-ed25519@openssh.com",
    }}));
    try testing.expect(takesKeyFiles(&.{.{
        .flag = "pubkey-accepted-algorithms",
        .value = "sk-ssh-ed25519@openssh.com,ssh-ed25519",
    }}));
    try testing.expect(takesKeyFiles(&.{.{
        .flag = "pubkey-accepted-algorithms",
        .value = "-ssh-rsa*",
    }}));
}

const sk_key = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t";
const file_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

test authorizedKeys {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const users = [_]User{
        .{
            .name = "alice",
            .keys = &.{sk_key ++ " alice@laptop"},
            .destinations = &.{ "10.20.0.10:22", "[fd00::1]:2222" },
        },
        .{ .name = "bob", .keys = &.{sk_key ++ "AA"}, .destinations = &.{"10.20.0.10:22"} },
    };
    try testing.expectEqualStrings(
        "restrict,port-forwarding,permitopen=\"10.20.0.10:22\",permitopen=\"[fd00::1]:2222\" " ++
            sk_key ++ " alice\n" ++
            "restrict,port-forwarding,permitopen=\"10.20.0.10:22\" " ++ sk_key ++ "AA bob\n",
        try authorizedKeys(a, &users, false, &why),
    );
    try testing.expectEqualStrings(
        "PermitOpen 10.20.0.10:22 [fd00::1]:2222\n",
        try permitOpen(a, &users),
    );
    try testing.expectEqualStrings("", try permitOpen(a, &.{}));
    try testing.expectEqual(2222, port("[fd00::1]:2222"));
    try testing.expectEqual(22, port("10.20.0.10:22"));
    // A key file, once sshd takes them.
    const files = [_]User{.{
        .name = "carol",
        .keys = &.{file_key},
        .destinations = &.{"10.0.0.1:22"},
    }};
    try testing.expectError(error.Invalid, authorizedKeys(a, &files, false, &why));
    try testing.expect(std.mem.indexOf(u8, why, "ed25519-sk") != null);
    _ = try authorizedKeys(a, &files, true, &why);
}

test "authorizedKeys refuses what would let more in than the user says" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var why: []const u8 = "";
    const d: []const []const u8 = &.{"10.0.0.1:22"};
    for ([_]struct { User, []const u8 }{
        // Options of the user's own: a command, any destination.
        .{
            .{ .name = "a", .keys = &.{"command=\"/bin/sh\" " ++ sk_key}, .destinations = d },
            "without options",
        },
        .{
            .{ .name = "a", .keys = &.{"permitopen=\"*:*\" " ++ sk_key}, .destinations = d },
            "without options",
        },
        .{
            .{ .name = "a", .keys = &.{sk_key ++ "\nssh-ed25519 AAAA"}, .destinations = d },
            "base64",
        },
        .{
            .{ .name = "a", .keys = &.{"sk-ssh-ed25519@openssh.com AAAA\"x"}, .destinations = d },
            "base64",
        },
        .{ .{ .name = "a", .keys = &.{}, .destinations = d }, "keys" },
        .{ .{ .name = "a", .keys = &.{sk_key}, .destinations = &.{} }, "destinations" },
        // A hostname, a wildcard, a quote that would end permitopen's.
        .{
            .{ .name = "a", .keys = &.{sk_key}, .destinations = &.{"db.internal:22"} },
            "literal address",
        },
        .{ .{ .name = "a", .keys = &.{sk_key}, .destinations = &.{"*:22"} }, "literal address" },
        .{
            .{ .name = "a", .keys = &.{sk_key}, .destinations = &.{"10.0.0.1:22\""} },
            "literal address",
        },
        .{ .{ .name = "Alice", .keys = &.{sk_key}, .destinations = d }, "a name is" },
        .{ .{ .name = "a b", .keys = &.{sk_key}, .destinations = d }, "a name is" },
    }) |c| {
        try testing.expectError(error.Invalid, authorizedKeys(a, &.{c[0]}, true, &why));
        try testing.expect(std.mem.indexOf(u8, why, c[1]) != null);
    }
    try testing.expectError(error.Invalid, authorizedKeys(a, &.{
        .{ .name = "a", .keys = &.{sk_key}, .destinations = d },
        .{ .name = "b", .keys = &.{sk_key ++ " other"}, .destinations = d },
    }, false, &why));
    try testing.expectEqualStrings("bastion: user b: a key given twice", why);
    try testing.expectError(error.Invalid, authorizedKeys(a, &.{
        .{ .name = "a", .keys = &.{sk_key}, .destinations = d },
        .{ .name = "a", .keys = &.{sk_key ++ "AA"}, .destinations = d },
    }, false, &why));
    try testing.expectEqualStrings("bastion: user a: named twice", why);
}
