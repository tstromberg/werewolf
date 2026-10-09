//! keys offers the person running howl their own public keys, from ~/.ssh,
//! for root on a machine whose form runs sshd and was given none. See
//! README.md.

const std = @import("std");
const forms = @import("form");
const sshd = @import("sshd");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// offer returns root's authorized_keys for machine name: the keys in
/// ~/.ssh the chain's sshd takes, security keys unless it takes key files
/// too, once the person agrees or yes answers for them. It returns null,
/// saying why, when there are none or the person declines; a machine with
/// no key still boots, reached by console.
pub fn offer(
    io: Io,
    gpa: Allocator,
    chain: []const forms.Form,
    name: []const u8,
    yes: bool,
) !?[]const u8 {
    if (!forms.runsSshd(chain)) return null;
    const key_files = forms.takesKeyFiles(gpa, chain) catch false;
    const home = howl.environ.get("HOME") orelse return null;
    const found = try usable(io, gpa, try std.fs.path.join(gpa, &.{ home, ".ssh" }), key_files);
    if (found.lines.len == 0) {
        howl.say(io, "root on {s} takes no key, so no one can log in by ssh: {s}", .{
            name,
            if (key_files)
                "~/.ssh holds no public key; --root-keys FILE takes one"
            else
                "~/.ssh holds no security key (ssh-keygen -t ed25519-sk makes one); " ++
                    "--sshd.pubkey-accepted-algorithms=ssh-ed25519 lets a key file in, " ++
                    "a posture weakness",
        });
        return null;
    }
    const files = try mem.join(gpa, ", ", found.files);
    if (!yes) {
        if (!(Io.File.stdin().isTty(io) catch false)) {
            howl.say(io, "root on {s} takes no key: --yes copies {s}; --root-keys FILE takes " ++
                "one", .{
                name,
                files,
            });
            return null;
        }
        var buf: [256]u8 = undefined;
        const q = std.mem.print(&buf, "howl: copy {s} to root on {s}, for ssh? [Y/n] ", .{
            files,
            name,
        }) catch "howl: copy your keys to root, for ssh? [Y/n] ";
        Io.File.stderr().writeStreamingAll(io, q) catch {};
        var in_buf: [64]u8 = undefined;
        var r = Io.File.stdin().readerStreaming(io, &in_buf);
        const answer = r.interface.takeDelimiterInclusive('\n') catch "";
        const a = mem.trim(u8, answer, " \t\r\n");
        if (a.len > 0 and (a[0] == 'n' or a[0] == 'N')) {
            howl.say(io, "root on {s} takes no key; --root-keys FILE takes one", .{name});
            return null;
        }
    }
    howl.say(io, "root on {s} takes {s}", .{ name, files });
    return try mem.concat(gpa, u8, found.lines);
}

/// Usable is the public keys found: each one's line, and its file's name.
const Usable = struct { lines: []const []const u8, files: []const []const u8 };

/// usable returns the keys in dir's *.pub files that sshd takes: security
/// keys, and key files when key_files.
fn usable(io: Io, gpa: Allocator, dir: []const u8, key_files: bool) !Usable {
    var lines: std.ArrayList([]const u8) = .empty;
    var files: std.ArrayList([]const u8) = .empty;
    var d = Dir.cwd().openDir(
        io,
        dir,
        .{ .iterate = true },
    ) catch return .{ .lines = &.{}, .files = &.{} };
    defer d.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file or !mem.endsWith(u8, e.name, ".pub")) continue;
        try names.append(gpa, try gpa.dupe(u8, e.name));
    }
    mem.sortUnstable([]const u8, names.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return mem.lessThan(u8, a, b);
        }
    }.lt);
    for (names.items) |n| {
        const text = d.readFileAlloc(io, n, gpa, .limited(16 << 10)) catch continue;
        const line = mem.trim(
            u8,
            text[0 .. mem.findScalar(u8, text, '\n') orelse text.len],
            " \t\r",
        );
        if (!takes(line, key_files)) continue;
        try lines.append(gpa, try gpa.print("{s}\n", .{line}));
        try files.append(gpa, n);
    }
    return .{ .lines = lines.items, .files = files.items };
}

/// takes reports whether line is a public key sshd takes.
fn takes(line: []const u8, key_files: bool) bool {
    var words = mem.tokenizeScalar(u8, line, ' ');
    const t = words.next() orelse return false;
    if (words.next() == null) return false;
    return sshd.isSecurityKey(t) or (key_files and sshd.isKeyFile(t));
}

const testing = std.testing;

test takes {
    const sk = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t me@yubikey";
    const file = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI me@laptop";
    try testing.expect(takes(sk, false));
    try testing.expect(!takes(file, false));
    try testing.expect(takes(file, true));
    try testing.expect(!takes("sk-ssh-ed25519@openssh.com", true));
    try testing.expect(!takes("ssh-dss AAAA", true));
}
