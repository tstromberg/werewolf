//! bite-cleanup: delete the distro bite took over, once werewolf is GRUB's
//! default (docs/bite.md).
//!
//!     bite-cleanup        delete it
//!     bite-cleanup -n     show what would go; change nothing
//!
//! Once werewolf commits, the distro is only a fallback, and a stale one:
//! nothing updates it, and it still holds its secrets, cloud-init's user-data
//! among them. bite-cleanup deletes everything on the victim's filesystem but
//! werewolf's directory and, if GRUB's environment block is on the same
//! filesystem, its top directory (/boot, which holds GRUB and werewolf's
//! kernel). It refuses until werewolf is GRUB's default: before that, a reset
//! still boots the distro.
//!
//! The victim's filesystem is mounted apart and writable, since /victim is
//! read-only, and with discard, so a thin cloud volume gets the freed blocks
//! back. The deleting is done by a child that can do nothing else: no new
//! privileges, only the capabilities that override file permissions, and
//! Landlock allowing nothing on any filesystem but removing files and
//! directories beneath the victim's mount, and running nothing at all. The
//! parent, which mounted it, unmounts it after.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const mount_bin = "/usr/lib/werewolf/mount";
const blkid_bin = "/usr/bin/blkid";
const base = "/run/werewolf/cleanup";
const env_dir = base ++ "/env";
const victim_dir = base ++ "/victim";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    const dry = args.len == 2 and std.mem.eql(u8, args[1], "-n");
    if (args.len != 1 and !dry) fail("usage: bite-cleanup [-n]", .{});
    if (linux.geteuid() != 0) fail("run as root", .{});

    const cmd = parseCmdline(readAll(
        io,
        gpa,
        "/proc/cmdline",
    )) orelse fail("this machine was not bitten", .{});

    // Only a committed machine may lose its fallback.
    if (!mountUuid(
        io,
        gpa,
        cmd.grubenv.uuid,
        env_dir,
    )) fail("cannot mount {s}", .{cmd.grubenv.uuid});
    const block = readAll(
        io,
        gpa,
        try gpa.print("{s}{s}", .{ env_dir, cmd.grubenv.path }),
    );
    _ = linux.umount2(env_dir, 0);
    if (!isCommitted(block)) fail(
        "werewolf is not yet GRUB's default; the distro is still its fallback",
        .{},
    );

    const keep = try keeps(gpa, cmd);
    if (!mountUuid(
        io,
        gpa,
        cmd.victim.uuid,
        victim_dir,
    )) fail("cannot mount {s}", .{cmd.victim.uuid});
    // Not every filesystem will turn discard on in a remount; it is a help,
    // not a promise.
    if (!dry and
        !run(
            io,
            &.{ mount_bin, "-o", "remount,discard", victim_dir },
        )) say("discard not available here", .{});

    const pid = linux.fork();
    if (pid == 0) prune(io, gpa, keep, dry);
    var status: i32 = 0;
    _ = linux.waitpid(@intCast(pid), &status, 0);
    linux.sync();
    _ = linux.umount2(victim_dir, 0);
    const s: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(s) or
        linux.W.EXITSTATUS(s) != 0) fail("deleting stopped; see above", .{});
    if (!dry) {
        say(
            "bite --undo is no longer possible; GRUB's menu still lists the distro, which no " ++
                "longer boots",
            .{},
        );
        say(
            "rm frees blocks, it does not erase them: snapshots taken before now still hold the " ++
                "distro",
            .{},
        );
    }
}

/// The child: confined, then deleting everything not kept.
fn prune(io: Io, gpa: Allocator, keep: []const []const u8, dry: bool) noreturn {
    const root = Dir.cwd().openDir(
        io,
        victim_dir,
        .{ .iterate = true, .follow_symlinks = false },
    ) catch |err|
        fail("{s}: {s}", .{ victim_dir, @errorName(err) });
    confine(root.handle) catch |err| fail("cannot confine the deleting: {s}", .{@errorName(err)});
    var n: usize = 0;
    walk(io, gpa, root, "", keep, dry, &n) catch |err| fail("{s}", .{@errorName(err)});
    var list: std.ArrayList(u8) = .empty;
    for (keep, 0..) |k, i| list.print(gpa, "{s}{s}", .{ if (i > 0) " " else "", k }) catch {};
    if (dry)
        say("-n: would delete {d} entries, keeping {s}; nothing changed", .{ n, list.items })
    else
        say("deleted {d} entries of the distro, keeping {s}", .{ n, list.items });
    std.process.exit(0);
}

/// Everything in dir (at path, from the filesystem's root) that is neither
/// kept nor above something kept goes. Symlinks are entries, never followed.
fn walk(
    io: Io,
    gpa: Allocator,
    dir: Dir,
    path: []const u8,
    keep: []const []const u8,
    dry: bool,
    n: *usize,
) !void {
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        const p = try gpa.print("{s}/{s}", .{ path, e.name });
        switch (fate(p, keep)) {
            .keep => {},
            .descend => {
                var sub = try dir.openDir(
                    io,
                    e.name,
                    .{ .iterate = true, .follow_symlinks = false },
                );
                defer sub.close(io);
                try walk(io, gpa, sub, p, keep, dry, n);
            },
            .delete => {
                n.* += 1;
                if (dry) say("would delete {s}", .{p}) else try dir.deleteTree(io, e.name);
            },
        }
    }
}

const Fate = enum { keep, descend, delete };

fn fate(path: []const u8, keep: []const []const u8) Fate {
    for (keep) |k| {
        if (std.mem.eql(u8, k, path)) return .keep;
        if (k.len > path.len and std.mem.startsWith(u8, k, path) and
            k[path.len] == '/') return .descend;
    }
    return .delete;
}

/// What stays: werewolf's directory, and the top directory holding GRUB's
/// environment block if it is on the same filesystem.
fn keeps(gpa: Allocator, cmd: Cmdline) ![]const []const u8 {
    var k: std.ArrayList([]const u8) = .empty;
    try k.append(gpa, cmd.victim.path);
    if (std.mem.eql(u8, cmd.victim.uuid, cmd.grubenv.uuid)) {
        var it = std.mem.tokenizeScalar(u8, cmd.grubenv.path, '/');
        const top = it.next() orelse return k.items;
        try k.append(gpa, try gpa.print("/{s}", .{top}));
    }
    return k.items;
}

/// Whether GRUB's block has werewolf as its saved default.
fn isCommitted(block: []const u8) bool {
    var it = std.mem.splitScalar(u8, block, '\n');
    while (it.next()) |line| {
        if (std.mem.eql(u8, line, "saved_entry=werewolf-a") or
            std.mem.eql(u8, line, "saved_entry=werewolf-b")) return true;
    }
    return false;
}

const Place = struct { uuid: []const u8, path: []const u8 };
const Cmdline = struct { victim: Place, grubenv: Place };

/// werewolf.victim=UUID:PATH and werewolf.grubenv=UUID:PATH, as bite wrote
/// them. PATH is absolute, without . or .. or empty parts.
fn parseCmdline(text: []const u8) ?Cmdline {
    var victim: ?Place = null;
    var grubenv: ?Place = null;
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |arg| {
        if (std.mem.startsWith(
            u8,
            arg,
            "werewolf.victim=",
        )) victim = parsePlace(arg["werewolf.victim=".len..]);
        if (std.mem.startsWith(
            u8,
            arg,
            "werewolf.grubenv=",
        )) grubenv = parsePlace(arg["werewolf.grubenv=".len..]);
    }
    return .{ .victim = victim orelse return null, .grubenv = grubenv orelse return null };
}

fn parsePlace(s: []const u8) ?Place {
    const colon = std.mem.findScalar(u8, s, ':') orelse return null;
    const uuid = s[0..colon];
    const path = s[colon + 1 ..];
    if (uuid.len == 0 or path.len < 2 or path[0] != '/') return null;
    for (uuid) |c| if (!std.ascii.isHex(c) and c != '-') return null;
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return null;
    }
    return .{ .uuid = uuid, .path = path };
}

// --- confinement -------------------------------------------------------------

const PR_SET_NO_NEW_PRIVS = 38;
const LINUX_CAPABILITY_VERSION_3 = 0x20080522;
const CAP_DAC_OVERRIDE = 1;
const CAP_DAC_READ_SEARCH = 2;
const CAP_FOWNER = 3;

/// The kernel's __user_cap_header_struct, whose pid is an int; Zig 0.17's
/// cap_user_header_t has it as a usize (see cmd/mount/mount.zig).
const CapHeader = extern struct { version: u32, pid: i32 };
const CapSets = extern struct { effective: u32, permitted: u32, inheritable: u32 };

// Landlock's filesystem rights (ABI 1), and REFER (2) and TRUNCATE (3).
const LL_EXECUTE = 1 << 0;
const LL_WRITE_FILE = 1 << 1;
const LL_REMOVE_DIR = 1 << 4;
const LL_REMOVE_FILE = 1 << 5;
const LL_MAKE_ALL = 0x7f << 6; // char, dir, reg, sock, fifo, block, sym
const LL_REFER = 1 << 13;
const LL_TRUNCATE = 1 << 14;
const LANDLOCK_RULE_PATH_BENEATH = 1;

/// Nothing but deleting beneath root: no new privileges; of root's
/// capabilities, only those that let it past files' owners and modes; and
/// Landlock, which handles every right that changes a filesystem or runs a
/// program, and grants removing, beneath root, alone.
fn confine(root: linux.fd_t) !void {
    try sys(linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    const header: CapHeader = .{ .version = LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    const caps: u32 = 1 << CAP_DAC_OVERRIDE | 1 << CAP_DAC_READ_SEARCH | 1 << CAP_FOWNER;
    const data = [2]CapSets{
        .{ .effective = caps, .permitted = caps, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    try sys(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));

    const abi = linux.syscall3(
        .landlock_create_ruleset,
        0,
        0,
        1,
    ); // LANDLOCK_CREATE_RULESET_VERSION
    try sys(abi);
    var handled: u64 = LL_EXECUTE | LL_WRITE_FILE | LL_REMOVE_DIR | LL_REMOVE_FILE | LL_MAKE_ALL;
    if (abi >= 2) handled |= LL_REFER;
    if (abi >= 3) handled |= LL_TRUNCATE;
    const ruleset = linux.syscall3(
        .landlock_create_ruleset,
        @intFromPtr(&handled),
        @sizeOf(u64),
        0,
    );
    try sys(ruleset);
    // struct landlock_path_beneath_attr: a u64 and an s32, packed.
    var rule: [12]u8 = undefined;
    std.mem.writeInt(u64, rule[0..8], LL_REMOVE_DIR | LL_REMOVE_FILE, .little);
    std.mem.writeInt(i32, rule[8..12], root, .little);
    try sys(linux.syscall4(
        .landlock_add_rule,
        ruleset,
        LANDLOCK_RULE_PATH_BENEATH,
        @intFromPtr(&rule),
        0,
    ));
    try sys(linux.syscall2(.landlock_restrict_self, ruleset, 0));
}

fn sys(rc: usize) !void {
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM => error.PermissionDenied,
        .NOSYS, .OPNOTSUPP => error.LandlockUnavailable,
        else => |e| {
            say("{s}", .{@tagName(e)});
            return error.SystemCallFailed;
        },
    };
}

// --- the rest ----------------------------------------------------------------

/// The filesystem with uuid on dir, through the mount helper, apart from
/// /victim and writable.
fn mountUuid(io: Io, gpa: Allocator, uuid: []const u8, dir: []const u8) bool {
    const tag = gpa.print("UUID={s}", .{uuid}) catch return false;
    const res = std.process.run(
        gpa,
        io,
        .{ .argv = &.{ blkid_bin, "-c", "/dev/null", "-l", "-o", "device", "-t", tag } },
    ) catch return false;
    const dev = std.mem.trim(u8, res.stdout, " \r\n");
    if (dev.len == 0) return false;
    Dir.cwd().createDirPath(io, dir) catch return false;
    return run(io, &.{ mount_bin, "-o", "nosuid,nodev,noexec", dev, dir });
}

fn run(io: Io, argv: []const []const u8) bool {
    var child = std.process.spawn(io, .{ .argv = argv, .stdin = .ignore }) catch return false;
    const term = child.wait(io) catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// path, read to its end: procfs reports a size of 0, so not readFileAlloc.
fn readAll(io: Io, gpa: Allocator, path: []const u8) []const u8 {
    var f = Dir.cwd().openFile(io, path, .{}) catch return "";
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.readerStreaming(io, &buf);
    return r.interface.allocRemaining(gpa, .limited(1 << 20)) catch "";
}

fn say(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "bite-cleanup: " ++ fmt ++ "\n", args) catch return;
    _ = linux.write(1, line.ptr, line.len);
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(
        &buf,
        "bite-cleanup: " ++ fmt ++ "\n",
        args,
    ) catch "bite-cleanup: failed\n";
    _ = linux.write(2, line.ptr, line.len);
    std.process.exit(1);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test parseCmdline {
    const c = parseCmdline(
        "console=hvc0 werewolf.victim=0e7e1f00-c4ec:/var/lib/werewolf werewolf.grubenv=0e7e1f00-" ++
            "c4ec:/boot/grub/grubenv werewolf.slot=a\n",
    ).?;
    try testing.expectEqualStrings("0e7e1f00-c4ec", c.victim.uuid);
    try testing.expectEqualStrings("/var/lib/werewolf", c.victim.path);
    try testing.expectEqualStrings("/boot/grub/grubenv", c.grubenv.path);
    try testing.expect(parseCmdline("werewolf.victim=ab:/var/lib/werewolf") == null);
    try testing.expect(parseCmdline("werewolf.victim=ab:/x werewolf.grubenv=ab:/../etc/x") == null);
    try testing.expect(parseCmdline("werewolf.victim=ab:/ werewolf.grubenv=ab:/b/g") == null);
    try testing.expect(parseCmdline("werewolf.victim=ab:x werewolf.grubenv=ab:/b/g") == null);
    try testing.expect(parseCmdline("werewolf.victim=a/b:/x werewolf.grubenv=ab:/b/g") == null);
    try testing.expect(parseCmdline("werewolf.victim=ab:/x//y werewolf.grubenv=ab:/b/g") == null);
}

test isCommitted {
    try testing.expect(isCommitted("# GRUB Environment Block\nsaved_entry=werewolf-b\n####"));
    try testing.expect(
        !isCommitted("# GRUB Environment Block\nnext_entry=werewolf-a\nsaved_entry=0\n####"),
    );
    try testing.expect(!isCommitted("saved_entry=werewolf-ab\n"));
    try testing.expect(!isCommitted(""));
}

test keeps {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const same = parseCmdline(
        "werewolf.victim=ab:/var/lib/werewolf werewolf.grubenv=ab:/boot/grub/grubenv",
    ).?;
    const k = try keeps(arena.allocator(), same);
    try testing.expectEqual(2, k.len);
    try testing.expectEqualStrings("/boot", k[1]);
    // Fedora: the root subvolume, and /boot a filesystem of its own.
    const apart = parseCmdline(
        "werewolf.victim=ab:/root/var/lib/werewolf werewolf.grubenv=cd:/grub2/grubenv",
    ).?;
    try testing.expectEqual(1, (try keeps(arena.allocator(), apart)).len);
}

test fate {
    const keep = [_][]const u8{ "/var/lib/werewolf", "/boot" };
    try testing.expectEqual(Fate.keep, fate("/boot", &keep));
    try testing.expectEqual(Fate.keep, fate("/var/lib/werewolf", &keep));
    try testing.expectEqual(Fate.descend, fate("/var", &keep));
    try testing.expectEqual(Fate.descend, fate("/var/lib", &keep));
    try testing.expectEqual(Fate.delete, fate("/var/lib/werewolf2", &keep));
    try testing.expectEqual(Fate.delete, fate("/var/li", &keep));
    try testing.expectEqual(Fate.delete, fate("/bootx", &keep));
    try testing.expectEqual(Fate.delete, fate("/etc", &keep));
}
