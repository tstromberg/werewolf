//! bite-cleanup deletes the distro bite took over, once werewolf is GRUB's
//! default. See README.md and docs/bite.md.
//!
//!     bite-cleanup        delete it
//!     bite-cleanup -n     show what would go; change nothing

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const broker = @import("broker");
const sandbox = @import("sandbox");
const cmdline = @import("cmdline");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    const dry = args.len == 2 and std.mem.eql(u8, args[1], "-n");
    if (args.len != 1 and !dry) fail("usage: bite-cleanup [-n]", .{});
    if (linux.geteuid() != 0) fail("run as root", .{});

    var refused: cmdline.Failure = .{};
    const line = cmdline.parse(readAll(io, gpa, "/proc/cmdline"), &refused) orelse
        fail("the command line's {s}: {s}; deleting nothing", .{ refused.word, refused.why });
    const cmd: Bitten = .{
        .victim = line.victim orelse fail("this machine was not bitten", .{}),
        .grubenv = line.grubenv orelse fail("this machine was not bitten", .{}),
        .slot = line.slot orelse fail("this machine was not bitten", .{}),
    };
    const p = plan(gpa, cmd) catch |err|
        fail("cannot tell what to keep: {s}; deleting nothing", .{@errorName(err)});

    // Before commit, a reset still boots the distro, so it must stay.
    const grub = ask(.grub);
    var block_buf: [4096]u8 = undefined;
    const block = readBlock(grub.path(), cmd.grubenv.path, &block_buf);
    grub.release();
    if (!isCommitted(block)) fail(
        "werewolf is not yet GRUB's default; the distro is still its fallback",
        .{},
    );

    const victim = ask(.victim);
    defer victim.release();
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) fail("cannot fork: {t}", .{linux.errno(pid)});
    if (pid == 0) prune(io, gpa, victim.path(), p, dry);
    var status: i32 = 0;
    while (linux.errno(linux.waitpid(@intCast(pid), &status, 0)) == .INTR) {}
    linux.sync();
    const s: u32 = @bitCast(status);
    const code = if (linux.W.IFEXITED(s)) linux.W.EXITSTATUS(s) else 255;
    if (code != 0 and code != partial) fail("deleting stopped; see above", .{});
    if (!dry) {
        if (!trim(victim.path()))
            say("trim not available here; the blocks are freed, not handed back", .{});
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
    if (code == partial) fail("some of the distro stays; see above", .{});
}

/// partial is the child's exit code when it deleted all it could, but some
/// entries stay.
const partial = 3;

/// prune runs in the child. It checks that every needed file is beneath dir
/// through no link, confines itself, then deletes everything not kept. A
/// layout it misreads must leave the distro, not take werewolf with it.
fn prune(io: Io, gpa: Allocator, dir: []const u8, p: Plan, dry: bool) noreturn {
    const root = Dir.cwd().openDir(
        io,
        dir,
        .{ .iterate = true, .follow_symlinks = false },
    ) catch |err|
        fail("{s}: {s}", .{ dir, @errorName(err) });
    for (p.need) |n| {
        const fd = openBeneath(root.handle, n, .{ .PATH = true }) orelse fail(
            "{s} is not on the victim's filesystem, or is reached through a link; deleting nothing",
            .{n},
        );
        _ = linux.close(fd);
    }
    confine(root.handle) catch fail(
        "cannot confine the deleting: {s} {s}",
        .{ sandbox.failed, sandbox.errnoName(sandbox.failed_errno) },
    );
    var t: Tally = .{};
    walk(io, gpa, root, "", p.keep, dry, &t) catch |err| fail("{s}", .{@errorName(err)});
    const kept = std.mem.join(gpa, " ", p.keep) catch "";
    if (dry)
        say("-n: would delete {d} entries, keeping {s}; nothing changed", .{ t.deleted, kept })
    else
        say("deleted {d} entries of the distro, keeping {s}", .{ t.deleted, kept });
    if (t.left > 0) {
        say("{d} entries may not be deleted and stay, named above", .{t.left});
        std.process.exit(partial);
    }
    std.process.exit(0);
}

/// Tally counts the trees the walk deleted (each counted at its top) and
/// the entries it was not allowed to delete.
const Tally = struct { deleted: usize = 0, left: usize = 0 };

/// walk deletes everything in dir (at path from the filesystem's root) that
/// is neither kept nor above something kept. Symlinks are deleted, never
/// followed.
fn walk(
    io: Io,
    gpa: Allocator,
    dir: Dir,
    path: []const u8,
    keep: []const []const u8,
    dry: bool,
    t: *Tally,
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
                try walk(io, gpa, sub, p, keep, dry, t);
            },
            .delete => {
                t.deleted += 1;
                if (dry) {
                    say("would delete {s}", .{p});
                } else dir.deleteTree(io, e.name) catch |err| switch (err) {
                    error.AccessDenied, error.PermissionDenied => t.left += try salvage(
                        io,
                        gpa,
                        dir,
                        e.name,
                        p,
                        0,
                    ),
                    else => return err,
                };
            },
        }
    }
}

/// salvage deletes all it can of name, in dir at path, and logs and counts
/// what stays. deleteTree stops at the first entry it may not delete, such
/// as an immutable or append-only file (chattr +i, +a) that some cloud
/// agents leave as /etc/resolv.conf. It recurses only toward such entries,
/// and never past max_depth.
fn salvage(
    io: Io,
    gpa: Allocator,
    dir: Dir,
    name: []const u8,
    path: []const u8,
    depth: usize,
) !usize {
    var sub = dir.openDir(io, name, .{ .iterate = true, .follow_symlinks = false }) catch |err|
        switch (err) {
            error.NotDir, error.SymLinkLoop => {
                say("{s} stays: it may not be deleted (immutable or append-only)", .{path});
                return 1;
            },
            else => return err,
        };
    defer sub.close(io);
    if (depth == max_depth) {
        say("{s} stays: what may not be deleted lies deeper than {d}", .{ path, max_depth });
        return 1;
    }
    var left: usize = 0;
    var it = sub.iterate();
    while (try it.next(io)) |e| {
        const p = try gpa.print("{s}/{s}", .{ path, e.name });
        sub.deleteTree(io, e.name) catch |err| switch (err) {
            error.AccessDenied, error.PermissionDenied => left += try salvage(
                io,
                gpa,
                sub,
                e.name,
                p,
                depth + 1,
            ),
            else => return err,
        };
    }
    if (left > 0) return left;
    dir.deleteDir(io, name) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => {
            say("{s} stays: it may not be deleted (immutable or append-only)", .{path});
            return 1;
        },
        else => return err,
    };
    return 0;
}

const max_depth = 256;

const Fate = enum { keep, descend, delete };

/// fate decides what walk does with path. A kept path stays whole even if
/// another kept path lies beneath it, so every keep is matched before any
/// is descended toward.
fn fate(path: []const u8, keep: []const []const u8) Fate {
    for (keep) |k| if (std.mem.eql(u8, k, path)) return .keep;
    for (keep) |k| {
        if (k.len > path.len and std.mem.startsWith(u8, k, path) and
            k[path.len] == '/') return .descend;
    }
    return .delete;
}

/// Plan lists what stays, and what must be found in it before anything goes.
const Plan = struct { keep: []const []const u8, need: []const []const u8 };

/// plan keeps werewolf's directory, which must hold the running slot's
/// root.erofs. If GRUB's environment block is on the same filesystem, it
/// also keeps the directory above GRUB's (/boot), which must hold the slot's
/// kernel in werewolf/. On btrfs that may be in a subvolume (/@/boot), so it
/// is derived from the block's path, not assumed.
fn plan(gpa: Allocator, cmd: Bitten) !Plan {
    var keep: std.ArrayList([]const u8) = .empty;
    var need: std.ArrayList([]const u8) = .empty;
    const slot = @tagName(cmd.slot);
    try keep.append(gpa, cmd.victim.path);
    try need.append(gpa, try gpa.print("{s}/{s}/root.erofs", .{ cmd.victim.path, slot }));
    // Compare the UUIDs' bytes, so letter case does not matter.
    if (std.mem.eql(u8, &cmdline.uuid(cmd.victim.uuid).?, &cmdline.uuid(cmd.grubenv.uuid).?)) {
        const grub = std.fs.path.dirnamePosix(cmd.grubenv.path) orelse "/";
        const boot = std.fs.path.dirnamePosix(grub) orelse "/";
        if (std.mem.eql(u8, boot, "/")) return error.GrubNotBeneathBoot;
        try keep.append(gpa, boot);
        try need.append(gpa, try gpa.print("{s}/werewolf/{s}/vmlinuz", .{ boot, slot }));
    }
    return .{ .keep = keep.items, .need = need.items };
}

/// isCommitted reports whether GRUB's block has werewolf as its saved default.
fn isCommitted(block: []const u8) bool {
    var it = std.mem.splitScalar(u8, block, '\n');
    while (it.next()) |line| {
        if (std.mem.eql(u8, line, "saved_entry=werewolf-a") or
            std.mem.eql(u8, line, "saved_entry=werewolf-b")) return true;
    }
    return false;
}

/// Bitten holds the words bite left on the command line: werewolf.victim,
/// werewolf.grubenv and werewolf.slot (lib/cmdline.zig).
const Bitten = struct { victim: cmdline.Place, grubenv: cmdline.Place, slot: cmdline.Slot };

// --- confinement -------------------------------------------------------------

const cap_dac_override = 1;
const cap_fowner = 3;

/// confine leaves the process able only to delete beneath root. It keeps
/// DAC_OVERRIDE (past file modes, including directory search) and FOWNER
/// (for sticky directories such as /tmp); Landlock allows only reading
/// directories and removing, beneath root; seccomp kills any call the walk
/// does not make.
fn confine(root: linux.fd_t) !void {
    try sandbox.keepOnly(1 << cap_dac_override | 1 << cap_fowner);
    try sandbox.landlock(&.{.{
        .fd = root,
        .access = sandbox.read_dir | sandbox.remove_dir | sandbox.remove_file,
    }}, &.{});
    var f: sandbox.Filter = .{};
    inline for (.{
        "openat", "getdents64", "lseek", "unlinkat", "newfstatat", "fstatat64",
        "close",  "write",      "mmap",  "munmap",   "mremap",     "exit_group",
    }) |name| f.allow(name);
    try f.install();
}

// --- the rest ----------------------------------------------------------------

/// ask mounts word's filesystem through the mount broker. If another
/// asker holds it (slot-keep holds GRUB's briefly at commit), it retries
/// once a second later.
fn ask(word: broker.Word) broker.Held {
    for (0..2) |i| {
        if (broker.ask(word)) |h| return h else |err| {
            if (i == 0 and err == error.Refused and
                std.mem.startsWith(u8, broker.refusal, "no busy"))
            {
                _ = linux.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);
                continue;
            }
            fail("cannot mount {s}: {s} {s}", .{ @tagName(word), @errorName(err), broker.refusal });
        }
    }
    unreachable;
}

/// openMount opens the broker's mount at dir as a directory.
fn openMount(dir: []const u8) ?i32 {
    var buf: [128]u8 = undefined;
    const z = std.mem.print(&buf, "{s}\x00", .{dir}) catch return null;
    const rc = linux.open(
        @ptrCast(z.ptr),
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

/// openBeneath opens path relative to dir (a leading / means dir), through
/// no symlink and never above dir (openat2).
fn openBeneath(dir: i32, path: []const u8, flags: linux.O) ?i32 {
    var buf: [512]u8 = undefined;
    const z = std.mem.print(&buf, "{s}\x00", .{std.mem.trimStart(u8, path, "/")}) catch
        return null;
    var o = flags;
    o.CLOEXEC = true;
    const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };
    const RESOLVE_NO_MAGICLINKS = 0x02;
    const RESOLVE_NO_SYMLINKS = 0x04;
    const RESOLVE_BENEATH = 0x08;
    var how: OpenHow = .{
        .flags = @as(u32, @bitCast(o)),
        .mode = 0,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    const rc = linux.syscall4(
        .openat2,
        @bitCast(@as(isize, dir)),
        @intFromPtr(z.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    );
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

/// readBlock returns GRUB's environment block at path on the filesystem at
/// dir, or "" if it is missing, reached through a link, or larger than buf
/// (GRUB's is 1 KiB). It opens non-blocking in case it is a FIFO.
fn readBlock(dir: []const u8, path: []const u8, buf: []u8) []const u8 {
    const d = openMount(dir) orelse return "";
    defer _ = linux.close(d);
    const fd = openBeneath(d, path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true }) orelse return "";
    defer _ = linux.close(fd);
    var n: usize = 0;
    while (n < buf.len) {
        const rc = linux.read(fd, buf[n..].ptr, buf.len - n);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) return buf[0..n] else {
                n += rc;
            },
            .INTR => {},
            else => return "",
        }
    }
    return "";
}

/// trim hands the free blocks of the filesystem at dir back to the disk
/// (FITRIM), so a thin cloud volume no longer holds them. It returns false
/// if the filesystem or the disk cannot.
fn trim(dir: []const u8) bool {
    const fd = openMount(dir) orelse return false;
    defer _ = linux.close(fd);
    // struct fstrim_range: start, len, minlen; the whole filesystem.
    var range = [3]u64{ 0, std.math.maxInt(u64), 0 };
    const FITRIM = 0xc0185879; // _IOWR('X', 121, struct fstrim_range)
    return linux.errno(linux.ioctl(fd, FITRIM, @intFromPtr(&range))) == .SUCCESS;
}

/// readAll returns path's contents, up to 1 MiB. It streams because procfs
/// reports a size of 0.
fn readAll(io: Io, gpa: Allocator, path: []const u8) []const u8 {
    var f = Dir.cwd().openFile(io, path, .{}) catch return "";
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.readerStreaming(io, &buf);
    return r.interface.allocRemaining(gpa, .limited(1 << 20)) catch "";
}

/// say writes one line to stdout, the console log. Names in it come from
/// the distro's disk, so each control byte becomes "?", and none can carry
/// an escape sequence or a false line to the console.
fn say(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "bite-cleanup: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
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

test isCommitted {
    try testing.expect(isCommitted("# GRUB Environment Block\nsaved_entry=werewolf-b\n####"));
    try testing.expect(
        !isCommitted("# GRUB Environment Block\nnext_entry=werewolf-a\nsaved_entry=0\n####"),
    );
    try testing.expect(!isCommitted("saved_entry=werewolf-ab\n"));
    try testing.expect(!isCommitted(""));
}

/// bitten parses a command line bite leaves, as main does.
fn bitten(text: []const u8) !Bitten {
    var refused: cmdline.Failure = .{};
    const c = cmdline.parse(text, &refused) orelse return error.Refused;
    return .{ .victim = c.victim.?, .grubenv = c.grubenv.?, .slot = c.slot.? };
}

const ab = "57e1f000-77e2-4b0f-8a3c-0000000000ab";
const cd = "57E1F000-77E2-4B0F-8A3C-0000000000CD";

test plan {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Debian: GRUB and werewolf's kernels in /boot, on the root filesystem.
    const debian = try plan(a, try bitten(
        "werewolf.victim=" ++ ab ++ ":/var/lib/werewolf werewolf.grubenv=" ++ ab ++
            ":/boot/grub/grubenv werewolf.slot=a",
    ));
    try testing.expectEqual(2, debian.keep.len);
    try testing.expectEqualStrings("/boot", debian.keep[1]);
    try testing.expectEqualStrings("/var/lib/werewolf/a/root.erofs", debian.need[0]);
    try testing.expectEqualStrings("/boot/werewolf/a/vmlinuz", debian.need[1]);
    // The same filesystem, its UUID written in capitals.
    const upper = try plan(a, try bitten(
        "werewolf.victim=" ++ ab ++ ":/var/lib/werewolf werewolf.grubenv=" ++
            "57E1F000-77E2-4B0F-8A3C-0000000000AB:/boot/grub/grubenv werewolf.slot=a",
    ));
    try testing.expectEqual(2, upper.keep.len);
    // Fedora: the root subvolume, and /boot a filesystem of its own.
    const apart = try plan(a, try bitten(
        "werewolf.victim=" ++ ab ++ ":/root/var/lib/werewolf werewolf.grubenv=" ++ cd ++
            ":/grub2/grubenv werewolf.slot=b",
    ));
    try testing.expectEqual(1, apart.keep.len);
    try testing.expectEqual(1, apart.need.len);
    try testing.expectEqualStrings("/root/var/lib/werewolf/b/root.erofs", apart.need[0]);
    // Ubuntu on btrfs: /boot in the root subvolume, @, beside everything
    // else of the distro. Keeping @ whole would delete none of it.
    const btrfs = try plan(a, try bitten(
        "werewolf.victim=" ++ ab ++ ":/@/var/lib/werewolf werewolf.grubenv=" ++ ab ++
            ":/@/boot/grub/grubenv werewolf.slot=a",
    ));
    try testing.expectEqualStrings("/@/boot", btrfs.keep[1]);
    try testing.expectEqualStrings("/@/boot/werewolf/a/vmlinuz", btrfs.need[1]);
    try testing.expectEqual(Fate.descend, fate("/@", btrfs.keep));
    try testing.expectEqual(Fate.delete, fate("/@/etc", btrfs.keep));
    try testing.expectEqual(Fate.keep, fate("/@/boot", btrfs.keep));
    // GRUB's directory at the top of the filesystem it shares: no /boot to
    // keep, and keeping / would delete nothing.
    try testing.expectError(error.GrubNotBeneathBoot, plan(a, try bitten(
        "werewolf.victim=" ++ ab ++ ":/var/lib/werewolf werewolf.grubenv=" ++ ab ++
            ":/grub/grubenv werewolf.slot=a",
    )));
    try testing.expectError(error.GrubNotBeneathBoot, plan(a, try bitten(
        "werewolf.victim=" ++ ab ++ ":/var/lib/werewolf werewolf.grubenv=" ++ ab ++
            ":/grubenv werewolf.slot=a",
    )));
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
    // One kept above another is kept, whichever comes first.
    const nested = [_][]const u8{ "/a/b/c", "/a" };
    try testing.expectEqual(Fate.keep, fate("/a", &nested));
}
