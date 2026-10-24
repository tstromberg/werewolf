//! Linux integration probe for the durable account table and retained homes.
//! Build for Linux with `--dep people -Mroot=test/people-ledger.zig
//! -Mpeople=lib/people.zig`. Run as root with only CAP_CHOWN and a disposable
//! parent directory as argv[1]; the caller removes that directory afterward.
const std = @import("std");
const linux = std.os.linux;
const people = @import("people");

fn ok(condition: bool) !void {
    if (!condition) return error.IntegrationCheckFailed;
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.page_allocator;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 2) return error.ExpectedDisposableParent;
    const data = try gpa.printSentinel("{s}/data", .{args[1]}, 0);
    try ok(linux.errno(linux.mkdir(data, 0o700)) == .SUCCESS);
    const opened = linux.open(data, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    try ok(linux.errno(opened) == .SUCCESS);
    const data_fd: i32 = @intCast(opened);
    defer _ = linux.close(data_fd);

    try ok(linux.errno(linux.fchmod(data_fd, 0o777)) == .SUCCESS);
    try std.testing.expectError(error.DataDirectory, people.openLedgerDir(data_fd));
    try ok(linux.errno(linux.fchmod(data_fd, 0o700)) == .SUCCESS);

    const ledger = try people.openLedgerDir(data_fd);
    defer _ = linux.close(ledger);
    try ok(try people.freshData(data_fd));
    const rows = [_]people.Identity{.{ .source = .people, .name = "alice", .id = people.userId("alice") }};
    try people.commitLedger(gpa, ledger, &rows);
    try ok(!(try people.freshData(data_fd)));
    const loaded = try people.loadLedger(gpa, ledger);
    try ok(loaded.len == 1 and loaded[0].id == rows[0].id);
    const homes = try people.openHomeDir(data_fd);
    defer _ = linux.close(homes);
    const keys = [_]people.Keys{.{ .name = "alice", .text = "", .id = rows[0].id }};
    try people.checkHomes(homes, &keys);
    try people.ensureHomes(homes, &keys);
    try people.checkHomes(homes, &keys);
    const reopen = linux.open(data, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    try ok(linux.errno(reopen) == .SUCCESS);
    const reopened_data: i32 = @intCast(reopen);
    defer _ = linux.close(reopened_data);
    const reopened_ledger = try people.openLedgerDir(reopened_data);
    defer _ = linux.close(reopened_ledger);
    const rebooted = try people.loadLedger(gpa, reopened_ledger);
    const active = try people.applyReserved(gpa, .{
        .passwd = "root:x:0:0::/root:/bin/sh\n",
        .group = "root:x:0:\n",
        .shadow = "root:!:::::::\n",
    }, rebooted, "alice\n", "/bin/ash", null, true);
    try ok(active.identities.len == 1 and active.refused.len == 0);
    try people.checkHomes(homes, active.keys);
    const wrong = [_]people.Keys{.{ .name = "alice", .text = "", .id = rows[0].id + 1 }};
    try std.testing.expectError(error.HomeOwner, people.checkHomes(homes, &wrong));
    try std.testing.expectError(error.HomeOwner, people.ensureHomes(homes, &wrong));
    try people.checkHomes(homes, &keys);
    try ok(linux.errno(linux.symlinkat("/etc", homes, "mallory")) == .SUCCESS);
    const linked = [_]people.Keys{.{ .name = "mallory", .text = "", .id = rows[0].id }};
    try std.testing.expectError(error.HomeOwner, people.checkHomes(homes, &linked));

    // An interrupted write leaves .new behind. The next commit replaces it.
    const stale = linux.openat(ledger, "identities.new", .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .CLOEXEC = true,
    }, 0o600);
    try ok(linux.errno(stale) == .SUCCESS);
    _ = linux.close(@intCast(stale));
    try people.commitLedger(gpa, ledger, &rows);
    try ok((try people.loadLedger(gpa, ledger)).len == 1);

    // O_PATH permits write/rename relative to the directory, but fsync on
    // that FD fails. The renamed rows are visible despite failed durability.
    const path_rc = linux.openat(data_fd, ".werewolf", .{
        .PATH = true,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    try ok(linux.errno(path_rc) == .SUCCESS);
    const path_ledger: i32 = @intCast(path_rc);
    defer _ = linux.close(path_ledger);
    const expanded = [_]people.Identity{
        rows[0], .{ .source = .people, .name = "bob", .id = people.userId("bob") },
    };
    try std.testing.expectError(error.LedgerWrite, people.commitLedger(gpa, path_ledger, &expanded));
    try ok((try people.loadLedger(gpa, ledger)).len == 2);
    try std.testing.expectError(error.LedgerWrite, people.syncLedger(path_ledger));
    try people.syncLedger(ledger);
    try ok((try people.loadLedger(gpa, ledger)).len == 2);

    try ok(linux.errno(linux.fchmodat2(ledger, "identities", 0o644, linux.AT.SYMLINK_NOFOLLOW)) == .SUCCESS);
    try std.testing.expectError(error.BadLedger, people.loadLedger(gpa, ledger));
    try ok(linux.errno(linux.fchmodat2(ledger, "identities", 0o600, linux.AT.SYMLINK_NOFOLLOW)) == .SUCCESS);

    const bad = linux.openat(ledger, "identities", .{
        .ACCMODE = .WRONLY,
        .TRUNC = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    try ok(linux.errno(bad) == .SUCCESS);
    try ok(linux.errno(linux.write(@intCast(bad), "broken".ptr, 6)) == .SUCCESS);
    _ = linux.close(@intCast(bad));
    try std.testing.expectError(error.BadLedger, people.loadLedger(gpa, ledger));
    try ok(linux.errno(linux.unlinkat(ledger, "identities", 0)) == .SUCCESS);
    try ok(linux.errno(linux.symlinkat("/etc/passwd", ledger, "identities")) == .SUCCESS);
    try std.testing.expectError(error.BadLedger, people.loadLedger(gpa, ledger));

    const old = try gpa.printSentinel("{s}/old", .{args[1]}, 0);
    try ok(linux.errno(linux.mkdir(old, 0o700)) == .SUCCESS);
    const old_rc = linux.open(old, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    try ok(linux.errno(old_rc) == .SUCCESS);
    const old_fd: i32 = @intCast(old_rc);
    defer _ = linux.close(old_fd);
    const old_ledger = try people.openLedgerDir(old_fd);
    defer _ = linux.close(old_ledger);
    const marker = linux.openat(old_fd, "service-data", .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .CLOEXEC = true,
    }, 0o600);
    try ok(linux.errno(marker) == .SUCCESS);
    _ = linux.close(@intCast(marker));
    try std.testing.expectError(error.NoLedger, people.loadLedger(gpa, old_ledger));
    try ok(!(try people.freshData(old_fd)));
}
