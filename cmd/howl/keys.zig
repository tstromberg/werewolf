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

pub fn currentUserName(io: Io, gpa: Allocator, why: *howl.Why) ![]const u8 {
    const result = try std.process.run(gpa, io, .{ .argv = &.{ "id", "-un" } });
    const name = mem.trim(u8, result.stdout, " \r\n");
    if (result.term != .exited or result.term.exited != 0 or name.len == 0)
        return why.refuse("cannot determine local user", .{});
    return name;
}

/// Provision a normal login from the caller's public keys. Explicit accounts
/// remain authoritative; Lima already provisions its login through NoCloud.
pub fn addCurrentUser(
    io: Io,
    gpa: Allocator,
    iface: howl.Interface,
    o: howl.Options,
    entries: []const howl.Entry,
    why: *howl.Why,
) ![]const howl.Entry {
    const users_index: ?usize = for (entries, 0..) |entry, n| {
        if (mem.eql(u8, entry.path, "users")) break n;
    } else null;
    const declared = iface.people_defined or iface.people.len > 0 or users_index != null;
    if (!try wantsCurrentUser(o, declared, why)) return entries;
    const key_files = if (@import("boot-config.zig").forForm(o.form)) |definition| blk: {
        if (definition.ssh == .disabled) {
            if (o.add_current_user == .yes) return why.refuse("{s} does not run SSH", .{o.form});
            return entries;
        }
        break :blk definition.ssh == .files;
    } else blk: {
        const chain = try howl.chain(io, gpa, o.form, why);
        if (!forms.runsSshd(chain)) {
            if (o.add_current_user == .yes) return why.refuse("{s} does not run SSH", .{o.form});
            return entries;
        }
        break :blk try forms.takesKeyFiles(gpa, chain);
    };
    const name = try currentUserName(io, gpa, why);
    const found: ?[]const []const u8 = if (howl.environ.get("HOME")) |home|
        (try usable(io, gpa, try std.fs.path.join(gpa, &.{ home, ".ssh" }), key_files)).lines
    else
        null;
    const existing = if (users_index) |n| entries[n].data else "";
    const users = try withCurrentUser(gpa, o, existing, name, found, key_files, why) orelse
        return entries;
    var result: std.ArrayList(howl.Entry) = .empty;
    try result.appendSlice(gpa, entries);
    const entry: howl.Entry = .{ .path = "users", .data = users, .from = "--add-current-user" };
    if (users_index) |n| result.items[n] = entry else try result.append(gpa, entry);
    mem.sortUnstable(howl.Entry, result.items, {}, struct {
        fn less(_: void, a: howl.Entry, b: howl.Entry) bool {
            return mem.lessThan(u8, a.path, b.path);
        }
    }.less);
    return result.items;
}

/// wantsCurrentUser decides, before howl asks who is running it, whether
/// o's machine may get that person's account. auto adds one only for a
/// target and where no account is declared; developer SSH is root's alone.
fn wantsCurrentUser(o: howl.Options, declared: bool, why: *howl.Why) !bool {
    if (o.add_current_user == .no or o.on == .lima or
        (o.on == null and o.add_current_user == .auto)) return false;
    if (o.dev) {
        if (o.add_current_user == .yes) return why.refuse(
            "--add-current-user=yes requires normal SSH; developer SSH only accepts root",
            .{},
        );
        return false;
    }
    return o.add_current_user == .yes or !declared;
}

/// withCurrentUser returns the users file existing with an account for name
/// holding found, the public keys the form's sshd takes from ~/.ssh (null
/// without HOME), or null to leave the file as it is: root, a declared
/// account, or under auto no key. yes refuses where auto gives up.
fn withCurrentUser(
    gpa: Allocator,
    o: howl.Options,
    existing: []const u8,
    name: []const u8,
    found: ?[]const []const u8,
    key_files: bool,
    why: *howl.Why,
) !?[]const u8 {
    if (mem.eql(u8, name, "root")) {
        if (o.add_current_user == .yes)
            return why.refuse("root is not a standard user; declare a named account in users", .{});
        return null;
    }
    if (!@import("people").isName(name))
        return why.refuse(
            "{s}: local username is not a supported guest account; declare users or use " ++
                "--add-current-user=no",
            .{name},
        );
    var lines = mem.splitScalar(u8, existing, '\n');
    while (lines.next()) |line| {
        var words = mem.tokenizeAny(u8, line, " \t\r");
        if (mem.eql(u8, words.next() orelse continue, name)) return null;
    }
    const keys = found orelse return why.refuse("HOME is unset; cannot find local SSH keys", .{});
    if (keys.len == 0) {
        if (o.add_current_user == .yes)
            return why.refuse("{s}: no local public SSH keys accepted by {s}", .{ name, o.form });
        return null;
    }
    const public = try gpa.alloc([]const u8, keys.len);
    for (keys, public) |line, *key| key.* = mem.trimEnd(u8, line, "\n");
    var reason: []const u8 = "";
    sshd.peopleKeys(
        gpa,
        &.{.{ .name = name, .keys = public, .destinations = &.{} }},
        key_files,
        &reason,
    ) catch |err| switch (err) {
        error.Invalid => return why.refuse("{s}", .{reason}),
        else => return err,
    };
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(gpa, existing);
    if (existing.len > 0 and existing[existing.len - 1] != '\n') try text.append(gpa, '\n');
    for (public) |key| try text.print(gpa, "{s} {s}\n", .{ name, key });
    return text.items;
}

/// devPrivatePath is the private key Howl uses for local developer VMs.
pub fn devPrivatePath(io: Io, gpa: Allocator) ![]const u8 {
    const dir = try howl.keysDir(io, gpa, "dev", "build/keys/dev");
    return gpa.print("{s}/ssh-ed25519", .{dir});
}

/// devPublic makes Howl's local developer key once and returns its public
/// half for the VM's root authorized_keys.
pub fn devPublic(io: Io, gpa: Allocator) ![]const u8 {
    const path = try devPrivatePath(io, gpa);
    const pub_path = try gpa.print("{s}.pub", .{path});
    if (!exists(io, path)) {
        const made = try std.process.run(gpa, io, .{ .argv = &.{
            "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "howl dev", "-f", path,
        } });
        if (made.term != .exited or made.term.exited != 0) return error.DevKeygenFailed;
    }
    if (!exists(io, pub_path)) {
        const derived = try std.process.run(gpa, io, .{ .argv = &.{
            "/usr/bin/ssh-keygen", "-y", "-f", path,
        } });
        if (derived.term != .exited or derived.term.exited != 0) return error.DevKeyUnreadable;
        try Dir.cwd().writeFile(io, .{ .sub_path = pub_path, .data = derived.stdout });
    }
    const public_key = try Dir.cwd().readFileAlloc(io, pub_path, gpa, .limited(16 << 10));
    return try gpa.dupe(u8, public_key);
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// offer returns root's authorized_keys for machine name: the keys in
/// ~/.ssh the chain's sshd takes, security keys unless it takes key files
/// too, once the person agrees, or at once when yes (--yes, or a machine
/// here). It returns null, saying why, when there are none or the person
/// declines; a machine with no key still boots, reached by console.
pub fn offer(
    io: Io,
    gpa: Allocator,
    chain: []const forms.Form,
    name: []const u8,
    yes: bool,
    announce: bool,
) !?[]const u8 {
    if (!forms.runsSshd(chain)) return null;
    const key_files = forms.takesKeyFiles(gpa, chain) catch false;
    return offerFor(io, gpa, key_files, name, yes, announce);
}

pub fn offerFor(
    io: Io,
    gpa: Allocator,
    key_files: bool,
    name: []const u8,
    yes: bool,
    announce: bool,
) !?[]const u8 {
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
    if (announce) howl.say(io, "root on {s} takes {s}", .{ name, files });
    return try mem.concat(gpa, u8, found.lines);
}

/// Usable is the public keys found: each one's line, and its file's name.
const Usable = struct { lines: []const []const u8, files: []const []const u8 };

/// securityIdentities returns the private keys in dir whose public halves
/// are security keys: only local FIDO credentials enter the automatically
/// forwarded agent. A public key without its private credential stub cannot
/// be loaded.
pub fn securityIdentities(io: Io, gpa: Allocator, dir: []const u8) ![]const []const u8 {
    const found = try usable(io, gpa, dir, false);
    var paths: std.ArrayList([]const u8) = .empty;
    for (found.files) |public| {
        const private = try std.fs.path.join(gpa, &.{ dir, public[0 .. public.len - 4] });
        const path = Dir.cwd().realPathFileAlloc(io, private, gpa) catch continue;
        try paths.append(gpa, path);
    }
    return paths.items;
}

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

const security_key = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5 fixture";
const software_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 fixture";

test "the local account goes only where a machine's login can use it" {
    var why: howl.Why = .{};
    // auto adds it on every target but Lima, which provisions its own login.
    for ([_]howl.Platform{ .qemu, .firecracker, .bhyve, .proxmox, .gcp, .aws, .azure }) |on|
        try testing.expect(try wantsCurrentUser(.{ .on = on }, false, &why));
    for ([_]@FieldType(howl.Options, "add_current_user"){ .auto, .yes, .no }) |mode|
        try testing.expect(!try wantsCurrentUser(
            .{ .on = .lima, .add_current_user = mode },
            false,
            &why,
        ));
    try testing.expect(!try wantsCurrentUser(
        .{ .on = .qemu, .add_current_user = .no },
        false,
        &why,
    ));
    // pack without a target adds it only when asked.
    try testing.expect(!try wantsCurrentUser(.{}, false, &why));
    try testing.expect(try wantsCurrentUser(.{ .add_current_user = .yes }, false, &why));
    // A declared account, even an empty users map, disables auto, not yes.
    try testing.expect(!try wantsCurrentUser(.{ .on = .qemu }, true, &why));
    try testing.expect(try wantsCurrentUser(
        .{ .on = .qemu, .add_current_user = .yes },
        true,
        &why,
    ));
    try testing.expect(!try wantsCurrentUser(.{ .on = .qemu, .dev = true }, false, &why));
    try testing.expectError(error.Refused, wantsCurrentUser(
        .{ .on = .qemu, .dev = true, .add_current_user = .yes },
        false,
        &why,
    ));
}

test "the local account takes the keys found, beside the accounts declared" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: howl.Why = .{};
    const auto: howl.Options = .{ .form = "playground", .on = .qemu };
    var yes = auto;
    yes.add_current_user = .yes;
    const both: []const []const u8 = &.{ security_key ++ "\n", software_key ++ "\n" };
    const added = "alice " ++ security_key ++ "\nalice " ++ software_key ++ "\n";
    try testing.expectEqualStrings(
        added,
        (try withCurrentUser(gpa, auto, "", "alice", both, true, &why)).?,
    );
    // No account is generated with an implicit admin grant.
    try testing.expect(mem.find(u8, added, "admin") == null);
    const bob = "bob " ++ security_key;
    try testing.expectEqualStrings(
        bob ++ "\n" ++ added,
        (try withCurrentUser(gpa, yes, bob, "alice", both, true, &why)).?,
    );
    // An account declared under the local name wins, with or without keys.
    try testing.expect(try withCurrentUser(gpa, yes, "alice\n", "alice", both, true, &why) == null);
    try testing.expect(try withCurrentUser(gpa, auto, "alice", "alice", null, true, &why) == null);
    // Root is no standard user; yes says so.
    try testing.expect(try withCurrentUser(gpa, auto, "", "root", both, true, &why) == null);
    try testing.expectError(error.Refused, withCurrentUser(gpa, yes, "", "root", both, true, &why));
    try testing.expectError(
        error.Refused,
        withCurrentUser(gpa, auto, "", "Alice", both, true, &why),
    );
    try testing.expectError(
        error.Refused,
        withCurrentUser(gpa, auto, "", "alice", null, true, &why),
    );
    // No key the form's sshd takes: auto gives up, yes refuses.
    try testing.expect(try withCurrentUser(gpa, auto, "", "alice", &.{}, false, &why) == null);
    try testing.expectError(
        error.Refused,
        withCurrentUser(gpa, yes, "", "alice", &.{}, false, &why),
    );
    try testing.expect(mem.find(u8, why.text, "no local public SSH keys") != null);
    // A key file where only security keys are taken is refused, not added.
    try testing.expectError(
        error.Refused,
        withCurrentUser(gpa, auto, "", "alice", both, false, &why),
    );
}

test "local keys follow the form's policy, and the agent takes only FIDO credentials" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][2][]const u8{
        .{ "fido", security_key },
        .{ "software", software_key },
        .{ "orphan", "sk-ecdsa-sha2-nistp256@openssh.com AAAA orphan" },
    }) |key| {
        try tmp.dir.writeFile(
            io,
            .{ .sub_path = try gpa.print("{s}.pub", .{key[0]}), .data = key[1] },
        );
        if (!mem.eql(u8, key[0], "orphan"))
            try tmp.dir.writeFile(io, .{ .sub_path = key[0], .data = "private stub" });
    }
    const dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const fido = try usable(io, gpa, dir, false);
    try testing.expectEqualStrings("fido.pub orphan.pub", try mem.join(gpa, " ", fido.files));
    const all = try usable(io, gpa, dir, true);
    try testing.expectEqualStrings(
        "fido.pub orphan.pub software.pub",
        try mem.join(gpa, " ", all.files),
    );
    try testing.expectEqualStrings(security_key ++ "\n", all.lines[0]);
    const agent = try securityIdentities(io, gpa, dir);
    try testing.expectEqual(1, agent.len);
    try testing.expectEqualStrings(try std.fs.path.join(gpa, &.{ dir, "fido" }), agent[0]);
}

test "--add-current-user takes auto, yes or no, once" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: howl.Why = .{};
    const o = try howl.options(gpa, &.{ "playground", "--add-current-user", "yes" }, &why);
    try testing.expectEqual(.yes, o.add_current_user);
    try testing.expectError(
        error.Refused,
        howl.options(gpa, &.{ "playground", "--add-current-user=maybe" }, &why),
    );
    try testing.expect(mem.find(u8, why.text, "auto, yes or no") != null);
    try testing.expectError(error.Refused, howl.options(
        gpa,
        &.{ "playground", "--add-current-user=auto", "--add-current-user=no" },
        &why,
    ));
    try testing.expect(mem.find(u8, why.text, "given twice") != null);
}
