//! compose derives from a chain of forms everything an image holds beyond
//! its packages. The build and the updater both call it, so a slot built on
//! a machine matches the build's. See lib/README.md.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const allow = @import("allow");
const form = @import("form");
const seal = @import("seal");
const service = @import("service");
const package = @import("package");
const people = @import("people");
pub const baselayout = package.baselayout;

const Form = form.Form;
const Failure = form.Failure;
const Error = form.Error;

pub const Arch = enum { aarch64, x86_64 };

/// Build describes a build beyond its chain.
pub const Build = struct {
    arch: Arch,
    /// dev marks a build for SSH test iteration (howl --dev=ssh): developer
    /// access through sh-shim, with no BusyBox and no console shell.
    dev: bool = false,
    /// ipe makes the image require IPE: stage0 activates its signed release policy.
    ipe: bool = false,
    /// tpm requires the measured release pair and rollback journal at boot.
    tpm: bool = false,
    /// posture_known is test/posture-known: the posture checks every form
    /// of a kind fails.
    posture_known: []const u8 = "",
};

/// records names what compose makes in /usr/share/werewolf. The updater
/// composes these anew and carries every other record forward, so none of
/// these is ever a stale copy.
pub const records = [_][]const u8{
    "age-enforce", "cmdline", "dev",    "etc",           "form",  "forms",      "net",
    "variants",    "oci",     "pledge", "posture-known", "prune", "weaknesses",
};

/// release_forms are the forms CI releases as disks, for both arches
/// (docs/releases.md): for installs; machines update through apk.
pub const release_forms = [_][]const u8{ "minimal", "prod", "prod-ssh" };

/// Accounts holds an image's account files, as its packages leave them.
pub const Accounts = struct { passwd: []const u8, group: []const u8, shadow: []const u8 };

/// Reconstruct a staged development image's injected SSH layer as well as
/// its leaf form. Older development images have no such staged layer.
/// Production reconstruction never adds developer access.
pub fn stagedChain(
    io: Io,
    gpa: Allocator,
    root: Dir,
    leaf: []const u8,
    dev: bool,
    f: *Failure,
) ![]const Form {
    const selection = root.readFileAlloc(
        io,
        "variants",
        gpa,
        .limited(1024),
    ) catch |err| switch (err) {
        error.FileNotFound => "",
        else => return err,
    };
    const text = mem.trim(u8, selection, " \n");
    const selected: []const []const u8 = if (text.len == 0) &.{} else &.{text};
    const forms = try form.chainSelectedIn(io, gpa, root, "forms", leaf, selected, f);
    if (!dev or hasForm(forms, "howl-dev")) return forms;
    root.access(io, "forms/howl-dev/form.yaml", .{}) catch |err| switch (err) {
        error.FileNotFound => return forms,
        else => return err,
    };
    return withDevSsh(gpa, forms, try form.chain(io, gpa, root, "howl-dev", f));
}

/// Add the developer layer before the leaf, reusing accounts the form
/// already declares. The builder and staged reconstruction use the same rule.
pub fn withDevSsh(gpa: Allocator, original: []const Form, layer: []const Form) ![]const Form {
    const access = try gpa.dupe(Form, layer);
    const existing = try form.apko(gpa, original, &.{});
    // Reuse a form's privilege-separation accounts. apko concatenates account
    // lists, so declaring one twice would produce duplicate passwd entries.
    for (access) |*fm| {
        if (!std.mem.eql(u8, fm.name, "howl-dev")) continue;
        const spec = try gpa.dupe(form.Entry, fm.spec.map);
        fm.spec.map = spec;
        for (spec) |*entry| {
            if (!std.mem.eql(u8, entry.key, "accounts")) continue;
            const kinds = try gpa.dupe(form.Entry, entry.value.map);
            entry.value.map = kinds;
            for (kinds) |*kind| {
                const declared = (existing.get(
                    "accounts",
                ) orelse continue).get(kind.key) orelse continue;
                if (declared != .list) continue;
                const field = if (std.mem.eql(u8, kind.key, "users")) "username" else "groupname";
                var needed: std.ArrayList(form.Node) = .empty;
                for (kind.value.list) |candidate| {
                    const name = candidate.get(field).?.scalar.text;
                    const found = for (declared.list) |account| {
                        const have = account.get(field) orelse continue;
                        if (have == .scalar and std.mem.eql(u8, have.scalar.text, name))
                            break true;
                    } else false;
                    if (!found) try needed.append(gpa, candidate);
                }
                kind.value = .{ .list = needed.items };
            }
        }
    }
    var out: std.ArrayList(Form) = .empty;
    const top = original[original.len - 1];
    for (original[0 .. original.len - 1]) |f| try out.append(gpa, f);
    for (access) |f| {
        if (std.mem.eql(u8, f.dir, top.dir)) continue;
        var seen = false;
        for (out.items) |have| if (std.mem.eql(u8, have.dir, f.dir)) {
            seen = true;
            break;
        };
        if (!seen) try out.append(gpa, f);
    }
    try out.append(gpa, top);
    return out.items;
}

/// compose writes what forms derive into two trees. ro is laid over the
/// packages: the forms' rootfs, base first, then the generated files. meta
/// gets werewolf's records in /usr/share/werewolf, with the chain staged for
/// the updater. Form directories resolve under root; image is the account
/// files.
pub fn compose(
    io: Io,
    gpa: Allocator,
    root: Dir,
    forms: []const Form,
    image: Accounts,
    ro: Dir,
    meta: Dir,
    b: Build,
    f: *Failure,
) !void {
    const allowed = try allowances(gpa, forms, f);
    try privileges(io, gpa, root, forms, allowed, b.dev, f);
    const accts = try withAccounts(io, gpa, root, forms, image, f);
    const passwd = accts.passwd;
    const group = accts.group;
    const shadow = accts.shadow;

    // ro: each form's rootfs, base first, so later forms' files win; then
    // the services form.yaml renders, each on a leash: its file, and run
    // and finish links to leash where the rootfs laid none.
    for (forms) |fm| {
        for (fm.images) |dir| try lay(io, gpa, root, dir, ro, "");
        try lay(io, gpa, root, try gpa.print("{s}/rootfs", .{fm.dir}), ro, "");
    }
    for (try form.services(io, gpa, root, forms, f)) |s| {
        if (mem.find(u8, s.path, "form.yaml: services.") == null) continue;
        const dir = try gpa.print("etc/sv/{s}", .{s.name});
        try ro.createDirPath(io, dir);
        try put(io, ro, try gpa.print("{s}/service", .{dir}), s.text);
        for (s.allow) |word| {
            const grant = allow.RuntimeAllowance.parse(word).?;
            const path = try gpa.print("etc/runtime-hardening/allow/{s}/{s}", .{
                s.name, grant.runtime,
            });
            try ro.createDirPath(io, path);
            try put(io, ro, try gpa.print("{s}/{s}", .{ path, grant.name }), "");
        }
        for ([_][2][]const u8{ .{ "run", "leash" }, .{ "finish", "leash-reap" } }) |link| {
            ro.symLink(
                io,
                try gpa.print("/usr/lib/werewolf/{s}", .{link[1]}),
                try gpa.print("{s}/{s}", .{ dir, link[0] }),
                .{},
            ) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => |e| return e,
            };
        }
    }
    // updates: how often the updater checks, where a form says (slot-update
    // reads /etc/werewolf/update-every); off, and the autoupdate service
    // is not in the image at all.
    const upd = form.updates(forms);
    if (forms[forms.len - 1].spec.get("machine")) |machine| {
        if (machine.get("metadata-users")) |enabled| {
            if (enabled == .scalar and mem.eql(u8, enabled.scalar.text, "true"))
                try put(io, ro, "etc/werewolf/metadata-users", "");
        }
    }
    if (upd.policy) |policy| try put(io, ro, "etc/werewolf/update-policy.json", policy);
    if (upd.every) |every| try put(
        io,
        ro,
        "etc/werewolf/update-every",
        try gpa.print("{d}\n", .{every}),
    );
    if (upd.off) try ro.deleteTree(io, "etc/sv/autoupdate");
    // One empty file per general allowance, for init, fence and posture. A
    // runtime allowance goes in the portable tree the hardened interpreters
    // read (lib/allow.zig), blanket under the `all` namespace: a form's allow
    // list is image-wide, so every service shares it.
    try ro.createDirPath(io, "etc/werewolf/allow");
    for (allowed) |a| {
        if (allow.RuntimeAllowance.parse(a)) |r| {
            const d = try gpa.print(
                "etc/runtime-hardening/allow/{s}/{s}",
                .{ allow.runtime_blanket, r.runtime },
            );
            try ro.createDirPath(io, d);
            try put(io, ro, try gpa.print("{s}/{s}", .{ d, r.name }), "");
        } else {
            try put(io, ro, try gpa.print("etc/werewolf/allow/{s}", .{a}), "");
        }
    }
    const sshd_config = try form.sshdConfig(gpa, forms, f);
    if (sshd_config.len > 0) {
        try ro.createDirPath(io, "etc/ssh/sshd_config.d");
        const text = try gpa.print("{s}\n", .{mem.trimEnd(u8, sshd_config, "\n")});
        try put(io, ro, "etc/ssh/sshd_config.d/form.conf", text);
    }
    // The key types init and cloud-metadata hold to verify-required
    // (lib/people.zig verify_path).
    const verify = try form.verifyRequired(gpa, forms);
    if (verify.len > 0) {
        try ro.createDirPath(io, "usr/share/werewolf");
        try put(io, ro, "usr/share/werewolf/sshd-verify-required", verify);
    }
    if (hasForm(forms, "bastion")) for (forms) |fm| {
        const bastion = fm.spec.get("bastion") orelse continue;
        if (bastion.get(
            "users",
        ) != null) return f.fail(gpa, "{s}: forwarding-only bastion users require explicit " ++
            "migration to users and bastion.destinations", .{
            fm.dir,
        });
    };
    // init seeds /run/werewolf from these; the image's /etc/passwd, group
    // and shadow link there.
    try ro.createDirPath(io, "usr/share/werewolf/etc");
    try put(io, ro, "usr/share/werewolf/age-enforce", "enforce\n");
    const normalized = try accounts(gpa, passwd, f);
    // A shell is a login form's policy, never the base filesystem's.
    const login_shell = if (b.dev)
        "root:x:0:0:root:/root:/usr/lib/werewolf/sh-shim\n"
    else if (hasForm(forms, "data-export"))
        "root:x:0:0:root:/root:/usr/lib/werewolf/data-export\n"
    else
        "root:x:0:0:root:/root:/bin/mksh\n";
    const users = if (b.dev or hasForm(forms, "sshd") or hasForm(forms, "data-export"))
        try mem.replaceOwned(
            u8,
            gpa,
            normalized,
            "root:x:0:0:root:/root:/sbin/nologin\n",
            login_shell,
        )
    else
        normalized;
    try unique(gpa, "group", group, f);
    try put(io, ro, "usr/share/werewolf/etc/passwd", users);
    try put(io, ro, "usr/share/werewolf/etc/group", group);
    try put(io, ro, "usr/share/werewolf/etc/shadow", shadow);
    // Link each service's supervise directory into /run/runit, which is
    // writable.
    for (try serviceNames(io, gpa, root, forms)) |s| {
        try ro.createDirPath(io, try gpa.print("etc/sv/{s}", .{s}));
        const target = try gpa.print("/run/runit/supervise.{s}", .{s});
        try ro.symLink(io, target, try gpa.print("etc/sv/{s}/supervise", .{s}), .{});
    }
    // Link each narrowed program to leash, which, run by the link, runs it
    // narrowed (docs/design/implemented/narrow.md).
    for (try form.services(io, gpa, root, forms, f)) |s| {
        for ((try parseService(gpa, s, f)).narrow) |n| {
            const dir = try gpa.print("etc/sv/{s}/narrow", .{s.name});
            try ro.createDirPath(io, dir);
            const link = try gpa.print("{s}/{s}", .{ dir, std.fs.path.basename(n.program) });
            ro.deleteFile(io, link) catch |err| switch (err) {
                error.FileNotFound => {},
                else => |e| return e,
            };
            try ro.symLink(io, "/usr/lib/werewolf/leash", link, .{});
        }
    }

    // meta: the records.
    var rec = try meta.createDirPathOpen(io, "usr/share/werewolf", .{});
    defer rec.close(io);
    try put(io, rec, "age-enforce", "enforce\n");
    // Stage the chain as forms/NAME (form.yaml, rootfs) and the known
    // posture failures; the updater composes the next slot from them.
    for (forms, 0..) |fm, i| {
        for (forms[0..i]) |before| if (mem.eql(u8, before.name, fm.name)) return f.fail(
            gpa,
            "{s} and {s}: two forms named {s} in one chain; the image stages each by name",
            .{ before.dir, fm.dir, fm.name },
        );
        try stage(io, gpa, root, fm, rec);
    }
    try put(io, rec, "posture-known", b.posture_known);
    const top = forms[forms.len - 1];
    try put(io, rec, "form", try gpa.print("{s}\n", .{top.name}));
    try put(io, rec, "variants", try mem.join(gpa, ",", top.selected));
    try put(io, rec, "prune", try lines(gpa, try prune(gpa, forms, f)));
    const known = try weaknesses(gpa, top, b);
    try put(io, rec, "weaknesses", if (upd.off)
        try gpa.print("{s}updates-enabled updates: off in the manifest\n", .{known})
    else
        known);
    try put(io, rec, "pledge", try pledge(io, gpa, root, forms, f));
    const images = try oci(io, gpa, root, forms, f);
    if (images.len > 0) try put(io, rec, "oci", images);
    if (b.dev) try put(io, rec, "dev", "ssh\n");
    try put(io, rec, "cmdline", try gpa.print("{s}\n", .{try cmdline(gpa, allowed, b.arch)}));
    try put(io, rec, "net", try net(gpa, forms, passwd, f));
}

fn put(io: Io, dir: Dir, path: []const u8, data: []const u8) !void {
    try dir.writeFile(io, .{ .sub_path = path, .data = data });
}

/// stage writes fm under dir as an image stages it, at forms/NAME:
/// form.yaml and rootfs, with its baked images laid in as `howl form`
/// lays them. The updater composes from what an image staged; a form's
/// package (NAME-form) carries the same tree.
pub fn stage(io: Io, gpa: Allocator, root: Dir, fm: Form, dir: Dir) !void {
    const at = try gpa.print("forms/{s}", .{fm.name});
    try dir.createDirPath(io, at);
    // People and secrets travel in the boot config, never in an image or
    // an apk repository. The updater needs only the image declaration.
    var image_entries: std.ArrayList(form.Entry) = .empty;
    for (fm.spec.map) |entry| {
        if (mem.eql(u8, entry.key, "users") or mem.eql(u8, entry.key, "secrets")) continue;
        try image_entries.append(gpa, entry);
    }
    var out: Io.Writer.Allocating = .init(gpa);
    try form.write(&out.writer, .{ .map = image_entries.items });
    const original = try root.readFileAlloc(
        io,
        try gpa.print("{s}/form.yaml", .{fm.dir}),
        gpa,
        .limited(256 << 10),
    );
    const text = if (fm.selected.len == 0 and image_entries.items.len == fm.spec.map.len and
        !mem.startsWith(u8, original, "# Generated by howl"))
        original
    else
        out.written();
    try put(io, dir, try gpa.print("{s}/form.yaml", .{at}), text);
    const rootfs = try gpa.print("{s}/rootfs", .{fm.dir});
    for (fm.images) |d| try lay(io, gpa, root, d, dir, try gpa.print("{s}/rootfs", .{at}));
    try lay(io, gpa, root, rootfs, dir, try gpa.print("{s}/rootfs", .{at}));
}

/// lay copies the tree at src, under root, into dst at to ("" for dst
/// itself): files with their modes, links as links, replacing what is
/// there. A missing src copies nothing. .DS_Store files are skipped, as the
/// build skips them.
fn lay(io: Io, gpa: Allocator, root: Dir, src: []const u8, dst: Dir, to: []const u8) !void {
    var from = root.openDir(io, src, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| return e,
    };
    defer from.close(io);
    var into = if (to.len == 0) dst else try dst.createDirPathOpen(io, to, .{});
    defer if (to.len > 0) into.close(io);
    var w = try from.walk(gpa);
    defer w.deinit();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    while (try w.next(io)) |e| {
        if (mem.eql(u8, e.basename, ".DS_Store")) continue;
        if (!cleanPath(e.path)) return error.UnexpectedFileKind;
        const there = into.statFile(io, e.path, .{ .follow_symlinks = false }) catch null;
        const was: ?Io.File.Kind = if (there) |st| st.kind else null;
        if (e.kind == .directory) {
            if (was != null and was != .directory) return error.UnexpectedFileKind;
            try into.createDirPath(io, e.path);
            continue;
        }
        if (was == .directory) return error.UnexpectedFileKind;
        switch (e.kind) {
            .sym_link => {
                const target = buf[0..try from.readLink(io, e.path, &buf)];
                into.deleteFile(io, e.path) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => |x| return x,
                };
                try into.symLink(io, target, e.path, .{});
            },
            .file => {
                into.deleteFile(io, e.path) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => |x| return x,
                };
                try copy(io, gpa, from, e.path, into);
            },
            else => return error.UnexpectedFileKind,
        }
    }
}

/// copy copies path from from to into, as a clone where the file system
/// can share its blocks: APFS here, as copy_file_range shares them on Btrfs
/// and XFS. An image service's tree is laid twice, gigabytes at a time.
fn copy(io: Io, gpa: Allocator, from: Dir, path: []const u8, into: Dir) !void {
    if (builtin.os.tag.isDarwin()) {
        const z = try gpa.dupeSentinel(u8, path, 0);
        defer gpa.free(z);
        if (clonefileat(from.handle, z, into.handle, z, 0) == 0) return;
    }
    try from.copyFile(path, into, path, io, .{});
}

extern "c" fn clonefileat(c_int, [*:0]const u8, c_int, [*:0]const u8, u32) c_int;

/// defaultId returns an account's default uid and gid: an FNV-1a hash of
/// its name, in [2^30, 2^31). Ids start above
/// system and people ids and stop below 2^31, which software that keeps a uid
/// in a signed int cannot hold. It depends on the name alone, so the id is
/// the same on every build and machine whatever forms come and go, and the
/// service keeps owning its files on /data.
pub fn defaultId(name: []const u8) u32 {
    return (1 << 30) | (std.hash.Fnv1a_32.hash(name) & ((1 << 30) - 1));
}

/// apko returns the chain's merged apko config (form.apko, with extra),
/// and werewolf's key (package.keyring), filling omitted account ids with
/// defaultId(name), and adding an account for each undeclared service
/// user. A user with no uid gets its own group,
/// home /var/empty and shell /sbin/nologin unless overridden; a same-named
/// declared group supplies its gid. It refuses two services that run as
/// one user, since strict share could not then keep them apart. It also
/// refuses a default id that a declared uid or gid, or another default,
/// already holds; a form's accounts must then give one of them a uid.
pub fn apko(
    io: Io,
    gpa: Allocator,
    root: Dir,
    forms: []const Form,
    extra: []const []const u8,
    f: *Failure,
) !form.Node {
    // werewolf's key, which signs minimal's hardened and application feeds
    // and, published, werewolf's own.
    const key = try gpa.dupe(
        form.Node,
        &.{.{ .scalar = .{ .raw = package.keyring, .text = package.keyring } }},
    );
    const keyring = try gpa.dupe(form.Entry, &.{.{ .key = "keyring", .value = .{ .list = key } }});
    const add = try gpa.dupe(form.Entry, &.{.{ .key = "contents", .value = .{ .map = keyring } }});
    const merged = try form.merge(gpa, try form.apko(gpa, forms, extra), .{ .map = add });
    const top = forms[forms.len - 1].dir;
    var declared: std.array_hash_map.String(void) = .empty;
    var declared_groups: std.array_hash_map.String(u32) = .empty;
    var ids: std.array_hash_map.Auto(u32, []const u8) = .empty;
    var groups: std.ArrayList(form.Node) = .empty;
    var users: std.ArrayList(form.Node) = .empty;
    if (merged.get("accounts")) |acc| {
        if (acc.get("users")) |list| for (try entries(gpa, top, list, f)) |u| {
            const name = try scalarAt(gpa, top, u, "username", f);
            try declared.put(gpa, name, {});
            if (u.get("uid") != null) try ids.put(gpa, try number(gpa, top, u, "uid", f), name);
            if (u.get("gid") != null) try ids.put(gpa, try number(gpa, top, u, "gid", f), name);
        };
        if (acc.get("groups")) |list| for (try entries(gpa, top, list, f)) |g| {
            const name = try scalarAt(gpa, top, g, "groupname", f);
            if (g.get("gid") != null) try ids.put(gpa, try number(gpa, top, g, "gid", f), name);
        };
        if (acc.get("groups")) |list| for (try entries(gpa, top, list, f)) |g| {
            const name = try scalarAt(gpa, top, g, "groupname", f);
            const gid = if (g.get("gid") == null)
                try defaultAccountId(gpa, top, name, &ids, f)
            else
                try number(gpa, top, g, "gid", f);
            try declared_groups.put(gpa, name, gid);
            const defaults = try mapOf(gpa, &.{.{ "gid", try gpa.print("{d}", .{gid}) }});
            try groups.append(gpa, try form.merge(gpa, defaults, g));
        };
        if (acc.get("users")) |list| for (try entries(gpa, top, list, f)) |u| {
            if (u.get("uid") != null) {
                try users.append(gpa, u);
                continue;
            }
            const name = try scalarAt(gpa, top, u, "username", f);
            const id = try defaultAccountId(gpa, top, name, &ids, f);
            const n = try gpa.print("{d}", .{id});
            const gid = try gpa.print("{d}", .{declared_groups.get(name) orelse id});
            const defaults = try mapOf(gpa, &.{
                .{ "uid", n },
                .{ "gid", gid },
                .{ "homedir", "/var/empty" },
                .{ "shell", "/sbin/nologin" },
            });
            try users.append(gpa, try form.merge(gpa, defaults, u));
            if (u.get("gid") == null and !declared_groups.contains(name))
                try groups.append(gpa, try mapOf(gpa, &.{ .{ "groupname", name }, .{ "gid", n } }));
        };
    }
    const Identity = struct { name: []const u8, shared: bool };
    var runs_as: std.array_hash_map.String(Identity) = .empty;
    const services = try form.services(io, gpa, root, forms, f);
    for (services) |s| {
        const parsed = try parseService(gpa, s, f);
        const user = parsed.user;
        // Login listeners deliberately start as root to create sessions;
        // they cannot be isolated from one another by account ownership.
        // privileges() restricts caps login to the permitted SSH listeners.
        const shared = parsed.shared_user or
            (mem.eql(u8, user, "root") and parsed.caps & service.cap.login != 0);
        if (runs_as.get(user)) |other| {
            if (!other.shared or !shared) return f.fail(
                gpa,
                "services {s} and {s} both run as {s}: each needs its own user, or every " ++
                    "component must declare shared-user: true",
                .{ other.name, s.name, user },
            );
            continue;
        }
        try runs_as.put(gpa, user, .{ .name = s.name, .shared = shared });
        if (declared.contains(user) or mem.eql(u8, user, "root")) continue;
        const id = try defaultAccountId(gpa, s.path, user, &ids, f);
        const n = try gpa.print("{d}", .{id});
        const gid = try gpa.print("{d}", .{declared_groups.get(user) orelse id});
        if (!declared_groups.contains(user))
            try groups.append(gpa, try mapOf(gpa, &.{ .{ "groupname", user }, .{ "gid", n } }));
        try users.append(gpa, try mapOf(gpa, &.{
            .{ "username", user },
            .{ "uid", n },
            .{ "gid", gid },
            .{ "homedir", "/var/empty" },
            .{ "shell", "/sbin/nologin" },
        }));
    }
    // A group a service joins is another service's user's, never a
    // system group such as shadow's or disk's.
    for (services) |s| for ((try parseService(gpa, s, f)).groups) |g| {
        const owner = runs_as.get(g) orelse return f.fail(
            gpa,
            "{s}: group {s}: no service runs as {s}, whose group it would join",
            .{ s.path, g, g },
        );
        _ = owner;
        if (mem.eql(u8, (try parseService(gpa, s, f)).user, g))
            return f.fail(gpa, "{s}: group {s} is its own", .{ s.path, g });
    };
    if (users.items.len == 0 and groups.items.len == 0) return merged;
    if (forms[forms.len - 1].selected.len > 0) {
        // Selecting an overlay on a generated test leaf can traverse the same
        // accounts in a different order. Assign IDs first, then keep the
        // selected image and its on-machine reconstruction byte-identical.
        const Order = struct {
            fn user(_: void, x: form.Node, y: form.Node) bool {
                return mem.lessThan(
                    u8,
                    x.get("username").?.scalar.text,
                    y.get("username").?.scalar.text,
                );
            }
            fn group(_: void, x: form.Node, y: form.Node) bool {
                return mem.lessThan(
                    u8,
                    x.get("groupname").?.scalar.text,
                    y.get("groupname").?.scalar.text,
                );
            }
        };
        mem.sort(form.Node, users.items, {}, Order.user);
        mem.sort(form.Node, groups.items, {}, Order.group);
    }
    var acc = merged.get("accounts") orelse form.Node{ .map = &.{} };
    acc = try replaceField(gpa, acc, "groups", .{ .list = groups.items });
    acc = try replaceField(gpa, acc, "users", .{ .list = users.items });
    return replaceField(gpa, merged, "accounts", acc);
}

/// defaultAccountId reserves name's default id, refusing another account's.
fn defaultAccountId(
    gpa: Allocator,
    path: []const u8,
    name: []const u8,
    ids: *std.array_hash_map.Auto(u32, []const u8),
    f: *Failure,
) Error!u32 {
    const id = defaultId(name);
    if (ids.get(id)) |holder| {
        if (!mem.eql(u8, holder, name)) return f.fail(
            gpa,
            "{s}: user {s}'s default id {d} is {s}'s: give one of them a uid in accounts",
            .{ path, name, id, holder },
        );
    }
    try ids.put(gpa, id, name);
    return id;
}

/// replaceField copies a map with key replaced, without joining list values.
fn replaceField(
    gpa: Allocator,
    node: form.Node,
    key: []const u8,
    value: form.Node,
) Allocator.Error!form.Node {
    var fields: std.ArrayList(form.Entry) = .empty;
    for (node.map) |entry| {
        if (!mem.eql(u8, entry.key, key)) try fields.append(gpa, entry);
    }
    try fields.append(gpa, .{ .key = key, .value = value });
    return .{ .map = fields.items };
}

/// format numbers the files compose writes and werewolf's programs read. Each
/// of werewolf's packages, programs and forms, depends on format_package,
/// and a published image's world names it, so a machine never takes one
/// built for another format; bump it when either side changes incompatibly.
/// 2: a form is form.yaml alone (its packages, accounts and paths in it);
/// a staged apko.yaml is refused.
/// 3: local-NAME stages the operator's forms and app for the updater;
/// inline update policy and metadata people need the matching programs.
/// 4: init passes inherited socketpairs to mount-broker and the slot services.
/// 5: shared-user service declarations and keyless UNIX people require
/// matching builders, launchers and metadata account reconciliation.
/// 6: local syslog readiness, service socket access and shutdown require
/// matching init, leash, runit-stage and minimal-form packages.
/// 7: DNS goes through unwound: lookup lines, the upstream resolver file
/// and fence's labels require matching init, fence, dhcp-client, leash,
/// unwound and minimal-form packages.
/// 8: inline variants, destination-scoped SSH egress and administrator groups.
pub const format = 8;

/// format_package is format's package, a name per format, so a world names
/// it with no version to compare. It holds /usr/lib/werewolf/format: apk
/// fetches no package without files.
pub const format_package = std.fmt.comptimePrint("werewolf-format{d}", .{format});

/// image_programs are the programs from cmd/ that every image runs, stage0's
/// init among them: a machine builds its next stage0 from its next root.
pub const image_programs = [_][]const u8{
    "init",         "stage0",       "iface-up", "fence",       "mount",   "mount-broker",
    "posture",      "seal-watch",   "seal",     "runit-stage", "reboot",  "slot-keep",
    "power-button", "ssh-host-key", "leash",    "leash-reap",  "syslogd", "unwound",
    "unwound-age",
};

/// formPrograms adds the packages of fm's form.yaml programs to names.
fn formPrograms(gpa: Allocator, fm: Form, names: *std.array_hash_map.String(void)) !void {
    for (try fm.items(gpa, "programs")) |item| {
        var it = mem.tokenizeAny(u8, item, " \t");
        while (it.next()) |p| {
            const stem = p[0 .. mem.findScalarLast(u8, p, '.') orelse p.len];
            try names.put(gpa, try gpa.print("werewolf-{s}", .{stem}), {});
        }
    }
}

/// packaged reports whether CI publishes fm as NAME-form. A form with
/// melange recipes is not: its packages exist only where it is built.
pub fn packaged(io: Io, gpa: Allocator, root: Dir, fm: Form) !bool {
    if ((try fm.items(gpa, "recipes")).len > 0) return false;
    root.access(io, try gpa.print("{s}/melange", .{fm.dir}), .{}) catch return true;
    return false;
}

/// formDepends returns what NAME-form depends on: the format, the forms
/// fm is built on and takes with it, its packages, and werewolf's programs
/// it runs, every image's for a form built on none.
pub fn formDepends(gpa: Allocator, fm: Form) ![]const []const u8 {
    var names: std.array_hash_map.String(void) = .empty;
    try names.put(gpa, format_package, {});
    // The form built on none brings every image's programs, and
    // werewolf's advisories, which its machine's updates are tiered by.
    if (fm.spec.get("base")) |b| {
        try names.put(gpa, try gpa.print("{s}-form", .{b.scalar.text}), {});
    } else {
        for (image_programs) |p| try names.put(gpa, try gpa.print("werewolf-{s}", .{p}), {});
        try names.put(gpa, "werewolf-advisories", {});
    }
    for (try fm.items(gpa, "with")) |m| try names.put(gpa, try gpa.print("{s}-form", .{m}), {});
    try formPrograms(gpa, fm, &names);
    for (try fm.items(gpa, "packages")) |p| try names.put(gpa, p, {});
    return names.keys();
}

/// published returns config for a build that takes werewolf's programs, and
/// the forms named in from_repo, from werewolf's repository: its repository
/// added, and its packages each such form as NAME-form, which brings its
/// own, then the other forms' packages and programs, extra, and the format
/// pin. Every image's programs come with the form built on none, or are
/// named when that form is not from the repository. apko gave config the key.
pub fn published(
    gpa: Allocator,
    config: form.Node,
    forms: []const Form,
    from_repo: []const []const u8,
    extra: []const []const u8,
) !form.Node {
    var names: std.array_hash_map.String(void) = .empty;
    for (forms) |fm| {
        const repo = for (from_repo) |n| {
            if (mem.eql(u8, n, fm.name)) break true;
        } else false;
        if (repo) {
            try names.put(gpa, try gpa.print("{s}-form", .{fm.name}), {});
            if (fm.selected.len > 0) {
                try formPrograms(gpa, fm, &names);
                for (try fm.items(gpa, "packages")) |p| try names.put(gpa, p, {});
            }
            continue;
        }
        if (fm.spec.get("base") == null) for (image_programs) |p|
            try names.put(gpa, try gpa.print("werewolf-{s}", .{p}), {});
        try formPrograms(gpa, fm, &names);
        for (try fm.items(gpa, "packages")) |p| try names.put(gpa, p, {});
    }
    for (extra) |p| try names.put(gpa, p, {});
    try names.put(gpa, format_package, {});
    const list = try gpa.alloc(form.Node, names.count());
    for (names.keys(), list) |p, *n| n.* = .{ .scalar = .{ .raw = p, .text = p } };

    // The packages replace the chain's; the repository joins its.
    var contents: std.ArrayList(form.Entry) = .empty;
    if (config.get("contents")) |c| if (c == .map) for (c.map) |e|
        if (!mem.eql(u8, e.key, "packages")) try contents.append(gpa, e);
    try contents.append(gpa, .{ .key = "packages", .value = .{ .list = list } });
    var top: std.ArrayList(form.Entry) = .empty;
    for (config.map) |e| try top.append(gpa, if (mem.eql(u8, e.key, "contents"))
        .{ .key = e.key, .value = .{ .map = contents.items } }
    else
        e);
    if (config.get("contents") == null)
        try top.append(gpa, .{ .key = "contents", .value = .{ .map = contents.items } });
    const url = try gpa.dupe(
        form.Node,
        &.{.{ .scalar = .{ .raw = package.repository, .text = package.repository } }},
    );
    const repo = try gpa.dupe(
        form.Entry,
        &.{.{ .key = "repositories", .value = .{ .list = url } }},
    );
    const add = try gpa.dupe(form.Entry, &.{.{ .key = "contents", .value = .{ .map = repo } }});
    return form.merge(gpa, .{ .map = top.items }, .{ .map = add });
}

/// mapOf returns a map node of plain scalars, in the order given.
fn mapOf(gpa: Allocator, pairs: []const [2][]const u8) Allocator.Error!form.Node {
    const out = try gpa.alloc(form.Entry, pairs.len);
    for (pairs, out) |p, *e| e.* = .{
        .key = p[0],
        .value = .{ .scalar = .{ .raw = p[1], .text = p[1] } },
    };
    return .{ .map = out };
}

/// withAccounts adds the accounts apko() returns (the forms' and the
/// service defaults) to the image's account files, after the packages' own,
/// as the apko tool would. On the build's root apko already added them, so
/// each file must end in exactly those lines; on a machine's root, which apk
/// filled, none is there and compose adds them. Anything else is refused,
/// because a machine's update could not reproduce it. So is a home other
/// than /var/empty or /dev/null: apko makes it at build time, but nothing
/// would on a machine.
pub fn withAccounts(
    io: Io,
    gpa: Allocator,
    root: Dir,
    forms: []const Form,
    image: Accounts,
    f: *Failure,
) !Accounts {
    var group: Added = .{ .file = "group" };
    var passwd: Added = .{ .file = "passwd" };
    var shadow: Added = .{ .file = "shadow" };
    const merged = try apko(io, gpa, root, forms, &.{}, f);
    const acc = merged.get("accounts") orelse return image;
    const top = forms[forms.len - 1].dir;
    if (acc.get("groups")) |groups| for (try entries(gpa, top, groups, f)) |g| {
        const name = try scalarAt(gpa, top, g, "groupname", f);
        const gid = try number(gpa, top, g, "gid", f);
        var members: std.ArrayList(u8) = .empty;
        if (g.get("members")) |m| for (try entries(gpa, top, m, f), 0..) |member, i| {
            if (member != .scalar) return f.fail(
                gpa,
                "{s}: accounts: group {s}: members",
                .{ top, name },
            );
            try members.print(gpa, "{s}{s}", .{ if (i > 0) "," else "", member.scalar.text });
        };
        try group.add(gpa, name, try gpa.print("{s}:x:{d}:{s}", .{ name, gid, members.items }));
    };
    if (acc.get("users")) |users| for (try entries(gpa, top, users, f)) |u| {
        const name = try scalarAt(gpa, top, u, "username", f);
        const uid = try number(gpa, top, u, "uid", f);
        const gid = if (u.get("gid") != null) try number(gpa, top, u, "gid", f) else uid;
        const home = if (u.get("homedir") != null)
            try scalarAt(gpa, top, u, "homedir", f)
        else
            try gpa.print("/home/{s}", .{name});
        const shell = if (u.get("shell") != null)
            try scalarAt(gpa, top, u, "shell", f)
        else
            "/bin/sh";
        if (!mem.eql(u8, home, "/var/empty") and !mem.eql(u8, home, "/dev/null")) return f.fail(
            gpa,
            "{s}: accounts: user {s}: homedir {s}: a machine's update would have none; " ++
                "give /var/empty, and the service a write path for its data",
            .{ top, name, home },
        );
        try passwd.add(gpa, name, try gpa.print(
            "{s}:x:{d}:{d}:Account created by apko:{s}:{s}",
            .{ name, uid, gid, home, shell },
        ));
        try shadow.add(gpa, name, try gpa.print("{s}:!:::::::", .{name}));
    };
    return .{
        .passwd = try passwd.onto(gpa, image.passwd, f),
        .group = try group.onto(gpa, image.group, f),
        .shadow = try shadow.onto(gpa, image.shadow, f),
    };
}

/// Added holds the lines apko adds to one account file, and their names.
const Added = struct {
    file: []const u8,
    names: std.ArrayList([]const u8) = .empty,
    lines: std.ArrayList(u8) = .empty,

    fn add(a: *Added, gpa: Allocator, name: []const u8, line: []const u8) Allocator.Error!void {
        try a.names.append(gpa, name);
        try a.lines.print(gpa, "{s}\n", .{line});
    }

    /// onto returns text unchanged if it ends in the lines (apko added
    /// them), or with them appended if it names none of them (apk wrote
    /// it). Anything else is refused.
    fn onto(a: Added, gpa: Allocator, text: []const u8, f: *Failure) Error![]const u8 {
        if (a.lines.items.len == 0 or mem.endsWith(u8, text, a.lines.items)) return text;
        var it = fileLines(text);
        while (it.next()) |have| for (a.names.items) |name| {
            const at = have[0 .. mem.findScalar(u8, have, ':') orelse have.len];
            if (mem.eql(u8, at, name)) return f.fail(
                gpa,
                "{s}: {s} is there, but the accounts apko added are not those the forms " ++
                    "give now, in their order: a root built from older forms; build it again",
                .{ a.file, name },
            );
        };
        const sep = if (text.len > 0 and text[text.len - 1] != '\n') "\n" else "";
        return gpa.print("{s}{s}{s}", .{ text, sep, a.lines.items });
    }
};

/// entries returns a list node's items.
fn entries(gpa: Allocator, path: []const u8, node: form.Node, f: *Failure) Error![]const form.Node {
    if (node != .list) return f.fail(gpa, "{s}: accounts: a list expected", .{path});
    return node.list;
}

/// scalarAt returns the scalar under key, or a failure naming key.
fn scalarAt(
    gpa: Allocator,
    path: []const u8,
    node: form.Node,
    key: []const u8,
    f: *Failure,
) Error![]const u8 {
    const v = node.get(key) orelse return f.fail(
        gpa,
        "{s}: accounts: an entry has no {s}",
        .{ path, key },
    );
    if (v != .scalar) return f.fail(gpa, "{s}: accounts: {s}: one value", .{ path, key });
    return v.scalar.text;
}

/// number returns the number under key, as apko reads it.
fn number(
    gpa: Allocator,
    path: []const u8,
    node: form.Node,
    key: []const u8,
    f: *Failure,
) Error!u32 {
    const text = try scalarAt(gpa, path, node, key, f);
    return std.fmt.parseInt(u32, text, 10) catch
        return f.fail(gpa, "{s}: accounts: {s}: {s} is not a number", .{ path, key, text });
}

/// lines joins items, one per line.
fn lines(gpa: Allocator, items: []const []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (items) |item| try out.print(gpa, "{s}\n", .{item});
    return out.items;
}

fn hasForm(forms: []const Form, name: []const u8) bool {
    for (forms) |fm| if (mem.eql(u8, fm.name, name)) return true;
    return false;
}

fn sortStrings(items: [][]const u8) void {
    mem.sortUnstable([]const u8, items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return mem.lessThan(u8, a, b);
        }
    }.lt);
}

/// allowances returns the chain's allowances, sorted and unique
/// (lib/allow.zig). It refuses nested-kvm without kvm.
pub fn allowances(gpa: Allocator, forms: []const Form, f: *Failure) Error![]const []const u8 {
    var set: std.array_hash_map.String(void) = .empty;
    for (forms) |fm| for (try fm.items(gpa, "allow")) |a| try set.put(gpa, a, {});
    const out = set.keys();
    sortStrings(out);
    if (set.contains("nested-kvm") and !set.contains("kvm"))
        return f.fail(gpa, "form {s} allows nested-kvm without kvm", .{forms[forms.len - 1].name});
    return out;
}

fn allows(allowed: []const []const u8, name: []const u8) bool {
    for (allowed) |a| if (mem.eql(u8, a, name)) return true;
    return false;
}

/// cmdline returns the kernel arguments for what has no runtime switch. The
/// kernel (docs/design/implemented/custom-kernel.md) already leaves out debugfs, IPv6,
/// 32-bit calls and modules; these hold the rest even if its config drifts:
/// no forced writes through /proc/PID/mem, slab_nomerge so a freed object is
/// not reused by an attacker's object of another type, and page shuffling so
/// layout is harder to predict. None costs anything. init_on_free is left off
/// for its cost (docs/security.md). KVM is built in and starts whenever the
/// host offers virtualization, so it is off unless allowed (kvm-arm.mode on
/// aarch64, clearing VMX/SVM CPU features on x86_64), and nested only if allowed.
///
/// loglevel=5 limits the console to warnings and worse; dmesg keeps all.
/// A cloud serial port takes about a millisecond a line: on GCP, notices
/// and info doubled boot time (0.23 s against 0.11 s). Panics, stalls, BUG
/// and the power-down line that test/console.zig reads are all errors or worse.
pub fn cmdline(gpa: Allocator, allowed: []const []const u8, arch: Arch) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "proc_mem.force_override=never slab_nomerge page_alloc.shuffle=1");
    const kvm = allows(allowed, "kvm");
    const nested = allows(allowed, "nested-kvm");
    // LTO wraps initcalls in generated stubs, so blacklisting vt_init and
    // svm_init by name misses them. Remove their CPU features before probing.
    // Linux records the intentional feature mask as CPU-out-of-spec taint.
    try out.appendSlice(gpa, switch (arch) {
        .aarch64 => if (nested) " kvm-arm.mode=nested" else if (!kvm) " kvm-arm.mode=none" else "",
        .x86_64 => if (nested)
            " kvm_intel.nested=1 kvm_amd.nested=1"
        else if (kvm)
            " kvm_intel.nested=0 kvm_amd.nested=0"
        else
            " clearcpuid=vmx,svm",
    });
    try out.appendSlice(gpa, " loglevel=5");
    return out.items;
}

/// uncommented returns line up to its first #.
fn uncommented(line: []const u8) []const u8 {
    return line[0 .. mem.findScalar(u8, line, '#') orelse line.len];
}

/// words splits line on spaces and tabs.
fn words(gpa: Allocator, line: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeAny(u8, line, " \t");
    while (it.next()) |w| try out.append(gpa, w);
    return out.items;
}

/// prune returns the files the chain removes from its packages because
/// nothing runs them. Each path must be relative and clean.
pub fn prune(gpa: Allocator, forms: []const Form, f: *Failure) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (forms) |fm| for (try fm.items(gpa, "prune")) |p| {
        if (!cleanPath(p))
            return f.fail(
                gpa,
                "form {s} prunes {s}: a path is relative and clean, usr/bin/bash",
                .{ forms[forms.len - 1].name, p },
            );
        try out.append(gpa, p);
    };
    return out.items;
}

fn cleanPath(p: []const u8) bool {
    if (p.len == 0 or mem.startsWith(u8, p, "/") or mem.endsWith(u8, p, "/")) return false;
    var segs = mem.splitScalar(u8, p, '/');
    while (segs.next()) |s| {
        if (s.len == 0 or mem.eql(u8, s, ".") or mem.eql(u8, s, "..")) return false;
    }
    return true;
}

/// weaknesses lists the posture checks the machine is expected to fail,
/// each with its excuse: the form's own, then those from test/posture-known
/// (the `*` line, plus the arch's line).
pub fn weaknesses(gpa: Allocator, top: Form, b: Build) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (top.weaknesses()) |e| try out.print(gpa, "{s} {s}\n", .{ e.key, e.value.scalar.text });
    if (b.dev) try out.appendSlice(gpa, "network-no-login authenticated SSH for local " ++
        "test iteration\n" ++
        "network-ssh-dev-security-keys the managed local developer key\n" ++
        "files-noexec-everywhere executable RAM for authenticated test uploads\n");
    const excuse = try gpa.print("every form on {t} (test/posture-known)", .{b.arch});
    var known = mem.splitScalar(u8, b.posture_known, '\n');
    while (known.next()) |line| {
        var it = mem.tokenizeAny(u8, line, " \t");
        const first = it.next() orelse continue;
        if (!mem.eql(u8, first, "*") and !mem.eql(u8, first, @tagName(b.arch))) continue;
        while (it.next()) |id| {
            if (b.ipe and mem.eql(u8, id, "boot-ipe-enforced")) continue;
            if (b.tpm and mem.eql(u8, id, "boot-rollback-protected")) continue;
            try out.print(gpa, "{s} {s}\n", .{ id, unbuilt(id, excuse) });
        }
    }
    return out.items;
}

/// unbuilt returns the excuse for a posture check the boot chain cannot
/// hold yet, as docs/design/implemented/verified-boot.md phases 4 and 5 name them, or
/// the generic excuse for the build.
fn unbuilt(id: []const u8, generic: []const u8) []const u8 {
    const bare = if (id.len > 0 and id[0] == '?') id[1..] else id;
    if (mem.eql(u8, bare, "boot-secure-boot"))
        return "Secure Boot is phase 5 of the boot design, not built: this image is not " ++
            "signed for it";
    if (mem.eql(u8, bare, "boot-ipe-enforced"))
        return "this image carries no IPE policy; build with IPE=1 for global image enforcement";
    if (mem.eql(u8, bare, "boot-rollback-protected"))
        return "no TPM counter guards the slot serial yet: phase 5 of the boot design";
    return generic;
}

/// pledge returns the union of every service's pledge, as one line. It
/// parses each service file as leash does and fails on one leash would
/// refuse, or on a listen port no net line declares, which fence would
/// refuse at boot. It also fails on a read or write path inside another
/// service's directory whose share is strict, which that directory's mode
/// would deny.
pub fn pledge(io: Io, gpa: Allocator, root: Dir, forms: []const Form, f: *Failure) ![]const u8 {
    var declared: std.ArrayList(u16) = .empty;
    var declared_udp: std.ArrayList(u16) = .empty;
    for (try form.netLines(gpa, forms, f)) |line| {
        var ws = mem.tokenizeAny(u8, line, " \t");
        if (mem.eql(u8, ws.next() orelse "", "listen") and ws.next() != null) {
            while (ws.next()) |w| if (port(w, "udp/")) |p| try declared_udp.append(gpa, p);
        }
        var why: []const u8 = "";
        const l = (form.listen(gpa, line, &why) catch |err| switch (err) {
            error.Invalid => return f.fail(
                gpa,
                "{s}: net: {s}: {s}",
                .{ forms[forms.len - 1].dir, line, why },
            ),
            error.OutOfMemory => return error.OutOfMemory,
        }) orelse continue;
        try declared.appendSlice(gpa, l.ports);
    }
    var promises: seal.Set = .empty;
    const services = try form.services(io, gpa, root, forms, f);
    const parsed = try gpa.alloc(service.Service, services.len);
    for (services, parsed) |s, *ps| {
        if (mem.startsWith(u8, s.text, form.unbaked)) {
            const ref = s.text[form.unbaked.len..mem.findScalar(u8, s.text, '\n').?];
            return f.fail(
                gpa,
                "{s}: {s}: no image baked: the build bakes it (howl build), or howl form --oci",
                .{ s.path, mem.trim(u8, ref, " ") },
            );
        }
        ps.* = try parseService(gpa, s, f);
        for (ps.listen) |p| if (mem.findScalar(u16, declared.items, p) == null)
            return f.fail(
                gpa,
                "{s}: listen tcp/{d}, which no net line declares: fence refuses the bind " ++
                    "(`listen tcp/{d} loopback` for the machine alone)",
                .{ s.path, p, p },
            );
        for (ps.listen_udp) |p| if (mem.findScalar(u16, declared_udp.items, p) == null and
            mem.findScalar(u16, s.loopback_udp, p) == null)
            return f.fail(
                gpa,
                "{s}: listen udp/{d}, which no net line declares: fence drops what arrives",
                .{ s.path, p },
            );
        promises.setUnion(ps.pledge);
    }
    for (services, parsed) |s, ps| {
        if (ps.root != null) continue; // its paths are inside its image
        for ([_][]const []const u8{ ps.read, ps.write, ps.sockets }) |paths| for (paths) |path| {
            const owner = serviceDirOwner(path) orelse continue;
            if (mem.eql(u8, owner, s.name)) continue;
            for (services, parsed) |o, po| {
                if (!mem.eql(u8, o.name, owner) or po.share != .strict) continue;
                if (ps.shared_user and po.shared_user and mem.eql(u8, ps.user, po.user)) continue;
                return f.fail(
                    gpa,
                    "{s}: {s} is inside {s}'s directory, which only {s} may enter: " ++
                        "{s} needs `share shared`",
                    .{ s.path, path, owner, owner, o.path },
                );
            }
        };
    }
    var out: std.ArrayList(u8) = .empty;
    var it = promises.iterator();
    var sep: []const u8 = "";
    while (it.next()) |p| : (sep = " ") try out.print(gpa, "{s}{t}", .{ sep, p });
    try out.append(gpa, '\n');
    return out.items;
}

/// serviceDirOwner returns the service whose directory, /run/svc/NAME or
/// /data/svc/NAME, is path or holds it, or null.
fn serviceDirOwner(path: []const u8) ?[]const u8 {
    for ([_][]const u8{ "/run/svc/", "/data/svc/" }) |prefix| {
        if (!mem.startsWith(u8, path, prefix)) continue;
        const rest = path[prefix.len..];
        const end = mem.findScalar(u8, rest, '/') orelse rest.len;
        if (end > 0) return rest[0..end];
    }
    return null;
}

/// privileges refuses a capability the chain did not allow, a memfd promise
/// without the jit allowance, and a shared directory no one writes or that a
/// service reaches without joining the owner's group. The first writer in
/// service-name order owns the path.
/// Other forms name neither, so they are unchanged.
fn privileges(
    io: Io,
    gpa: Allocator,
    root: Dir,
    forms: []const Form,
    allowed: []const []const u8,
    dev: bool,
    f: *Failure,
) !void {
    const services = try form.services(io, gpa, root, forms, f);
    var owner_of: std.array_hash_map.String([]const u8) = .empty;
    var user_of: std.array_hash_map.String([]const u8) = .empty;
    for (services) |s| {
        const parsed = try parseService(gpa, s, f);
        try user_of.put(gpa, s.name, parsed.user);
        if (parsed.caps & service.cap.net_raw != 0 and !allows(allowed, "packet"))
            return f.fail(gpa, "{s}: caps net_raw: the chain does not allow packet", .{s.path});
        if (parsed.caps & service.cap.net_admin != 0 and !allows(allowed, "netadmin"))
            return f.fail(gpa, "{s}: caps net_admin: the chain does not allow netadmin", .{s.path});
        // A memory file is the one writable place no mount flag covers, and
        // W^X sees only one mapping at a time: written, then mapped as code,
        // it runs wherever IPE is off (docs/security.md). Only a form that
        // already runs code it writes may promise it.
        if (parsed.pledge.contains(.memfd) and !allows(allowed, "jit"))
            return f.fail(
                gpa,
                "{s}: pledge memfd: a memory file maps as code; the chain does not allow jit",
                .{s.path},
            );
        if (parsed.caps & service.cap.login != 0 and
            (!(mem.eql(u8, s.name, "sshd") or (dev and mem.eql(u8, s.name, "sshd-dev"))) or
                (!allows(
                    allowed,
                    "pty",
                ) and !(mem.eql(u8, s.name, "sshd") and hasForm(forms, "data-export")))))
            return f.fail(
                gpa,
                "{s}: caps login requires sshd with pty or the fixed data-export endpoint",
                .{s.path},
            );
        if (mem.eql(u8, s.name, "caddy") or mem.eql(u8, parsed.user, "caddy")) {
            for ([_][]const []const u8{ parsed.read, parsed.write, parsed.sockets }) |paths| {
                for (paths) |p| {
                    if (!mem.eql(u8, p, "/data") and !mem.startsWith(u8, p, "/data/")) continue;
                    if (serviceDirOwner(p)) |owner| if (mem.eql(u8, owner, s.name)) continue;
                    return f.fail(
                        gpa,
                        "{s}: {s}: caddy holds TLS keys and may not reach another service's " ++
                            "/data tree",
                        .{ s.path, p },
                    );
                }
            }
        }
        for (parsed.data) |d| if (d.write and !owner_of.contains(d.host))
            try owner_of.put(gpa, d.host, s.name);
    }
    for (services) |s| {
        const parsed = try parseService(gpa, s, f);
        for (parsed.data) |d| {
            const owner = owner_of.get(d.host) orelse return f.fail(
                gpa,
                "{s}: data {s}: no service writes it",
                .{ s.path, d.host },
            );
            if (mem.eql(u8, owner, s.name)) continue;
            const owner_user = user_of.get(owner).?;
            const joined = for (parsed.groups) |g| {
                if (mem.eql(u8, g, owner_user)) break true;
            } else false;
            if (!joined) return f.fail(
                gpa,
                "{s}: data {s}: {s} owns it; group {s} joins that user",
                .{ s.path, d.host, owner, owner_user },
            );
        }
        if (parsed.root == null) {
            for ([_][]const []const u8{ parsed.read, parsed.write }) |paths| for (paths) |p| {
                if (!mem.startsWith(u8, p, "/data/share/")) continue;
                var owner: ?[]const u8 = null;
                for (owner_of.keys(), owner_of.values()) |host, who| {
                    if (mem.eql(u8, p, host) or
                        (mem.startsWith(u8, p, host) and p[host.len] == '/'))
                    {
                        owner = who;
                        break;
                    }
                }
                const who = owner orelse return f.fail(
                    gpa,
                    "{s}: {s}: no service writes this shared directory",
                    .{ s.path, p },
                );
                if (mem.eql(u8, who, s.name)) continue;
                const owner_user = user_of.get(who).?;
                const joined = for (parsed.groups) |g| {
                    if (mem.eql(u8, g, owner_user)) break true;
                } else false;
                if (!joined) return f.fail(
                    gpa,
                    "{s}: {s}: {s} owns it; group {s} joins that user",
                    .{ s.path, p, who, owner_user },
                );
            };
        }
    }
}

/// oci lists the services that run in a baked-in image: `root NAME DIR USER`,
/// then `write NAME PATH` for each path init binds beneath the image root
/// and fence allows (cmd/init/oci.zig, cmd/fence). `data NAME HOST IMAGE
/// read|write` is a directory under /data/share, bound the same way.
pub fn oci(io: Io, gpa: Allocator, root: Dir, forms: []const Form, f: *Failure) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (try form.services(io, gpa, root, forms, f)) |s| {
        const parsed = try parseService(gpa, s, f);
        const dir = parsed.root orelse continue;
        try out.print(gpa, "root {s} {s} {s}\n", .{ s.name, dir, parsed.user });
        for (parsed.write) |path| try out.print(gpa, "write {s} {s}\n", .{ s.name, path });
        for (parsed.data) |d| try out.print(gpa, "data {s} {s} {s} {s}\n", .{
            s.name, d.host, d.image, if (d.write) "write" else "read",
        });
    }
    return out.items;
}

test "OCI service cannot alias the age cache directory" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var failure: Failure = .{};
    const yaml = "services:\n  unwound-age:\n    image: example.com/test:1\n" ++
        "    exec: /app\n    user: root\n";
    const fm = try testForm(gpa, "collision", yaml);
    try testing.expectError(error.Form, oci(std.testing.io, gpa, Dir.cwd(), &.{fm}, &failure));
}

fn parseService(gpa: Allocator, s: form.Service, f: *Failure) !service.Service {
    var bad: service.Bad = .{};
    return service.parse(gpa, s.text, &bad) catch |err| switch (err) {
        error.Invalid => return f.fail(gpa, "{s}, line {d}: {s}", .{ s.path, bad.line, bad.why }),
        else => |e| return e,
    };
}

/// serviceNames returns the names in the chain's rootfs/etc/sv directories,
/// sorted and unique.
fn serviceNames(io: Io, gpa: Allocator, root: Dir, forms: []const Form) ![]const []const u8 {
    var set: std.array_hash_map.String(void) = .empty;
    for (forms) |fm| {
        var sv = root.openDir(
            io,
            try gpa.print("{s}/rootfs/etc/sv", .{fm.dir}),
            .{ .iterate = true },
        ) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer sv.close(io);
        var it = sv.iterate();
        while (try it.next(io)) |e| if (e.name[0] != '.') try set.put(
            gpa,
            try gpa.dupe(u8, e.name),
            {},
        );
    }
    for (forms) |fm| if (fm.spec.get("services")) |svcs| for (svcs.map) |s|
        try set.put(gpa, s.key, {});
    // updates: off leaves the autoupdate service out of the image (compose).
    if (form.updates(forms).off) _ = set.swapRemove("autoupdate");
    const out = set.keys();
    sortStrings(out);
    return out;
}

/// accounts returns the passwd init seeds. Group 0 can read /etc/shadow,
/// so accounts other than root in it (Alpine's sync, shutdown, halt and
/// operator) move to nogroup (posture's files-accounts). A repeated name or
/// uid, which two forms of a bundle can cause, is refused.
pub fn accounts(gpa: Allocator, passwd: []const u8, f: *Failure) Error![]const u8 {
    try unique(gpa, "passwd", passwd, f);
    var out: std.ArrayList(u8) = .empty;
    var it = fileLines(passwd);
    while (it.next()) |line| {
        var fields: std.ArrayList([]const u8) = .empty;
        var fi = mem.splitScalar(u8, line, ':');
        while (fi.next()) |field| try fields.append(gpa, field);
        if (fields.items.len >= 4 and isZero(fields.items[3]) and !isZero(fields.items[2]))
            fields.items[3] = "65533";
        for (fields.items, 0..) |field, i| try out.print(
            gpa,
            "{s}{s}",
            .{ if (i > 0) ":" else "", field },
        );
        try out.append(gpa, '\n');
    }
    return out.items;
}

fn isZero(field: []const u8) bool {
    return (std.fmt.parseInt(u32, field, 10) catch return false) == 0;
}

/// fileLines splits text into lines, without an empty one after the last newline.
fn fileLines(text: []const u8) mem.SplitIterator(u8, .scalar) {
    return mem.splitScalar(
        u8,
        if (mem.endsWith(u8, text, "\n")) text[0 .. text.len - 1] else text,
        '\n',
    );
}

/// unique refuses an account file, passwd or group, that repeats a name or id.
fn unique(gpa: Allocator, file: []const u8, text: []const u8, f: *Failure) Error!void {
    var names: std.array_hash_map.String(void) = .empty;
    var ids: std.array_hash_map.String(void) = .empty;
    var it = fileLines(text);
    while (it.next()) |line| {
        var fi = mem.splitScalar(u8, line, ':');
        const name = fi.next() orelse "";
        _ = fi.next();
        const id = fi.next() orelse "";
        if ((try names.getOrPut(gpa, name)).found_existing or
            (try ids.getOrPut(gpa, id)).found_existing)
            return f.fail(
                gpa,
                "{s}: {s} or its id {s} is there twice: a bundle's forms disagree",
                .{ file, name, id },
            );
    }
}

/// net compiles the chain's network policy for fence and unwound: one rule
/// per line, sorted and unique, with users as uids from passwd. It reads
/// `listen tcp/PORT... [loopback]`, `connect USER|:all|:people
/// PROTO/PORT|icmp... [public]`, `metadata USER...` and `lookup USER|:people
/// PATTERN TYPE... [unfiltered]` (forms/README.md). A colon begins no
/// account's name: `:all` is every user, `:people` every person's uid range.
pub fn net(gpa: Allocator, forms: []const Form, passwd: []const u8, f: *Failure) Error![]const u8 {
    var uids: std.array_hash_map.String([]const u8) = .empty;
    var pw = fileLines(passwd);
    while (pw.next()) |line| {
        var fi = mem.splitScalar(u8, line, ':');
        const name = fi.next() orelse "";
        _ = fi.next();
        try uids.put(gpa, name, fi.next() orelse "");
    }
    var out: std.ArrayList([]const u8) = .empty;
    var lookups = false;
    const source_lines = try form.netLines(gpa, forms, f);
    var direct: std.array_hash_map.String(void) = .empty;
    var everyone: [people.ids.len][]const u8 = undefined;
    for (&everyone, people.ids) |*text, range| text.* = try gpa.print(
        "{d}-{d}",
        .{ range[0], range[1] },
    );
    for (source_lines) |item| {
        const w = try words(gpa, uncommented(item));
        if (w.len == 2 and mem.eql(u8, w[0], "dns-direct")) try direct.put(gpa, w[1], {});
        // People's ranges hold people alone, or another account would
        // share their grants.
        if (w.len > 1 and
            mem.eql(u8, w[1], ":people")) for (uids.keys(), uids.values()) |name, text|
        {
            const id = std.fmt.parseInt(u32, text, 10) catch continue;
            for (people.ids) |range| if (id >= range[0] and id <= range[1]) return f.fail(
                gpa,
                "form {s}: net: {s}: account {s} has uid {d}, among people's " ++
                    "{d}-{d} (lib/people.zig ids): give it another",
                .{ forms[forms.len - 1].name, uncommented(item), name, id, range[0], range[1] },
            );
        };
    }
    for (source_lines) |item| {
        const line = uncommented(item);
        lookups = lookups or mem.startsWith(u8, line, "lookup ");
        const w = try words(gpa, line);
        // A DNS service alone may contact upstream servers directly, and
        // only on ports it declared in its own connect rule.
        if (w.len > 0 and mem.eql(u8, w[0], "connect")) for (w) |t| if (isDnsPort(t)) {
            if (w.len <= 2 or direct.get(w[1]) == null) return f.fail(
                gpa,
                "form {s}: DNS goes through unwound; direct port 53 or 853 needs " ++
                    "dns-direct: true in the DNS service (docs/design/implemented/unwound-policy" ++
                    ".md): {s}",
                .{ forms[forms.len - 1].name, line },
            );
        };
        if (!try netLine(gpa, w, &uids, &everyone, &out)) return f.fail(
            gpa,
            "form {s}: a net line cannot compile: {s}{s}",
            .{
                forms[forms.len - 1].name, line,
                if (w.len > 1 and uids.get(w[1]) == null and
                    (mem.eql(u8, w[1], "all") or mem.eql(u8, w[1], "people")))
                    " (every user is :all, every person :people)"
                else
                    "",
            },
        );
    }
    // unwound answers every lookup at 127.0.0.53:53 and asks the resolvers
    // as its upstream user, the one user that may (cmd/unwound).
    if (uids.get(unwound_upstream)) |uid| {
        try out.append(gpa, "listen tcp 53 loopback");
        try out.append(gpa, try gpa.print("dns {s}", .{uid}));
    } else if (lookups) return f.fail(
        gpa,
        "form {s}: lookup needs unwound, and its {s} account (forms/minimal)",
        .{ forms[forms.len - 1].name, unwound_upstream },
    );
    const kept = try loopbackOnly(gpa, out.items, forms[forms.len - 1].name, f);
    sortStrings(kept);
    var text: std.ArrayList(u8) = .empty;
    for (kept, 0..) |line, i| {
        if (i > 0 and mem.eql(u8, line, kept[i - 1])) continue;
        try text.print(gpa, "{s}\n", .{line});
    }
    return text.items;
}

const unwound_upstream = "_unwoundnet";

/// loopbackOnly returns grants without the loopback-only TCP grants another
/// line holds: fence refuses a loopback line's users its port everywhere else,
/// so beside a broader grant to the same users, or every user's, it would take
/// that grant away. `all`'s loopback line beside another user's broader grant
/// would take theirs, and fails.
fn loopbackOnly(
    gpa: Allocator,
    grants: [][]const u8,
    name: []const u8,
    f: *Failure,
) Error![][]const u8 {
    var kept: std.ArrayList([]const u8) = .empty;
    for (grants) |line| {
        const w = try words(gpa, line);
        const held = w.len == 5 and mem.eql(u8, w[0], "connect") and mem.eql(u8, w[2], "tcp") and
            mem.eql(u8, w[4], "loopback") and for (grants) |other|
        {
            const o = try words(gpa, other);
            if (o.len != 4 or !mem.eql(u8, o[0], "connect") or !mem.eql(u8, o[2], "tcp") or
                (!mem.eql(u8, o[3], w[3]) and !mem.eql(u8, o[3], "any"))) continue;
            if (mem.eql(u8, o[1], w[1]) or mem.eql(u8, o[1], "all")) break true;
            if (mem.eql(u8, w[1], "all")) return f.fail(
                gpa,
                "form {s}: net: {s} would refuse tcp/{s} beyond loopback to everyone, " ++
                    "though {s} grants it: give the loopback grant to fewer users",
                .{ name, line, w[3], other },
            );
        } else false;
        if (!held) try kept.append(gpa, line);
    }
    return kept.items;
}

fn isDnsPort(word: []const u8) bool {
    for ([_][]const u8{
        "tcp/",
        "udp/",
    }) |proto| if (port(word, proto)) |p| return p == 53 or p == 853;
    return false;
}

/// netLine compiles one net line's words onto out. It returns false for a
/// line that cannot compile.
fn netLine(
    gpa: Allocator,
    w: []const []const u8,
    uids: *const std.array_hash_map.String([]const u8),
    everyone: []const []const u8,
    out: *std.ArrayList([]const u8),
) Allocator.Error!bool {
    if (w.len == 0) return true;
    if (mem.eql(u8, w[0], "bastion-connect") and w.len == 3) {
        const address = std.Io.net.IpAddress.parseLiteral(w[2]) catch return false;
        const dest = try gpa.print("{f}", .{switch (address) {
            .ip4 => |a| std.Io.net.IpAddress{ .ip4 = .{ .bytes = a.bytes, .port = 0 } },
            .ip6 => |a| std.Io.net.IpAddress{ .ip6 = .{ .bytes = a.bytes, .port = 0 } },
        }});
        // Use the address without the formatter's :0 port suffix.
        const colon = mem.findScalarLast(u8, dest, ':') orelse return false;
        const host = if (dest[0] == '[') dest[1 .. colon - 1] else dest[0..colon];
        const ids: []const []const u8 = if (mem.eql(u8, w[1], ":people"))
            everyone
        else
            &.{uids.get(w[1]) orelse return false};
        for (ids) |uid| try out.append(
            gpa,
            try gpa.print("connect {s} tcp {d} destination {s}", .{ uid, address.getPort(), host }),
        );
        return true;
    }

    // listen USER udp/PORT...: fence delivers the port, and lets only USER
    // send from it (docs/design/implemented/listen-udp.md).
    if (mem.eql(u8, w[0], "listen") and w.len > 2 and !mem.startsWith(u8, w[1], "tcp/")) {
        const uid = uids.get(w[1]) orelse return false;
        const lan = mem.eql(u8, w[w.len - 1], "lan");
        const ports = w[2 .. w.len - @intFromBool(lan)];
        if (ports.len == 0) return false;
        for (ports) |p| try out.append(
            gpa,
            try gpa.print("listen {s} udp {d}{s}", .{
                uid, port(p, "udp/") orelse return false, if (lan) " lan" else "",
            }),
        );
        return true;
    }
    if (mem.eql(u8, w[0], "listen") and w.len > 1) {
        const lo = mem.eql(u8, w[w.len - 1], "loopback");
        const lan = mem.eql(u8, w[w.len - 1], "lan");
        const ports = w[1 .. w.len - @intFromBool(lo or lan)];
        if (ports.len == 0) return false;
        for (ports) |p| {
            // Fence already allows bind(0), but no external traffic to an
            // undeclared port. Only the service's leash gets this grant.
            if (lo and mem.eql(u8, p, "tcp/0")) continue;
            try out.append(gpa, try gpa.print(
                "listen tcp {d}{s}",
                .{
                    port(p, "tcp/") orelse return false,
                    if (lo) " loopback" else if (lan) " lan" else "",
                },
            ));
        }
        return true;
    }
    // form.netLines checked the rest of a lookup line; unwound checks it again.
    if (mem.eql(u8, w[0], "lookup") and w.len > 3) {
        var one: [1][]const u8 = undefined;
        const who: []const []const u8 = if (mem.eql(u8, w[1], ":people")) everyone else blk: {
            one[0] = uids.get(w[1]) orelse return false;
            break :blk &one;
        };
        const rest = try mem.join(gpa, " ", w[2..]);
        for (who) |u| try out.append(gpa, try gpa.print("lookup {s} {s}", .{ u, rest }));
        return true;
    }
    if (mem.eql(u8, w[0], "dns-direct") and w.len == 2) {
        try out.append(gpa, try gpa.print("dns-direct {s}", .{uids.get(w[1]) orelse return false}));
        return true;
    }
    if (mem.eql(u8, w[0], "metadata") and w.len > 1) {
        for (w[1..]) |u|
            try out.append(gpa, try gpa.print("metadata {s}", .{uids.get(u) orelse return false}));
        return true;
    }
    if (mem.eql(u8, w[0], "connect") and w.len > 2) {
        // :all and :people are many users: no lan, which is a user's, and
        // no any, every port.
        const many = mem.eql(u8, w[1], ":all") or mem.eql(u8, w[1], ":people");
        var one: [1][]const u8 = undefined;
        const whos: []const []const u8 = if (mem.eql(u8, w[1], ":people")) everyone else blk: {
            one[0] = if (mem.eql(u8, w[1], ":all")) "all" else uids.get(w[1]) orelse return false;
            break :blk &one;
        };
        const public = mem.eql(u8, w[w.len - 1], "public");
        const lan = mem.eql(u8, w[w.len - 1], "lan");
        if (lan and many) return false;
        const lo = mem.eql(u8, w[w.len - 1], "loopback");
        const targets = w[2 .. w.len - @intFromBool(public or lan or lo)];
        if (targets.len == 0) return false;
        for (whos) |who| for (targets) |t| {
            if (mem.eql(u8, t, "icmp")) {
                if (public or lan or lo) return false;
                try out.append(gpa, try gpa.print("connect {s} icmp", .{who}));
                continue;
            }
            // any is every TCP port, for one user. public would refuse the
            // private networks a scan is for.
            if (mem.eql(u8, t, "any")) {
                if (public or lan or lo or many) return false;
                try out.append(gpa, try gpa.print("connect {s} tcp any", .{who}));
                continue;
            }
            const proto = if (mem.startsWith(u8, t, "udp/")) "udp" else "tcp";
            if (lan and !mem.eql(u8, proto, "udp")) return false;
            if (lo and !mem.eql(u8, proto, "tcp")) return false;
            const p = port(t, if (proto[0] == 'u') "udp/" else "tcp/") orelse return false;
            try out.append(gpa, try gpa.print(
                "connect {s} {s} {d}{s}",
                .{
                    who,
                    proto,
                    p,
                    if (public) " public" else if (lan) " lan" else if (lo) " loopback" else "",
                },
            ));
        };
        return true;
    }
    return false;
}

/// port parses prefix followed by a port of 1 to 65535, or returns null.
fn port(word: []const u8, prefix: []const u8) ?u16 {
    if (!mem.startsWith(u8, word, prefix) or word.len == prefix.len) return null;
    for (word[prefix.len..]) |c| if (!std.ascii.isDigit(c)) return null;
    const n = std.fmt.parseInt(u32, word[prefix.len..], 10) catch return null;
    return if (n >= 1 and n <= 65535) @intCast(n) else null;
}

const testing = std.testing;

/// testForm makes a form from form.yaml text alone, for functions that read
/// only its spec.
fn testForm(gpa: Allocator, name: []const u8, yaml: []const u8) !Form {
    var diag: form.Diagnostic = .{};
    return .{ .name = name, .dir = name, .spec = try form.parse(gpa, yaml, &diag) };
}

test "cmdline: what each allowance takes back, by arch" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const base = "proc_mem.force_override=never slab_nomerge page_alloc.shuffle=1";
    for ([_]struct { []const []const u8, Arch, []const u8 }{
        .{ &.{}, .aarch64, base ++ " kvm-arm.mode=none loglevel=5" },
        .{ &.{"kvm"}, .aarch64, base ++ " loglevel=5" },
        .{ &.{ "kvm", "nested-kvm" }, .aarch64, base ++ " kvm-arm.mode=nested loglevel=5" },
        .{ &.{}, .x86_64, base ++ " clearcpuid=vmx,svm loglevel=5" },
        .{ &.{"kvm"}, .x86_64, base ++ " kvm_intel.nested=0 kvm_amd.nested=0 loglevel=5" },
        .{
            &.{ "kvm", "nested-kvm" },
            .x86_64,
            base ++ " kvm_intel.nested=1 kvm_amd.nested=1 loglevel=5",
        },
    }) |c| try testing.expectEqualStrings(c[2], try cmdline(gpa, c[0], c[1]));
}

test "compose links each narrowed program to leash" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    const app = "exec /usr/bin/app\nuser app\nrun /usr/bin/ffmpeg /usr/bin/cat\n" ++
        "pledge stdio rpath exec landlock seccomp\n" ++
        "narrow /usr/bin/ffmpeg pledge stdio rpath\nnarrow /usr/bin/cat pledge stdio\n";
    for ([_][2][]const u8{
        .{ "forms/x/form.yaml", "" },
        .{ "forms/x/rootfs/etc/sv/app/service", app },
        .{ "forms/x/rootfs/etc/sv/web/service", "exec /usr/bin/web\nuser web\npledge stdio\n" },
    }) |file| {
        try tmp.dir.createDirPath(io, std.fs.path.dirname(file[0]).?);
        try tmp.dir.writeFile(io, .{ .sub_path = file[0], .data = file[1] });
    }
    var f: Failure = .{};
    const forms = try form.chain(io, gpa, tmp.dir, "x", &f);
    var ro = try tmp.dir.createDirPathOpen(io, "ro", .{});
    defer ro.close(io);
    var meta = try tmp.dir.createDirPathOpen(io, "meta", .{});
    defer meta.close(io);
    const image: Accounts = .{
        .passwd = "root:x:0:0::/:/sbin/nologin\n",
        .group = "root:x:0:\n",
        .shadow = "",
    };
    try compose(io, gpa, tmp.dir, forms, image, ro, meta, .{ .arch = .x86_64 }, &f);
    var buf: [64]u8 = undefined;
    for ([_][]const u8{ "ffmpeg", "cat" }) |p| try testing.expectEqualStrings(
        "/usr/lib/werewolf/leash",
        buf[0..try ro.readLink(io, try gpa.print("etc/sv/app/narrow/{s}", .{p}), &buf)],
    );
    // A service that narrows nothing has no narrow directory.
    try testing.expectError(error.FileNotFound, ro.access(io, "etc/sv/web/narrow", .{}));
}

test "form overlays replace vendor image files in the root and staged update" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    for ([_][2][]const u8{
        .{ "forms/x/form.yaml", "" },
        .{ "vendor/oci/x/etc/config", "vendor" },
        .{ "forms/x/rootfs/oci/x/etc/config", "confined" },
    }) |file| {
        try tmp.dir.createDirPath(io, std.fs.path.dirname(file[0]).?);
        try tmp.dir.writeFile(io, .{ .sub_path = file[0], .data = file[1] });
    }
    try tmp.dir.createDirPath(io, "vendor/oci/x/usr/bin");
    try tmp.dir.createDirPath(io, "forms/x/rootfs/oci/x/usr/bin");
    try tmp.dir.symLink(io, "vendor-shell", "vendor/oci/x/usr/bin/sh", .{});
    try tmp.dir.symLink(io, "/usr/lib/werewolf/probe", "forms/x/rootfs/oci/x/usr/bin/sh", .{});
    var failure: Failure = .{};
    const forms = try gpa.dupe(Form, try form.chain(io, gpa, tmp.dir, "x", &failure));
    forms[0].images = &.{"vendor"};
    var ro = try tmp.dir.createDirPathOpen(io, "ro", .{});
    defer ro.close(io);
    var meta = try tmp.dir.createDirPathOpen(io, "meta", .{});
    defer meta.close(io);
    try compose(
        io,
        gpa,
        tmp.dir,
        forms,
        .{ .passwd = "", .group = "", .shadow = "" },
        ro,
        meta,
        .{ .arch = .aarch64 },
        &failure,
    );
    var text: [64]u8 = undefined;
    try testing.expectEqualStrings("confined", try ro.readFile(io, "oci/x/etc/config", &text));
    try testing.expectEqualStrings(
        "/usr/lib/werewolf/probe",
        text[0..try ro.readLink(io, "oci/x/usr/bin/sh", &text)],
    );
    try testing.expectEqualStrings(
        "confined",
        try meta.readFile(io, "usr/share/werewolf/forms/x/rootfs/oci/x/etc/config", &text),
    );
    try testing.expectEqualStrings("/usr/lib/werewolf/probe", text[0..try meta.readLink(
        io,
        "usr/share/werewolf/forms/x/rootfs/oci/x/usr/bin/sh",
        &text,
    )]);
}

test "allowances: along the chain, sorted, once each; nested-kvm needs kvm" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    var f: Failure = .{};
    const got = try allowances(gpa, &.{
        try testForm(gpa, "jre", "allow: [jit, pty]\n"),
        try testForm(gpa, "mine", "allow: [packet, jit]\n"),
    }, &f);
    try testing.expectEqual(3, got.len);
    for ([_][]const u8{
        "jit",
        "packet",
        "pty",
    }, got) |want, g| try testing.expectEqualStrings(want, g);
    try testing.expectError(error.Form, allowances(gpa, &.{
        try testForm(gpa, "vm", "allow: [nested-kvm]\n"),
    }, &f));
}

test "net: users as uids, ports as numbers, sorted, once each; what cannot compile fails" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const passwd = "root:x:0:0:root:/root:/sbin/nologin\n_update:x:69:69::/var/empty:/sbin/nolog" ++
        "in\n" ++
        "web:x:300:300::/var/empty:/sbin/nologin\n";
    const with_unwound = passwd ++ "_unwoundnet:x:54:54::/var/empty:/sbin/nologin\n";
    var f: Failure = .{};
    const got = try net(gpa, &.{
        try testForm(
            gpa,
            "prod",
            "net:\n  - connect _update tcp/443\n  - lookup _update Packages.Wolfi.dev.\n",
        ),
        try testForm(gpa, "web", "net:\n  - listen tcp/08080 # leading zeros\n" ++
            "  - listen tcp/5432 loopback\n  - connect web tcp/443 public\n  - connect :all " ++
            "icmp\n" ++
            "  - metadata web\n  - connect _update tcp/443\n  - listen root udp/51820\n" ++
            "  - lookup root *.example.com TXT\n"),
    }, with_unwound, &f);
    // unwound's upstream user alone reaches the resolvers; it answers at 53.
    try testing.expectEqualStrings(
        "connect 300 tcp 443 public\nconnect 69 tcp 443\n" ++
            "connect all icmp\ndns 54\nlisten 0 udp 51820\nlisten tcp 53 loopback\nlisten tcp " ++
            "5432 " ++
            "loopback\nlisten tcp 8080\nlookup 0 *.example.com TXT\nlookup 69 " ++
            "packages.wolfi.dev A AAAA\n" ++
            "metadata 300\n",
        got,
    );
    // Without unwound's account, no grant can be kept.
    try testing.expectError(error.Form, net(gpa, &.{
        try testForm(gpa, "prod", "net:\n  - lookup root a.example\n"),
    }, "root:x:0:0:root:/root:/sbin/nologin\n", &f));
    // dns grants, and connect dns, would reach resolvers past unwound.
    for ([_][]const u8{
        "net:\n  - dns _update\n",
        "net:\n  - dns root\n",
        "services:\n  worker:\n    user: web\n    exec: /worker\n    connect: dns tcp/443\n",
    }) |yaml| {
        try testing.expectError(
            error.Form,
            net(gpa, &.{try testForm(gpa, "old", yaml)}, passwd, &f),
        );
        try testing.expect(mem.find(u8, f.text, "is gone") != null);
    }
    // A service's grants are its user's; root's would be everyone's.
    for ([_][]const u8{
        "services:\n  worker:\n    exec: /worker\n    lookup: a.example\n",
        "services:\n  worker:\n    user: root\n    exec: /worker\n    lookup: a.example\n",
        "services:\n  worker:\n    user: web\n    shared-user: true\n" ++
            "    exec: /worker\n    lookup: a.example\n",
        "services:\n  worker:\n    user: web\n    exec: /worker\n    lookup: a.example ANY\n",
        "net:\n  - lookup root a.example AXFR\n",
        "net:\n  - lookup root a.example unfiltered\n",
        "net:\n  - lookup nobody a.example\n",
        "net:\n  - lookup root\n",
    }) |yaml| try testing.expectError(
        error.Form,
        net(gpa, &.{try testForm(gpa, "bad", yaml)}, with_unwound, &f),
    );
    const looker = try net(gpa, &.{try testForm(gpa, "looker", "services:\n  worker:\n    user: " ++
        "web\n" ++
        "    exec: /worker\n    lookup: [api.example.com, \"_acme.example.org TXT\", \"* all " ++
        "unfiltered\"]\n")}, with_unwound, &f);
    try testing.expect(mem.find(u8, looker, "lookup 300 api.example.com A AAAA\n") != null);
    try testing.expect(mem.find(u8, looker, "lookup 300 _acme.example.org TXT\n") != null);
    try testing.expect(mem.find(
        u8,
        looker,
        "lookup 300 * A AAAA CNAME MX TXT SRV NS PTR CAA TLSA unfiltered\n",
    ) != null);
    const direct_form = try testForm(gpa, "resolver", "services:\n  resolver:\n" ++
        "    user: web\n    exec: /resolver\n    listen: [tcp/53 udp/53 lan]\n" ++
        "    dns-direct: true\n    connect: [udp/53 tcp/53 tcp/853]\n" ++
        "    lookup: \"*\"\n");
    const direct_policy = try net(gpa, &.{direct_form}, with_unwound, &f);
    try testing.expect(mem.find(u8, direct_policy, "dns-direct 300\n") != null);
    try testing.expect(mem.find(u8, direct_policy, "listen tcp 53 lan\n") != null);
    try testing.expect(mem.find(u8, direct_policy, "listen 300 udp 53 lan\n") != null);
    try testing.expect(mem.find(u8, direct_policy, "connect 300 udp 53\n") != null);
    try testing.expect(mem.find(u8, direct_policy, "connect 300 tcp 853\n") != null);
    try testing.expect(mem.find(u8, direct_policy, "lookup 300 * A AAAA\n") != null);
    try testing.expectError(error.Form, net(gpa, &.{try testForm(gpa, "bad", "services:\n" ++
        "  worker:\n    user: web\n    exec: /worker\n    connect: udp/53\n")}, with_unwound, &f));
    try testing.expectError(error.Form, net(gpa, &.{try testForm(gpa, "bad", "net:\n" ++
        "  - dns-direct web\nservices:\n  worker:\n    user: web\n")}, with_unwound, &f));
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const direct_service = try form.services(testing.io, gpa, tmp.dir, &.{direct_form}, &f);
    try testing.expect(mem.find(u8, direct_service[0].text, "dns-direct") == null);
    const ephemeral = try testForm(
        gpa,
        "worker",
        "services:\n  worker:\n    user: web\n    exec: /worker\n" ++
            "    pledge: stdio inet listen\n    listen: [tcp/0 loopback, tcp/8080 loopback, " ++
            "udp/5353 loopback]\n",
    );
    // The service may request a temporary port, but no port zero or range
    // is published or forwarded.
    try testing.expectEqualStrings(
        "listen tcp 8080 loopback\n",
        try net(gpa, &.{ephemeral}, passwd, &f),
    );
    try testing.expectEqualSlices(u16, &.{}, try form.listens(gpa, &.{ephemeral}, &f));
    const rendered = try form.services(testing.io, gpa, tmp.dir, &.{ephemeral}, &f);
    var bad: service.Bad = .{};
    const worker = try service.parse(gpa, rendered[0].text, &bad);
    try testing.expectEqualSlices(u16, &.{ 0, 8080 }, worker.listen);
    try testing.expectEqualSlices(u16, &.{5353}, worker.listen_udp);
    try testing.expectEqualSlices(u16, &.{5353}, rendered[0].loopback_udp);
    _ = try pledge(testing.io, gpa, tmp.dir, &.{ephemeral}, &f);
    const discovery = try testForm(
        gpa,
        "discovery",
        "services:\n  discovery:\n    user: web\n    exec: /discovery\n" ++
            "    pledge: stdio inet listen connect\n" ++
            "    listen: [udp/5353 udp/1900 lan]\n    connect: [udp/5353 udp/1900 lan]\n",
    );
    try testing.expectEqualStrings(
        "connect 300 udp 1900 lan\nconnect 300 udp 5353 lan\n" ++
            "listen 300 udp 1900 lan\nlisten 300 udp 5353 lan\n",
        try net(gpa, &.{discovery}, passwd, &f),
    );
    // UDP scopes belong to fence, not leash or host TCP forwards.
    const ds = try form.services(testing.io, gpa, tmp.dir, &.{discovery}, &f);
    try testing.expect(mem.find(u8, ds[0].text, "lan") == null);
    try testing.expectEqualSlices(u16, &.{}, try form.listens(gpa, &.{discovery}, &f));
    _ = try pledge(testing.io, gpa, tmp.dir, &.{discovery}, &f);
    for ([_][]const u8{
        "listen udp/53",                   "listen tcp/0",
        "listen tcp/65536",                "listen loopback",
        "connect nobody tcp/443",          "connect web icmp public",
        "connect web public",              "metadata nobody",
        "serve tcp/80",                    "connect web sctp/9",
        "listen tcp/",                     "listen tcp/99999999999999999999",
        "listen nobody udp/53",            "listen root udp/0",
        "listen root tcp/53",              "listen root udp/53 loopback",
        "connect web udp/53",              "connect web tcp/53",
        "connect web tcp/853",             "connect :all udp/853",
        "listen root lan",                 "connect web tcp/80 lan",
        "connect :all udp/5353 lan",       "connect web icmp lan",
        "connect web udp/5353 public lan", "connect :all any",
        "connect :people any",             "connect :people udp/5353 lan",
        "lookup :all a.example A AAAA",    "metadata :people",
        "listen :people udp/53",           "connect :nobody tcp/443",
    }) |line| {
        const forms = [_]Form{try testForm(gpa, "bad", try gpa.print("net:\n  - {s}\n", .{line}))};
        try testing.expectError(error.Form, net(gpa, &forms, with_unwound, &f));
        try testing.expect(mem.endsWith(u8, f.text, line));
    }
    // :people is every person's uid range, NoCloud's and named people's.
    const play = try testForm(
        gpa,
        "play",
        "net:\n  - connect :people tcp/443\n  - lookup :people *\n",
    );
    try testing.expectEqualStrings(
        "connect 500-60000 tcp 443\nconnect 65536-1073741823 tcp 443\ndns 54\n" ++
            "listen tcp 53 loopback\nlookup 500-60000 * A AAAA\nlookup 65536-1073741823 * A AAAA\n",
        try net(gpa, &.{play}, with_unwound, &f),
    );
    // An account among those ranges would share people's grants.
    try testing.expectError(error.Form, net(
        gpa,
        &.{play},
        with_unwound ++ "demo:x:590:590::/var/empty:/sbin/nologin\n",
        &f,
    ));
    try testing.expect(mem.find(u8, f.text, "account demo has uid 590") != null);
    // A loopback-only grant goes beside a broader one to the same users or
    // to all; all's beside another user's broader grant would take it.
    for ([_]struct { []const u8, []const u8 }{
        .{
            "  - connect :people tcp/22 loopback\n  - connect :people tcp/22\n",
            "connect 500-60000 tcp 22\nconnect 65536-1073741823 tcp 22\n",
        },
        .{ "  - connect web tcp/22 loopback\n  - connect :all tcp/22\n", "connect all tcp 22\n" },
        .{
            "  - connect web tcp/22 loopback\n  - connect root tcp/22\n",
            "connect 0 tcp 22\nconnect 300 tcp 22 loopback\n",
        },
        .{
            "  - connect web tcp/22 loopback\n  - connect web tcp/443\n",
            "connect 300 tcp 22 loopback\nconnect 300 tcp 443\n",
        },
    }) |c| try testing.expectEqualStrings(
        c[1],
        try net(gpa, &.{try testForm(gpa, "su", try gpa.print("net:\n{s}", .{c[0]}))}, passwd, &f),
    );
    try testing.expectError(error.Form, net(gpa, &.{try testForm(
        gpa,
        "su",
        "net:\n  - connect :all tcp/22 loopback\n  - connect root tcp/22\n",
    )}, passwd, &f));
    try testing.expect(mem.find(u8, f.text, "though connect 0 tcp 22 grants it") != null);
    // Bare all and people are accounts' names, as any other word is.
    const named = try testForm(gpa, "named", "net:\n  - connect all tcp/443\n");
    try testing.expectEqualStrings(
        "connect 400 tcp 443\n",
        try net(gpa, &.{named}, passwd ++ "all:x:400:400::/var/empty:/sbin/nologin\n", &f),
    );
    try testing.expectError(error.Form, net(gpa, &.{named}, passwd, &f));
    try testing.expect(mem.endsWith(u8, f.text, "(every user is :all, every person :people)"));
}

test "accounts: no account but root in group 0; a name or id twice refused" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    var f: Failure = .{};
    try testing.expectEqualStrings(
        "root:x:0:0:root:/root:/sbin/nologin\nsync:x:5:65533:sync:/sbin:/bin/sync\n" ++
            "web:x:300:300::/var/empty:/sbin/nologin\n",
        try accounts(gpa, "root:x:0:0:root:/root:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync" ++
            "\n" ++
            "web:x:300:300::/var/empty:/sbin/nologin\n", &f),
    );
    try testing.expectError(error.Form, accounts(gpa, "a:x:1:1::/:/x\na:x:2:2::/:/x\n", &f));
    try testing.expectError(error.Form, accounts(gpa, "a:x:1:1::/:/x\nb:x:1:2::/:/x\n", &f));
    try testing.expectEqualStrings(
        "passwd: b or its id 1 is there twice: a bundle's forms disagree",
        f.text,
    );
    try testing.expectError(error.Form, unique(gpa, "group", "a:x:7:\nb:x:7:\n", &f));
}

test "prune: relative and clean paths only" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    var f: Failure = .{};
    const got = try prune(gpa, &.{try testForm(gpa, "valkey", "prune:\n  - usr/bin/bash\n")}, &f);
    try testing.expectEqualStrings("usr/bin/bash", got[0]);
    const spaced = try prune(
        gpa,
        &.{try testForm(gpa, "plex", "prune:\n  - usr/lib/plexmediaserver/Plex Script Host\n")},
        &f,
    );
    try testing.expectEqual(1, spaced.len);
    try testing.expectEqualStrings("usr/lib/plexmediaserver/Plex Script Host", spaced[0]);
    for ([_][]const u8{ "/usr/bin/bash", "./usr", "../etc", "usr/", "usr/..", "usr/." }) |p| {
        const forms = [_]Form{try testForm(gpa, "bad", try gpa.print("prune:\n  - {s}\n", .{p}))};
        try testing.expectError(error.Form, prune(gpa, &forms, &f));
    }
}

test "weaknesses: the form's own, then every form's and its arch's from posture-known" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const top = try testForm(gpa, "sshd", "weaknesses:\n  programs-no-shell: a shell for logins\n");
    const known = "# comment: * and arch lines\n" ++
        "* ?files-x ?boot-secure-boot boot-rollback-protected\n" ++
        "x86_64 kernel-y\naarch64 kernel-z\n";
    try testing.expectEqualStrings(
        "programs-no-shell a shell for logins\n?files-x every form on aarch64 " ++
            "(test/posture-known)\n" ++
            "?boot-secure-boot Secure Boot is phase 5 of the boot design, not built: " ++
            "this image is not signed for it\n" ++
            "boot-rollback-protected no TPM counter guards the slot serial yet: " ++
            "phase 5 of the boot design\n" ++
            "kernel-z every form on aarch64 (test/posture-known)\n",
        try weaknesses(gpa, top, .{ .arch = .aarch64, .posture_known = known }),
    );
    // Developer SSH adds its own, and takes the same lines as any build.
    const dev = try weaknesses(gpa, top, .{ .arch = .x86_64, .dev = true, .posture_known = known });
    try testing.expect(mem.startsWith(u8, dev, "programs-no-shell a shell for logins\n" ++
        "network-no-login authenticated SSH for local test iteration\n"));
    try testing.expect(mem.endsWith(
        u8,
        dev,
        "kernel-y every form on x86_64 (test/posture-known)\n",
    ));
}

test "staged developer SSH preserves chain order and never enters production" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    for ([_][2][]const u8{
        .{ "forms/base/form.yaml", "" },
        .{ "forms/app/form.yaml", "base: base\n" },
    }) |file| {
        try tmp.dir.createDirPath(io, std.fs.path.dirname(file[0]).?);
        try tmp.dir.writeFile(io, .{ .sub_path = file[0], .data = file[1] });
    }
    var f: Failure = .{};
    // Development images from before SSH injection still reconstruct.
    const old = try stagedChain(io, gpa, tmp.dir, "app", true, &f);
    try testing.expectEqual(@as(usize, 2), old.len);
    try tmp.dir.createDirPath(io, "forms/howl-dev");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/howl-dev/form.yaml", .data = "base: base\n" });
    const dev = try stagedChain(io, gpa, tmp.dir, "app", true, &f);
    try testing.expectEqual(@as(usize, 3), dev.len);
    for (dev, [_][]const u8{ "base", "howl-dev", "app" }) |fm, name|
        try testing.expectEqualStrings(name, fm.name);
    const prod = try stagedChain(io, gpa, tmp.dir, "app", false, &f);
    try testing.expectEqual(@as(usize, 2), prod.len);
    try testing.expect(!hasForm(prod, "howl-dev"));
    // A leaf that already references the layer must not acquire it twice.
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/app/form.yaml",
        .data = "base: base\nwith: [howl-dev]\n",
    });
    const linked = try stagedChain(io, gpa, tmp.dir, "app", true, &f);
    try testing.expectEqual(@as(usize, 3), linked.len);
    try testing.expectEqualStrings("app", linked[2].name);
}

test "developer access is SSH alone: shell-free posture, and sh-shim" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/x");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/x/form.yaml", .data = "" });
    var f: Failure = .{};
    const forms = try form.chain(io, gpa, tmp.dir, "x", &f);
    var ro = try tmp.dir.createDirPathOpen(io, "ro", .{});
    defer ro.close(io);
    var meta = try tmp.dir.createDirPathOpen(io, "meta", .{});
    defer meta.close(io);
    try compose(io, gpa, tmp.dir, forms, .{
        .passwd = baselayout.passwd,
        .group = baselayout.group,
        .shadow = baselayout.shadow,
    }, ro, meta, .{
        .arch = .aarch64,
        .dev = true,
        .posture_known = "* boot-ipe-enforced\n",
    }, &f);
    const passwd = try ro.readFileAlloc(io, "usr/share/werewolf/etc/passwd", gpa, .limited(4096));
    try testing.expect(mem.find(u8, passwd, "/root:/usr/lib/werewolf/sh-shim\n") != null);
    try testing.expectEqualStrings(
        "ssh\n",
        try meta.readFileAlloc(io, "usr/share/werewolf/dev", gpa, .limited(32)),
    );
    const known = try meta.readFileAlloc(io, "usr/share/werewolf/weaknesses", gpa, .limited(4096));
    try testing.expect(mem.find(u8, known, "network-no-login ") != null);
    try testing.expect(mem.find(u8, known, "files-noexec-everywhere ") != null);
    try testing.expect(mem.find(u8, known, "programs-no-shell ") == null);
    try testing.expect(mem.find(u8, known, "programs-no-interpreters ") == null);
}

test "IPE builds retain unrelated weaknesses and remove closed kernel gaps" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const top = try testForm(gpa, "minimal", "weaknesses:\n  programs-no-shell: deliberate\n");
    const got = try weaknesses(gpa, top, .{
        .arch = .aarch64,
        .ipe = true,
        .posture_known = "* boot-ipe-enforced boot-rollback-protected\n",
    });
    try testing.expect(mem.find(u8, got, "boot-ipe-enforced") == null);
    try testing.expect(mem.find(u8, got, "boot-rollback-protected") != null);
    try testing.expect(mem.find(u8, got, "programs-no-shell deliberate") != null);
    const protected = try weaknesses(gpa, top, .{
        .arch = .aarch64,
        .ipe = true,
        .tpm = true,
        .posture_known = "* boot-ipe-enforced boot-rollback-protected\n",
    });
    try testing.expect(mem.find(u8, protected, "boot-ipe-enforced") == null);
    try testing.expect(mem.find(u8, protected, "boot-rollback-protected") == null);
    try testing.expect(mem.find(u8, protected, "programs-no-shell deliberate") != null);
}

test "pledge: a path inside a strict service's directory fails the build" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/x/rootfs/etc/sv/db");
    try tmp.dir.createDirPath(io, "forms/x/rootfs/etc/sv/web");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/x/form.yaml", .data = "" });
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/x/rootfs/etc/sv/web/service",
        .data = "exec /w\nuser web\npledge stdio\nread /data/svc/web/a /data/svc /data/svc/db/x\n",
    });
    for ([_]struct { db: []const u8, fails: bool }{
        .{ .db = "", .fails = true },
        .{ .db = "share strict\n", .fails = true },
        .{ .db = "share shared\n", .fails = false },
        .{ .db = "share browseable\n", .fails = false },
    }) |c| {
        try tmp.dir.writeFile(io, .{
            .sub_path = "forms/x/rootfs/etc/sv/db/service",
            .data = try gpa.print("exec /d\nuser db\npledge stdio rpath\n{s}", .{c.db}),
        });
        var f: Failure = .{};
        const forms = try form.chain(io, gpa, tmp.dir, "x", &f);
        const got = pledge(io, gpa, tmp.dir, forms, &f);
        if (c.fails) {
            try testing.expectError(error.Form, got);
            try testing.expect(mem.find(u8, f.text, "/data/svc/db/x") != null);
        } else try testing.expectEqualStrings("stdio rpath\n", try got);
    }
}

test "privileges: a memfd promise needs the jit allowance" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/x/rootfs/etc/sv/app");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/x/form.yaml", .data = "" });
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/x/rootfs/etc/sv/app/service",
        .data = "exec /a\nuser app\npledge stdio memfd\n",
    });
    var f: Failure = .{};
    const forms = try form.chain(io, gpa, tmp.dir, "x", &f);
    try testing.expectError(error.Form, privileges(io, gpa, tmp.dir, forms, &.{}, false, &f));
    try testing.expect(mem.find(u8, f.text, "pledge memfd") != null);
    try privileges(io, gpa, tmp.dir, forms, &.{"jit"}, false, &f);
}

test "privileges: the developer SSH listener needs an explicit development build" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/x/rootfs/etc/sv/sshd-dev");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/x/form.yaml", .data = "" });
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/x/rootfs/etc/sv/sshd-dev/service",
        .data = "exec /usr/bin/sshd\nuser root\ncaps login\npledge stdio\n",
    });
    var failure: Failure = .{};
    const chain = try form.chain(io, gpa, tmp.dir, "x", &failure);
    try testing.expectError(
        error.Form,
        privileges(io, gpa, tmp.dir, chain, &.{"pty"}, false, &failure),
    );
    try testing.expectError(error.Form, privileges(io, gpa, tmp.dir, chain, &.{}, true, &failure));
    try privileges(io, gpa, tmp.dir, chain, &.{"pty"}, true, &failure);
}

test "privileges: fixed export SSH needs no terminal and grants no other root service" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/data-export/rootfs/etc/sv/sshd");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/data-export/form.yaml", .data = "" });
    const listener = "exec /usr/bin/sshd\nuser root\ncaps login\npledge stdio\n";
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "forms/data-export/rootfs/etc/sv/sshd/service", .data = listener },
    );
    var failure: Failure = .{};
    const chain = try form.chain(io, a, tmp.dir, "data-export", &failure);
    try privileges(io, a, tmp.dir, chain, &.{}, false, &failure);
    try tmp.dir.createDirPath(io, "forms/data-export/rootfs/etc/sv/other");
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "forms/data-export/rootfs/etc/sv/other/service", .data = listener },
    );
    try testing.expectError(error.Form, privileges(io, a, tmp.dir, chain, &.{}, false, &failure));
}

test "privileges: caddy may not read another service's /data tree" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/x/rootfs/etc/sv/caddy");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/x/form.yaml", .data = "" });
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/x/rootfs/etc/sv/caddy/service",
        .data = "exec /usr/bin/caddy\nuser caddy\npledge stdio rpath\n" ++
            "read /etc/caddy /data/svc/app/public\n",
    });
    var failure: Failure = .{};
    const chain = try form.chain(io, a, tmp.dir, "x", &failure);
    try testing.expectError(error.Form, privileges(io, a, tmp.dir, chain, &.{}, false, &failure));
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/x/rootfs/etc/sv/caddy/service",
        .data = "exec /usr/bin/caddy\nuser caddy\npledge stdio rpath\nread /etc/caddy\n",
    });
    const ok_chain = try form.chain(io, a, tmp.dir, "x", &failure);
    try privileges(io, a, tmp.dir, ok_chain, &.{}, false, &failure);
}

test "apko: a service user apko.yaml does not name gets an account, its id its name's hash" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    const declared =
        \\accounts:
        \\  groups:
        \\    - groupname: web
        \\      gid: 80
        \\  users:
        \\    - username: web
        \\      uid: 80
        \\      homedir: /var/empty
        \\
    ;
    try tmp.dir.createDirPath(io, "forms/x/rootfs/etc/sv/web");
    try tmp.dir.createDirPath(io, "forms/x/rootfs/etc/sv/db");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/x/form.yaml", .data = declared });
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/x/rootfs/etc/sv/web/service",
        .data = "exec /w\nuser web\npledge stdio\n",
    });
    const db_service = "forms/x/rootfs/etc/sv/db/service";
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = db_service, .data = "exec /d\nuser db\npledge stdio\n" },
    );
    var f: Failure = .{};
    const forms = try form.chain(io, gpa, tmp.dir, "x", &f);
    const merged = try apko(io, gpa, tmp.dir, forms, &.{}, &f);
    const id = defaultId("db");
    try testing.expect(id >= 1 << 30 and id < 1 << 31);
    try testing.expectEqual(id, defaultId("db")); // stable
    try testing.expect(defaultId("db") != defaultId("dc"));
    const acc = merged.get("accounts").?;
    const users = acc.get("users").?.list;
    try testing.expectEqual(2, users.len);
    try testing.expectEqualStrings("web", users[0].get("username").?.scalar.text);
    try testing.expectEqualStrings("db", users[1].get("username").?.scalar.text);
    try testing.expectEqualStrings(try gpa.print("{d}", .{id}), users[1].get("uid").?.scalar.text);
    try testing.expectEqualStrings("/var/empty", users[1].get("homedir").?.scalar.text);
    try testing.expectEqualStrings(
        "db",
        acc.get("groups").?.list[1].get("groupname").?.scalar.text,
    );
    // withAccounts adds the default accounts as the apko tool would.
    const accts = try withAccounts(io, gpa, tmp.dir, forms, .{
        .passwd = "root:x:0:0:root:/root:/bin/sh\n",
        .group = "root:x:0:root\n",
        .shadow = "root:*::0:::::\n",
    }, &f);
    try testing.expect(mem.find(u8, accts.passwd, try gpa.print(
        "db:x:{d}:{d}:Account created by apko:/var/empty:/sbin/nologin\n",
        .{ id, id },
    )) != null);

    // A service joins another's group; never a group no service runs as,
    // nor its own.
    for ([_]struct { text: []const u8, refused: ?[]const u8 }{
        .{ .text = "exec /d\nuser db\npledge stdio\ngroup web\n", .refused = null },
        .{
            .text = "exec /d\nuser db\npledge stdio\ngroup shadow\n",
            .refused = "no service runs as shadow",
        },
        .{ .text = "exec /d\nuser db\npledge stdio\ngroup db\n", .refused = "group db is its own" },
    }) |case| {
        try tmp.dir.writeFile(io, .{ .sub_path = db_service, .data = case.text });
        if (case.refused) |why| {
            try testing.expectError(error.Form, apko(io, gpa, tmp.dir, forms, &.{}, &f));
            try testing.expect(mem.find(u8, f.text, why) != null);
        } else _ = try apko(io, gpa, tmp.dir, forms, &.{}, &f);
    }

    // Two services running as one user are refused.
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = db_service, .data = "exec /d\nuser web\npledge stdio\n" },
    );
    try testing.expectError(error.Form, apko(io, gpa, tmp.dir, forms, &.{}, &f));
    try testing.expect(mem.find(u8, f.text, "both run as web") != null);

    // A default id that a declared account already holds is refused.
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = db_service, .data = "exec /d\nuser db\npledge stdio\n" },
    );
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/x/form.yaml",
        .data = try gpa.print("accounts:\n  users:\n    - username: old\n      uid: {d}\n", .{id}),
    });
    const again = try form.chain(io, gpa, tmp.dir, "x", &f);
    try testing.expectError(error.Form, apko(io, gpa, tmp.dir, again, &.{}, &f));
    try testing.expect(mem.find(u8, f.text, "is old's") != null);
}

test "apko: declared accounts inherit ids and keep shell and group overrides on updates" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/x");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/x/form.yaml", .data =
        \\accounts:
        \\  groups:
        \\    - groupname: worker
        \\      members: [helper]
        \\    - groupname: pinned
        \\      gid: 123
        \\    - groupname: web
        \\      gid: 456
        \\  users:
        \\    - username: worker
        \\      shell: /usr/lib/werewolf/sh-shim
        \\    - username: helper
        \\    - username: shared
        \\      gid: 123
        \\    - username: pinned
        \\      uid: 123
        \\      homedir: /var/empty
        \\      shell: /usr/bin/false
        \\services:
        \\  worker:
        \\    exec: /worker
        \\    user: worker
        \\    pledge: stdio
        \\  web:
        \\    exec: /web
        \\    user: web
        \\    pledge: stdio
        \\
    });
    var f: Failure = .{};
    const forms = try form.chain(io, gpa, tmp.dir, "x", &f);
    const merged = try apko(io, gpa, tmp.dir, forms, &.{}, &f);
    const acc = merged.get("accounts").?;
    const users = acc.get("users").?.list;
    const groups = acc.get("groups").?.list;
    try testing.expectEqual(5, users.len);
    try testing.expectEqual(4, groups.len);
    try testing.expectEqualStrings("worker", groups[0].get("groupname").?.scalar.text);
    try testing.expectEqualStrings(
        try gpa.print("{d}", .{defaultId("worker")}),
        groups[0].get("gid").?.scalar.text,
    );
    try testing.expectEqual(1, groups[0].get("members").?.list.len);
    try testing.expectEqualStrings("helper", groups[3].get("groupname").?.scalar.text);
    const empty: Accounts = .{ .passwd = "", .group = "", .shadow = "" };
    const got = try withAccounts(io, gpa, tmp.dir, forms, empty, &f);
    for ([_]struct { name: []const u8, gid: ?u32 = null, shell: []const u8 = "/sbin/nologin" }{
        .{ .name = "worker", .shell = "/usr/lib/werewolf/sh-shim" },
        .{ .name = "helper" },
        .{ .name = "shared", .gid = 123 },
        .{ .name = "web", .gid = 456 },
    }) |case| {
        const uid = defaultId(case.name);
        try testing.expect(mem.find(u8, got.passwd, try gpa.print(
            "{s}:x:{d}:{d}:Account created by apko:/var/empty:{s}\n",
            .{ case.name, uid, case.gid orelse uid, case.shell },
        )) != null);
    }
    try testing.expect(mem.find(
        u8,
        got.passwd,
        "pinned:x:123:123:Account created by apko:/var/empty:/usr/bin/false\n",
    ) != null);
    const again = try withAccounts(io, gpa, tmp.dir, forms, got, &f);
    try testing.expectEqualStrings(got.passwd, again.passwd);
    try testing.expectEqualStrings(got.group, again.group);
    try testing.expectEqualStrings(got.shadow, again.shadow);
}

test "apko: every component must opt in to a shared non-root identity" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    try tmp.dir.createDirPath(io, "forms/app");
    for ([_][2]bool{
        .{ false, false },
        .{ true, false },
        .{ false, true },
        .{ true, true },
    }) |sharing| {
        const text = try gpa.print(
            "services:\n  first:\n    exec: /a\n    user: app\n    shared-user: {s}\n    " ++
                "pledge: stdio\n  second:\n    exec: /b\n    user: app\n    shared-user: {s}\n  " ++
                "  pledge: stdio\n",
            .{ if (sharing[0]) "true" else "false", if (sharing[1]) "true" else "false" },
        );
        try tmp.dir.writeFile(
            io,
            .{
                .sub_path = "forms/app/form.yaml",
                .data = try mem.concat(gpa, u8, &.{ text, "    read: /run/svc/first\n" }),
            },
        );
        var f: Failure = .{};
        const forms = try form.chain(io, gpa, tmp.dir, "app", &f);
        if (!sharing[0] or !sharing[1]) {
            try testing.expectError(error.Form, apko(io, gpa, tmp.dir, forms, &.{}, &f));
        } else {
            const cfg = try apko(io, gpa, tmp.dir, forms, &.{}, &f);
            try testing.expectEqual(1, cfg.get("accounts").?.get("users").?.list.len);
            try testing.expectEqual(1, cfg.get("accounts").?.get("groups").?.list.len);
            _ = try pledge(io, gpa, tmp.dir, forms, &f);
        }
    }
    // Opting in does not grant access to a different UNIX identity's paths.
    try tmp.dir.writeFile(
        io,
        .{
            .sub_path = "forms/app/form.yaml",
            .data = "services:\n  first:\n    exec: /a\n    user: app\n    shared-user: true\n  " ++
                "  pledge: stdio\n  second:\n    exec: /b\n    user: other\n    shared-user: " ++
                "true\n    pledge: stdio\n    read: /run/svc/first\n",
        },
    );
    var refused: Failure = .{};
    const separate = try form.chain(io, gpa, tmp.dir, "app", &refused);
    _ = try apko(io, gpa, tmp.dir, separate, &.{}, &refused);
    try testing.expectError(error.Form, pledge(io, gpa, tmp.dir, separate, &refused));
}

test "selected account files survive wrapping the production leaf" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    for ([_][2][]const u8{
        .{ "base", "accounts:\n  groups:\n    - groupname: worker\n" ++
            "      gid: 77\n  users:\n    - username: worker\n      uid: 77\n" ++
            "      homedir: /var/empty\n      shell: /sbin/nologin\n" },
        .{ "ssh-su", "base: base\naccounts:\n  groups:\n    - groupname: agent\n" ++
            "      gid: 22\n  users:\n    - username: agent\n      uid: 22\n" ++
            "      homedir: /var/empty\n      shell: /sbin/nologin\n" },
        .{ "wrapped", "base: base\n" },
    }) |fixture| {
        const path = try gpa.print("forms/{s}/form.yaml", .{fixture[0]});
        try tmp.dir.createDirPath(io, std.fs.path.dirname(path).?);
        try tmp.dir.writeFile(io, .{ .sub_path = path, .data = fixture[1] });
    }
    var f: Failure = .{};
    const base = try form.chainSelectedIn(io, gpa, tmp.dir, "forms", "base", &.{"ssh"}, &f);
    const wrapped = try form.chainSelectedIn(io, gpa, tmp.dir, "forms", "wrapped", &.{"ssh"}, &f);
    const empty: Accounts = .{ .passwd = "", .group = "", .shadow = "" };
    const production = try withAccounts(io, gpa, tmp.dir, base, empty, &f);
    const native = try withAccounts(io, gpa, tmp.dir, wrapped, empty, &f);
    try testing.expectEqualStrings(production.passwd, native.passwd);
    try testing.expectEqualStrings(production.group, native.group);
    try testing.expectEqualStrings(production.shadow, native.shadow);
    try testing.expectEqualStrings(
        "agent:x:22:22:Account created by apko:/var/empty:/sbin/nologin\n" ++
            "worker:x:77:77:Account created by apko:/var/empty:/sbin/nologin\n",
        production.passwd,
    );
}

test "apko: omitted account ids cannot collide with an explicit uid or gid" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/x");
    inline for ([_][]const u8{
        "accounts:\n  users:\n    - username: worker\n    - username: pinned\n      uid: {d}\n",
        "accounts:\n  groups:\n    - groupname: worker\n    - groupname: pinned\n      gid: {d}\n",
        "accounts:\n  users:\n    - username: worker\n    - username: pinned\n" ++
            "      uid: 123\n      gid: {d}\n",
    }) |text| {
        try tmp.dir.writeFile(io, .{
            .sub_path = "forms/x/form.yaml",
            .data = try gpa.print(text, .{defaultId("worker")}),
        });
        var f: Failure = .{};
        const forms = try form.chain(io, gpa, tmp.dir, "x", &f);
        try testing.expectError(error.Form, apko(io, gpa, tmp.dir, forms, &.{}, &f));
        try testing.expect(mem.find(u8, f.text, "is pinned's") != null);
    }
}

test serviceDirOwner {
    try testing.expectEqualStrings("db", serviceDirOwner("/data/svc/db").?);
    try testing.expectEqualStrings("db", serviceDirOwner("/run/svc/db/run/x.sock").?);
    try testing.expectEqual(null, serviceDirOwner("/data/svc"));
    try testing.expectEqual(null, serviceDirOwner("/data/svc/"));
    try testing.expectEqual(null, serviceDirOwner("/etc/nginx"));
}

test "compose: service runtime grants stay scoped and follow whole-service replacement" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    for ([_][2][]const u8{
        .{ "base", "services:\n  search:\n    exec: /search\n    user: search\n" ++
            "    pledge: stdio\n    allow: [java:native, glibc:dlopen, glibc:ifunc]\n" ++
            "  n8n:\n    exec: /n8n\n" ++
            "    user: n8n\n    pledge: stdio\n" ++
            "    allow: [node:native, php:upload-progress, future-package2:feature-3]\n" },
        .{ "site", "base: base\nservices:\n  search:\n    exec: /search\n    user: search\n" ++
            "    pledge: stdio\n  runner:\n    exec: /runner\n    user: runner\n    pledge: " ++
            "stdio\n" },
    }) |fixture| {
        try tmp.dir.createDirPath(io, try gpa.print("forms/{s}", .{fixture[0]}));
        try tmp.dir.writeFile(io, .{
            .sub_path = try gpa.print("forms/{s}/form.yaml", .{fixture[0]}),
            .data = fixture[1],
        });
    }
    const image: Accounts = .{
        .passwd = "root:x:0:0:root:/root:/sbin/nologin\n",
        .group = "root:x:0:root\n",
        .shadow = "root:*::0:::::\n",
    };
    for ([_][]const u8{ "base", "site" }) |name| {
        var f: Failure = .{};
        const forms = try form.chain(io, gpa, tmp.dir, name, &f);
        var ro = try tmp.dir.createDirPathOpen(io, try gpa.print("{s}-ro", .{name}), .{});
        defer ro.close(io);
        var meta = try tmp.dir.createDirPathOpen(io, try gpa.print("{s}-meta", .{name}), .{});
        defer meta.close(io);
        try compose(io, gpa, tmp.dir, forms, image, ro, meta, .{ .arch = .aarch64 }, &f);
        for ([_][]const u8{
            "etc/runtime-hardening/allow/n8n/node/native",
            "etc/runtime-hardening/allow/n8n/php/upload-progress",
            "etc/runtime-hardening/allow/n8n/future-package2/feature-3",
        }) |path| try testing.expectEqualStrings("", try ro.readFileAlloc(
            io,
            path,
            gpa,
            .limited(1),
        ));
        if (mem.eql(u8, name, "base")) {
            try ro.access(io, "etc/runtime-hardening/allow/search/java/native", .{});
            try ro.access(io, "etc/runtime-hardening/allow/search/glibc/dlopen", .{});
            try ro.access(io, "etc/runtime-hardening/allow/search/glibc/ifunc", .{});
        } else {
            try testing.expectError(error.FileNotFound, ro.access(
                io,
                "etc/runtime-hardening/allow/search",
                .{},
            ));
        }
        for ([_][]const u8{ "all", "runner" }) |ns| try testing.expectError(
            error.FileNotFound,
            ro.access(io, try gpa.print("etc/runtime-hardening/allow/{s}", .{ns}), .{}),
        );
    }
}

test "compose: ro and meta from a chain and a package-only image's accounts" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    const web_apko =
        \\accounts:
        \\  groups:
        \\    - groupname: web
        \\      gid: 80
        \\  users:
        \\    - username: web
        \\      uid: 80
        \\      homedir: /var/empty
        \\      shell: /sbin/nologin
        \\
    ;
    const web_form =
        \\base: minimal
        \\allow: [jit, php:exec, glibc:ifunc, future-package2:feature-3]
        \\net:
        \\  - listen tcp/80
        \\  - connect web tcp/443
        \\
    ;
    const web_service = "exec /usr/bin/web\nuser web\nlisten tcp/80\npledge stdio inet listen\n";
    for ([_][2][]const u8{
        .{ "forms/minimal/form.yaml", "" },
        .{ "forms/minimal/rootfs/etc/sv/minimal/run", "minimal's\n" },
        .{ "forms/minimal/rootfs/etc/motd", "minimal's\n" },
        .{ "forms/web/form.yaml", web_form ++ web_apko },
        .{ "forms/web/rootfs/etc/sv/web/service", web_service },
        .{ "forms/web/rootfs/etc/motd", "web's\n" },
    }) |file| {
        try tmp.dir.createDirPath(io, std.fs.path.dirname(file[0]).?);
        try tmp.dir.writeFile(io, .{ .sub_path = file[0], .data = file[1] });
    }
    try tmp.dir.symLink(io, "/run/werewolf/passwd", "forms/minimal/rootfs/etc/passwd", .{});
    var f: Failure = .{};
    const forms = try form.chain(io, gpa, tmp.dir, "web", &f);
    var ro = try tmp.dir.createDirPathOpen(io, "ro", .{});
    defer ro.close(io);
    var meta = try tmp.dir.createDirPathOpen(io, "meta", .{});
    defer meta.close(io);
    // The packages' accounts, as apk leaves them on a machine: no web account.
    const image: Accounts = .{
        .passwd = "root:x:0:0:root:/root:/bin/sh\nsync:x:5:0:sync:/sbin:/bin/sync\n",
        .group = "root:x:0:root\n",
        .shadow = "root:*::0:::::\n",
    };
    const b: Build = .{ .arch = .aarch64, .posture_known = "* files-x\naarch64 kernel-y\n" };
    try compose(io, gpa, tmp.dir, forms, image, ro, meta, b, &f);

    const added = "web:x:80:80:Account created by apko:/var/empty:/sbin/nologin\n";
    var buf: [64]u8 = undefined;
    for ([_][2][]const u8{
        // Each form's rootfs, base first, later forms winning.
        .{ "etc/motd", "web's\n" },
        .{ "etc/sv/minimal/run", "minimal's\n" },
        .{ "etc/sv/web/service", web_service },
        .{ "etc/werewolf/allow/jit", "" },
        // A runtime's allowance, in the portable tree, blanket (namespace all).
        .{ "etc/runtime-hardening/allow/all/php/exec", "" },
        .{ "etc/runtime-hardening/allow/all/glibc/ifunc", "" },
        .{ "etc/runtime-hardening/allow/all/future-package2/feature-3", "" },
        // The chain's accounts are added as apko adds them; only root is in group 0.
        .{ "usr/share/werewolf/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n" ++
            "sync:x:5:65533:sync:/sbin:/bin/sync\n" ++ added },
        .{ "usr/share/werewolf/etc/group", "root:x:0:root\nweb:x:80:\n" },
        .{ "usr/share/werewolf/etc/shadow", "root:*::0:::::\nweb:!:::::::\n" },
    }) |want| try testing.expectEqualStrings(
        want[1],
        try ro.readFileAlloc(io, want[0], gpa, .limited(4096)),
    );
    try testing.expectEqualStrings(
        "/run/werewolf/passwd",
        buf[0..try ro.readLink(io, "etc/passwd", &buf)],
    );
    for ([_][]const u8{ "minimal", "web" }) |s| try testing.expectEqualStrings(
        try gpa.print("/run/runit/supervise.{s}", .{s}),
        buf[0..try ro.readLink(io, try gpa.print("etc/sv/{s}/supervise", .{s}), &buf)],
    );

    const cmdline_want = "proc_mem.force_override=never slab_nomerge " ++
        "page_alloc.shuffle=1 kvm-arm.mode=none loglevel=5\n";
    for ([_][2][]const u8{
        .{ "age-enforce", "enforce\n" },
        .{ "form", "web\n" },
        .{ "net", "connect 80 tcp 443\nlisten tcp 80\n" },
        .{ "pledge", "stdio inet listen\n" },
        .{ "cmdline", cmdline_want },
        .{ "weaknesses", "files-x every form on aarch64 (test/posture-known)\n" ++
            "kernel-y every form on aarch64 (test/posture-known)\n" },
        // The chain staged for the updater, and its kind's known failures.
        .{ "forms/minimal/form.yaml", "" },
        .{ "forms/web/form.yaml", web_form ++ web_apko },
        .{ "forms/web/rootfs/etc/motd", "web's\n" },
        .{ "forms/minimal/rootfs/etc/motd", "minimal's\n" },
        .{ "posture-known", b.posture_known },
    }) |want| try testing.expectEqualStrings(
        want[1],
        try meta.readFileAlloc(
            io,
            try gpa.print("usr/share/werewolf/{s}", .{want[0]}),
            gpa,
            .limited(4096),
        ),
    );
    try testing.expectError(error.FileNotFound, meta.access(io, "usr/share/werewolf/oci", .{}));
    try testing.expectError(error.FileNotFound, meta.access(io, "usr/share/werewolf/dev", .{}));
    // Everything made in /usr/share/werewolf is named in records, so the
    // updater carries none of it forward.
    for ([_]Dir{ ro, meta }) |tree| {
        var d = try tree.openDir(io, "usr/share/werewolf", .{ .iterate = true });
        defer d.close(io);
        var it = d.iterate();
        while (try it.next(io)) |e| {
            for (records) |r| {
                if (mem.eql(u8, r, e.name)) break;
            } else return error.NotInRecords;
        }
    }

    // Composing again from the staged chain, as an updater does, gives the
    // same result.
    var staged = try meta.openDir(io, "usr/share/werewolf", .{});
    defer staged.close(io);
    const again = try form.chain(io, gpa, staged, "web", &f);
    try tmp.dir.createDirPath(io, "again");
    var ro2 = try tmp.dir.createDirPathOpen(io, "again/ro", .{});
    defer ro2.close(io);
    var meta2 = try tmp.dir.createDirPathOpen(io, "again/meta", .{});
    defer meta2.close(io);
    try compose(io, gpa, staged, again, image, ro2, meta2, b, &f);
    for ([_][]const u8{ "etc/motd", "usr/share/werewolf/etc/passwd", "etc/sv/web/service" }) |p|
        try testing.expectEqualStrings(
            try ro.readFileAlloc(io, p, gpa, .limited(4096)),
            try ro2.readFileAlloc(io, p, gpa, .limited(4096)),
        );
    for ([_][]const u8{ "net", "cmdline", "weaknesses", "forms/web/form.yaml" }) |p| {
        const path = try gpa.print("usr/share/werewolf/{s}", .{p});
        try testing.expectEqualStrings(
            try meta.readFileAlloc(io, path, gpa, .limited(4096)),
            try meta2.readFileAlloc(io, path, gpa, .limited(4096)),
        );
    }
}

test "withAccounts: what apko added must be what its rule gives; homes it cannot make refused" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    var f: Failure = .{};
    const user = "accounts:\n  users:\n    - username: web\n      uid: 80\n";
    const two =
        \\accounts:
        \\  users:
        \\    - username: one
        \\      uid: 1
        \\      homedir: /var/empty
        \\    - username: two
        \\      uid: 2
        \\      homedir: /var/empty
        \\
    ;
    const team =
        \\accounts:
        \\  groups:
        \\    - groupname: team
        \\      gid: 9
        \\      members: [web, db]
        \\
    ;
    for ([_][2][]const u8{
        .{ "forms/plain/form.yaml", user ++ "      homedir: /var/empty\n" },
        .{ "forms/home/form.yaml", user },
        .{ "forms/two/form.yaml", two },
        .{ "forms/team/form.yaml", team },
    }) |file| {
        try tmp.dir.createDirPath(io, std.fs.path.dirname(file[0]).?);
        try tmp.dir.writeFile(io, .{ .sub_path = file[0], .data = file[1] });
    }
    const line = "web:x:80:80:Account created by apko:/var/empty:/bin/sh";
    const plain = try form.chain(io, gpa, tmp.dir, "plain", &f);
    // On the build's root apko's line is there, so nothing is added.
    const built: Accounts = .{
        .passwd = "root:x:0:0\n" ++ line ++ "\n",
        .group = "",
        .shadow = "web:!:::::::\n",
    };
    const same = try withAccounts(io, gpa, tmp.dir, plain, built, &f);
    try testing.expectEqualStrings(built.passwd, same.passwd);
    try testing.expectEqualStrings(built.shadow, same.shadow);
    // A line for the name that differs from apko's is refused.
    const other: Accounts = .{ .passwd = "web:x:81:81::/:/bin/sh\n", .group = "", .shadow = "" };
    try testing.expectError(error.Form, withAccounts(io, gpa, tmp.dir, plain, other, &f));
    // Some of apko's accounts but not all means a root built from older
    // forms; it is refused, since no machine's update would give that order.
    const empty: Accounts = .{ .passwd = "", .group = "", .shadow = "" };
    const both = try form.chain(io, gpa, tmp.dir, "two", &f);
    const fresh = try withAccounts(io, gpa, tmp.dir, both, empty, &f);
    try testing.expectEqualStrings(
        fresh.passwd,
        (try withAccounts(io, gpa, tmp.dir, both, fresh, &f)).passwd,
    );
    const second = fresh.passwd[mem.findScalar(u8, fresh.passwd, '\n').? + 1 ..];
    const older: Accounts = .{ .passwd = second, .group = "", .shadow = "" };
    try testing.expectError(error.Form, withAccounts(io, gpa, tmp.dir, both, older, &f));
    // apko's default home, /home/NAME, is refused: a machine's update would not make it.
    const home = try form.chain(io, gpa, tmp.dir, "home", &f);
    try testing.expectError(
        error.Form,
        withAccounts(io, gpa, tmp.dir, home, .{ .passwd = "", .group = "", .shadow = "" }, &f),
    );
    // A group's members are joined by commas.
    const teams = try form.chain(io, gpa, tmp.dir, "team", &f);
    const got = try withAccounts(
        io,
        gpa,
        tmp.dir,
        teams,
        .{ .passwd = "", .group = "root:x:0:root", .shadow = "" },
        &f,
    );
    try testing.expectEqualStrings("root:x:0:root\nteam:x:9:web,db\n", got.group);
}
