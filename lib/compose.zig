//! compose derives from a chain of forms everything an image holds beyond
//! its packages. The build and the updater both call it, so a slot built on
//! a machine matches the build's. See lib/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const form = @import("form");
const seal = @import("seal");
const service = @import("service");
const package = @import("package");

const Form = form.Form;
const Failure = form.Failure;
const Error = form.Error;

pub const Arch = enum { aarch64, x86_64 };

/// Build describes a build beyond its chain.
pub const Build = struct {
    arch: Arch,
    /// dev marks a DEV=1 build, with busybox-full and the debug shell.
    dev: bool = false,
    /// posture_known is test/posture-known: the posture checks every form
    /// of a kind fails.
    posture_known: []const u8 = "",
};

/// records names what compose makes in /usr/share/werewolf. The updater
/// composes these anew and carries every other record forward, so none of
/// these is ever a stale copy.
pub const records = [_][]const u8{
    "cmdline",        "dev", "etc", "form",   "forms",         "module-params", "modules",
    "modules-bitten", "net", "oci", "pledge", "posture-known", "prune",         "weaknesses",
};

/// release_forms are the forms CI releases as disks, for both arches
/// (docs/releases.md): for installs; machines update through apk.
pub const release_forms = [_][]const u8{ "minimal", "prod", "prod-ssh" };

/// Accounts holds an image's account files, as its packages leave them.
pub const Accounts = struct { passwd: []const u8, group: []const u8, shadow: []const u8 };

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
    const accts = try withAccounts(io, gpa, root, forms, image, f);
    const passwd = accts.passwd;
    const group = accts.group;
    const shadow = accts.shadow;

    // ro: each form's rootfs, base first, so later forms' files win; then
    // the services form.yaml renders, each on a leash: its file, and run
    // and finish links to leash where the rootfs laid none.
    for (forms) |fm| {
        try lay(io, gpa, root, try gpa.print("{s}/rootfs", .{fm.dir}), ro, "");
        for (fm.images) |dir| try lay(io, gpa, root, dir, ro, "");
    }
    for (try form.services(io, gpa, root, forms, f)) |s| {
        if (mem.find(u8, s.path, "form.yaml: services.") == null) continue;
        const dir = try gpa.print("etc/sv/{s}", .{s.name});
        try ro.createDirPath(io, dir);
        try put(io, ro, try gpa.print("{s}/service", .{dir}), s.text);
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
    // One empty file per allowance, for init, fence and posture.
    try ro.createDirPath(io, "etc/werewolf/allow");
    for (allowed) |a| try put(io, ro, try gpa.print("etc/werewolf/allow/{s}", .{a}), "");
    const sshd_config = try form.sshdConfig(gpa, forms, f);
    if (sshd_config.len > 0) {
        try ro.createDirPath(io, "etc/ssh/sshd_config.d");
        const text = try gpa.print("{s}\n", .{mem.trimEnd(u8, sshd_config, "\n")});
        try put(io, ro, "etc/ssh/sshd_config.d/form.conf", text);
    }
    if (hasForm(forms, "bastion")) {
        const files = try form.bastionFiles(gpa, forms, f);
        try ro.createDirPath(io, "etc/ssh/bastion");
        try put(io, ro, "etc/ssh/bastion/authorized_keys", files.keys);
        try put(io, ro, "etc/ssh/bastion/permit-open", files.permit);
        try ro.createDirPath(io, "etc/sv/sshd");
        try put(io, ro, "etc/sv/sshd/service", try form.bastionService(io, gpa, root, forms, f));
    }
    // init seeds /run/werewolf from these; the image's /etc/passwd, group
    // and shadow link there.
    try ro.createDirPath(io, "usr/share/werewolf/etc");
    const users = try accounts(gpa, passwd, f);
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
    // narrowed (docs/design/narrow.md).
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
    const mods = try modules(gpa, forms, b.arch);
    // Each record lists what its stage0 loads, in the build's order, so the
    // updater builds the same stage0s: modules for werewolf's own disk,
    // modules-bitten for a distro's after bite.
    try put(io, rec, "modules", try lines(gpa, mods.native));
    try put(io, rec, "modules-bitten", try lines(gpa, mods.all));
    try put(io, rec, "prune", try lines(gpa, try prune(gpa, forms, f)));
    const known = try weaknesses(gpa, top, b);
    try put(io, rec, "weaknesses", if (upd.off)
        try gpa.print("{s}updates-enabled updates: off in the manifest\n", .{known})
    else
        known);
    try put(io, rec, "pledge", try pledge(io, gpa, root, forms, f));
    const images = try oci(io, gpa, root, forms, f);
    if (images.len > 0) try put(io, rec, "oci", images);
    if (b.dev) try put(io, rec, "dev", "dev\n");
    var params: std.ArrayList(u8) = .empty;
    for (moduleParams(allowed, b.arch)) |p|
        try params.print(gpa, "{s} {s}\n", .{ p.module, p.value });
    try put(io, rec, "module-params", params.items);
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
    const text = if (image_entries.items.len == fm.spec.map.len and
        !mem.startsWith(u8, original, "# Generated by howl"))
        original
    else
        out.written();
    try put(io, dir, try gpa.print("{s}/form.yaml", .{at}), text);
    const rootfs = try gpa.print("{s}/rootfs", .{fm.dir});
    try lay(io, gpa, root, rootfs, dir, try gpa.print("{s}/rootfs", .{at}));
    for (fm.images) |d| try lay(io, gpa, root, d, dir, try gpa.print("{s}/rootfs", .{at}));
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
        switch (e.kind) {
            .directory => try into.createDirPath(io, e.path),
            .sym_link => {
                const target = buf[0..try from.readLink(io, e.path, &buf)];
                into.deleteFile(io, e.path) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => |x| return x,
                };
                try into.symLink(io, target, e.path, .{});
            },
            .file => try from.copyFile(e.path, into, e.path, io, .{}),
            else => return error.UnexpectedFileKind,
        }
    }
}

/// default_id_first and default_id_count bound defaultId to [65536, 2^31).
/// Ids start above 16 bits, clear of every id a package, a form's own pick
/// or a convention (nobody, 65534) takes, and stop below 2^31, which
/// software that keeps a uid in a signed int cannot hold. So many ids make
/// two names landing on one all but impossible.
const default_id_first: u32 = 1 << 16;
const default_id_count: u32 = (1 << 31) - (1 << 16);

/// defaultId returns the uid and gid of a service user no form's accounts
/// declare: an FNV-1a hash of its name, in [65536, 2^31). It depends on the
/// name alone, so the id is the same on every build and machine whatever
/// forms come and go, and the service keeps owning its files on /data.
pub fn defaultId(name: []const u8) u32 {
    return default_id_first + std.hash.Fnv1a_32.hash(name) % default_id_count;
}

/// apko returns the chain's merged apko config (form.apko, with extra) plus
/// an account for each service user no form's accounts declare: a group and
/// a user, both with id defaultId(name), home /var/empty and shell
/// /sbin/nologin, after the declared ones. It refuses two services that run
/// as one user, since strict share could not then keep them apart. It also
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
    const merged = try form.apko(gpa, forms, extra);
    const top = forms[forms.len - 1].dir;
    var declared: std.array_hash_map.String(void) = .empty;
    var ids: std.array_hash_map.Auto(u32, []const u8) = .empty;
    if (merged.get("accounts")) |acc| {
        if (acc.get("users")) |users| for (try entries(gpa, top, users, f)) |u| {
            const name = try scalarAt(gpa, top, u, "username", f);
            try declared.put(gpa, name, {});
            try ids.put(gpa, try number(gpa, top, u, "uid", f), name);
        };
        if (acc.get("groups")) |groups| for (try entries(gpa, top, groups, f)) |g| {
            const name = try scalarAt(gpa, top, g, "groupname", f);
            try ids.put(gpa, try number(gpa, top, g, "gid", f), name);
        };
    }
    var runs_as: std.array_hash_map.String([]const u8) = .empty;
    var groups: std.ArrayList(form.Node) = .empty;
    var users: std.ArrayList(form.Node) = .empty;
    const services = try form.services(io, gpa, root, forms, f);
    for (services) |s| {
        const user = (try parseService(gpa, s, f)).user;
        if (try runs_as.fetchPut(gpa, user, s.name)) |other| return f.fail(
            gpa,
            "services {s} and {s} both run as {s}: each needs a user of its own",
            .{ other.value, s.name, user },
        );
        if (declared.contains(user)) continue;
        const id = defaultId(user);
        if (ids.get(id)) |holder| return f.fail(
            gpa,
            "{s}: user {s}'s default id {d} is {s}'s: give one of them a uid in accounts",
            .{ s.path, user, id, holder },
        );
        try ids.put(gpa, id, user);
        const n = try gpa.print("{d}", .{id});
        try groups.append(gpa, try mapOf(gpa, &.{ .{ "groupname", user }, .{ "gid", n } }));
        try users.append(gpa, try mapOf(gpa, &.{
            .{ "username", user },
            .{ "uid", n },
            .{ "gid", n },
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
        if (mem.eql(
            u8,
            owner,
            s.name,
        )) return f.fail(gpa, "{s}: group {s} is its own", .{ s.path, g });
    };
    if (users.items.len == 0) return merged;
    const added = try gpa.dupe(form.Entry, &.{
        .{ .key = "groups", .value = .{ .list = groups.items } },
        .{ .key = "users", .value = .{ .list = users.items } },
    });
    const add = try gpa.dupe(form.Entry, &.{.{ .key = "accounts", .value = .{ .map = added } }});
    return form.merge(gpa, merged, .{ .map = add });
}

/// format numbers the files compose writes and werewolf's programs read. Each
/// of werewolf's packages, programs and forms, depends on format_package,
/// and a published image's world names it, so a machine never takes one
/// built for another format; bump it when either side changes incompatibly.
/// 2: a form is form.yaml alone (its packages, accounts and paths in it);
/// a staged apko.yaml is refused.
/// 3: local-NAME stages the operator's forms and app for the updater;
/// inline update policy and metadata people need the matching programs.
pub const format = 3;

/// format_package is format's package, a name per format, so a world names
/// it with no version to compare. It holds /usr/lib/werewolf/format: apk
/// fetches no package without files.
pub const format_package = std.fmt.comptimePrint("werewolf-format{d}", .{format});

/// image_programs are the programs from cmd/ that every image runs, stage0's
/// init among them: a machine builds its next stage0 from its next root.
pub const image_programs = [_][]const u8{
    "init",         "stage0",       "modload",      "iface-up",    "fence",        "mount",
    "mount-broker", "posture",      "seal-watch",   "seal",        "runit-stage",  "reboot",
    "grub-setenv",  "slot-keep",    "power-button", "debug-shell", "ssh-host-key", "leash",
    "leash-reap",   "bite-cleanup",
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
/// and keyring added, and its packages each such form as NAME-form, which
/// brings its own, then the other forms' packages and programs, extra, and
/// the format pin. Every image's programs come with the form built on none,
/// or are named when that form is not from the repository. keyring must be
/// named as the index's signature names the key.
pub fn published(
    gpa: Allocator,
    config: form.Node,
    forms: []const Form,
    from_repo: []const []const u8,
    extra: []const []const u8,
    keyring: []const u8,
) !form.Node {
    if (!mem.eql(u8, std.fs.path.basename(keyring), package.repository_key))
        return error.KeyringName;
    var names: std.array_hash_map.String(void) = .empty;
    for (forms) |fm| {
        const repo = for (from_repo) |n| {
            if (mem.eql(u8, n, fm.name)) break true;
        } else false;
        if (repo) {
            try names.put(gpa, try gpa.print("{s}-form", .{fm.name}), {});
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

    // The packages replace the chain's; the repository and key join its.
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
    const one = struct {
        fn of(a: Allocator, text: []const u8) !form.Node {
            return .{ .list = try a.dupe(
                form.Node,
                &.{.{ .scalar = .{ .raw = text, .text = text } }},
            ) };
        }
    };
    const repo = try gpa.dupe(form.Entry, &.{
        .{ .key = "repositories", .value = try one.of(gpa, package.repository) },
        .{ .key = "keyring", .value = try one.of(gpa, keyring) },
    });
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

/// cmdline returns the kernel arguments for hardening that has no runtime
/// switch: no debugfs, no forced writes through /proc/PID/mem, no 32-bit
/// calls on x86_64, and no IPv6 unless allowed. On aarch64 the kernel starts
/// KVM whenever the host offers EL2, so it is off unless allowed, and
/// nested only if allowed. slab_nomerge stops a freed object being reused
/// by an attacker's object of another type; page shuffling makes layout
/// harder to predict. Neither costs anything. init_on_free is left off for
/// its cost (docs/security.md).
///
/// loglevel=5 limits the console to warnings and worse; dmesg keeps all.
/// A cloud serial port takes about a millisecond a line: on GCP, notices
/// and info doubled boot time (0.23 s against 0.11 s). Panics, stalls, BUG
/// and the power-down line that test/boot reads are all errors or worse.
pub fn cmdline(gpa: Allocator, allowed: []const []const u8, arch: Arch) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(
        gpa,
        "debugfs=off proc_mem.force_override=never slab_nomerge page_alloc.shuffle=1",
    );
    if (!allows(allowed, "ipv6")) try out.appendSlice(gpa, " ipv6.disable=1");
    switch (arch) {
        .aarch64 => if (allows(allowed, "nested-kvm"))
            try out.appendSlice(gpa, " kvm-arm.mode=nested")
        else if (!allows(allowed, "kvm"))
            try out.appendSlice(gpa, " kvm-arm.mode=none"),
        .x86_64 => try out.appendSlice(gpa, " ia32_emulation=0"),
    }
    try out.appendSlice(gpa, " loglevel=5");
    return out.items;
}

pub const Param = struct { module: []const u8, value: []const u8 };

/// moduleParams returns module parameters. On x86_64 with kvm allowed it
/// sets nested virtualization, which Linux enables by default, to match
/// the nested-kvm allowance.
pub fn moduleParams(allowed: []const []const u8, arch: Arch) []const Param {
    if (arch != .x86_64 or !allows(allowed, "kvm")) return &.{};
    if (allows(allowed, "nested-kvm")) return &.{
        .{ .module = "kvm-intel", .value = "nested=1" },
        .{ .module = "kvm-amd", .value = "nested=1" },
    };
    return &.{
        .{ .module = "kvm-intel", .value = "nested=0" },
        .{ .module = "kvm-amd", .value = "nested=0" },
    };
}

/// bitten_tags mark modules only a distro's disk needs after bite: its
/// filesystem's. Modules.bitten holds those; native holds the rest, for
/// werewolf's own disk and a direct boot; all holds both in chain order,
/// the load order of stage0-bitten.zst.
const bitten_tags = [_][]const u8{ "@xfs:", "@btrfs:" };

pub const Modules = struct {
    native: []const []const u8,
    bitten: []const []const u8,
    all: []const []const u8,
};

/// modules returns, in order, the leaf modules the chain's form.yaml names
/// for arch. A line `ARCH MODULE...` applies to that arch only. A line
/// `@TAG MODULE...` yields `@TAG:MODULE`, loaded only by a stage0 that finds
/// that tag.
pub fn modules(gpa: Allocator, forms: []const Form, arch: Arch) Allocator.Error!Modules {
    var native: std.ArrayList([]const u8) = .empty;
    var bitten: std.ArrayList([]const u8) = .empty;
    var all: std.ArrayList([]const u8) = .empty;
    for (forms) |fm| for (try fm.items(gpa, "modules")) |line| {
        var w = try words(gpa, uncommented(line));
        if (w.len == 0) continue;
        if (std.meta.stringToEnum(Arch, w[0])) |a| {
            if (a != arch) continue;
            w = w[1..];
        }
        const tag = if (w.len > 0 and isTag(w[0])) w[0] else "";
        for (if (tag.len > 0) w[1..] else w) |m| {
            const word = if (tag.len > 0) try gpa.print("{s}:{s}", .{ tag, m }) else m;
            const is_bitten = for (bitten_tags) |t| {
                if (mem.startsWith(u8, word, t)) break true;
            } else false;
            try (if (is_bitten) &bitten else &native).append(gpa, word);
            try all.append(gpa, word);
        }
    };
    return .{ .native = native.items, .bitten = bitten.items, .all = all.items };
}

/// isTag reports whether word is @ followed by lowercase letters or digits.
fn isTag(word: []const u8) bool {
    if (word.len < 2 or word[0] != '@') return false;
    for (word[1..]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c)) return false;
    return true;
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
    for (forms) |fm| for (try fm.items(gpa, "prune")) |item| {
        var it = mem.tokenizeAny(u8, item, " \t");
        while (it.next()) |p| {
            if (mem.startsWith(u8, p, "/") or mem.startsWith(u8, p, "./") or
                mem.startsWith(u8, p, "../") or mem.endsWith(u8, p, "/") or
                mem.endsWith(u8, p, "/..") or mem.endsWith(u8, p, "/."))
                return f.fail(
                    gpa,
                    "form {s} prunes {s}: a path is relative and clean, usr/bin/bash",
                    .{ forms[forms.len - 1].name, p },
                );
            try out.append(gpa, p);
        }
    };
    return out.items;
}

/// weaknesses lists the posture checks the machine is expected to fail,
/// each with its excuse: the form's own, then those from test/posture-known
/// (the `dev` line for a DEV=1 build, else `*`, plus the arch's line).
pub fn weaknesses(gpa: Allocator, top: Form, b: Build) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (top.weaknesses()) |e| try out.print(gpa, "{s} {s}\n", .{ e.key, e.value.scalar.text });
    const kind = if (b.dev) "dev" else "*";
    const excuse = if (b.dev)
        "a DEV=1 build: busybox-full and the debug shell"
    else
        try gpa.print("every form on {t} (test/posture-known)", .{b.arch});
    var known = mem.splitScalar(u8, b.posture_known, '\n');
    while (known.next()) |line| {
        var it = mem.tokenizeAny(u8, line, " \t");
        const first = it.next() orelse continue;
        if (!mem.eql(u8, first, kind) and !mem.eql(u8, first, @tagName(b.arch))) continue;
        while (it.next()) |id| try out.print(gpa, "{s} {s}\n", .{ id, unbuilt(id, excuse) });
    }
    return out.items;
}

/// unbuilt returns the excuse for a posture check the boot chain cannot
/// hold yet, as docs/design/verified-boot.md phases 4 and 5 name them, or
/// the generic excuse for the build.
fn unbuilt(id: []const u8, generic: []const u8) []const u8 {
    const bare = if (id.len > 0 and id[0] == '?') id[1..] else id;
    if (mem.eql(u8, bare, "boot-secure-boot"))
        return "Secure Boot is phase 5 of the boot design, not built: Alpine's kernel is not signed for it";
    if (mem.eql(u8, bare, "boot-sig-enforced"))
        return "Alpine builds this kernel without signature enforcement; phase 4 builds werewolf's own";
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
        for (ps.listen_udp) |p| if (mem.findScalar(u16, declared_udp.items, p) == null)
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

/// oci lists the services that run in a baked-in image: `root NAME DIR USER`,
/// then `write NAME PATH` for each path init binds beneath the image root
/// and fence allows (cmd/init/oci.zig, cmd/fence).
pub fn oci(io: Io, gpa: Allocator, root: Dir, forms: []const Form, f: *Failure) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (try form.services(io, gpa, root, forms, f)) |s| {
        const parsed = try parseService(gpa, s, f);
        const dir = parsed.root orelse continue;
        try out.print(gpa, "root {s} {s} {s}\n", .{ s.name, dir, parsed.user });
        for (parsed.write) |path| try out.print(gpa, "write {s} {s}\n", .{ s.name, path });
    }
    return out.items;
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

/// net compiles the chain's network policy for fence: one rule per line,
/// sorted and unique, with users as uids from passwd. It reads
/// `listen tcp/PORT... [loopback]`, `connect USER|all PROTO/PORT|icmp...
/// [public]` and `metadata USER...` (forms/README.md).
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
    for (try form.netLines(gpa, forms, f)) |item| {
        const line = uncommented(item);
        if (!try netLine(gpa, try words(gpa, line), &uids, &out)) return f.fail(
            gpa,
            "form {s}: a net line cannot compile: {s}",
            .{ forms[forms.len - 1].name, line },
        );
    }
    sortStrings(out.items);
    var text: std.ArrayList(u8) = .empty;
    for (out.items, 0..) |line, i| {
        if (i > 0 and mem.eql(u8, line, out.items[i - 1])) continue;
        try text.print(gpa, "{s}\n", .{line});
    }
    return text.items;
}

/// netLine compiles one net line's words onto out. It returns false for a
/// line that cannot compile.
fn netLine(
    gpa: Allocator,
    w: []const []const u8,
    uids: *const std.array_hash_map.String([]const u8),
    out: *std.ArrayList([]const u8),
) Allocator.Error!bool {
    if (w.len == 0) return true;
    // listen USER udp/PORT...: fence delivers the port, and lets only USER
    // send from it (docs/design/listen-udp.md).
    if (mem.eql(u8, w[0], "listen") and w.len > 2 and !mem.startsWith(u8, w[1], "tcp/")) {
        const uid = uids.get(w[1]) orelse return false;
        for (w[2..]) |p| try out.append(
            gpa,
            try gpa.print("listen {s} udp {d}", .{ uid, port(p, "udp/") orelse return false }),
        );
        return true;
    }
    if (mem.eql(u8, w[0], "listen") and w.len > 1) {
        const lo = mem.eql(u8, w[w.len - 1], "loopback");
        const ports = w[1 .. w.len - @intFromBool(lo)];
        if (ports.len == 0) return false;
        for (ports) |p| try out.append(gpa, try gpa.print(
            "listen tcp {d}{s}",
            .{ port(p, "tcp/") orelse return false, if (lo) " loopback" else "" },
        ));
        return true;
    }
    if (mem.eql(u8, w[0], "metadata") and w.len > 1) {
        for (w[1..]) |u|
            try out.append(gpa, try gpa.print("metadata {s}", .{uids.get(u) orelse return false}));
        return true;
    }
    if (mem.eql(u8, w[0], "connect") and w.len > 2) {
        const who = if (mem.eql(u8, w[1], "all")) "all" else uids.get(w[1]) orelse return false;
        const public = mem.eql(u8, w[w.len - 1], "public");
        const targets = w[2 .. w.len - @intFromBool(public)];
        if (targets.len == 0) return false;
        for (targets) |t| {
            if (mem.eql(u8, t, "icmp")) {
                if (public) return false;
                try out.append(gpa, try gpa.print("connect {s} icmp", .{who}));
                continue;
            }
            const proto = if (mem.startsWith(u8, t, "udp/")) "udp" else "tcp";
            const p = port(t, if (proto[0] == 'u') "udp/" else "tcp/") orelse return false;
            try out.append(gpa, try gpa.print(
                "connect {s} {s} {d}{s}",
                .{ who, proto, p, if (public) " public" else "" },
            ));
        }
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

test "cmdline and module parameters: what each allowance takes back, by arch" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const base = "debugfs=off proc_mem.force_override=never slab_nomerge page_alloc.shuffle=1";
    for ([_]struct { []const []const u8, Arch, []const u8 }{
        .{ &.{}, .aarch64, base ++ " ipv6.disable=1 kvm-arm.mode=none loglevel=5" },
        .{ &.{"ipv6"}, .aarch64, base ++ " kvm-arm.mode=none loglevel=5" },
        .{ &.{"kvm"}, .aarch64, base ++ " ipv6.disable=1 loglevel=5" },
        .{
            &.{ "kvm", "nested-kvm" },
            .aarch64,
            base ++ " ipv6.disable=1 kvm-arm.mode=nested loglevel=5",
        },
        .{ &.{}, .x86_64, base ++ " ipv6.disable=1 ia32_emulation=0 loglevel=5" },
        .{ &.{ "ipv6", "kvm" }, .x86_64, base ++ " ia32_emulation=0 loglevel=5" },
    }) |c| try testing.expectEqualStrings(c[2], try cmdline(gpa, c[0], c[1]));

    try testing.expectEqual(0, moduleParams(&.{"kvm"}, .aarch64).len);
    try testing.expectEqual(0, moduleParams(&.{}, .x86_64).len);
    const off = moduleParams(&.{"kvm"}, .x86_64);
    try testing.expectEqualStrings("kvm-intel", off[0].module);
    try testing.expectEqualStrings("nested=0", off[1].value);
    try testing.expectEqualStrings(
        "nested=1",
        moduleParams(&.{ "kvm", "nested-kvm" }, .x86_64)[0].value,
    );
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

test "allowances: along the chain, sorted, once each; nested-kvm needs kvm" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    var f: Failure = .{};
    const got = try allowances(gpa, &.{
        try testForm(gpa, "jre", "allow: [jit, pty]\n"),
        try testForm(gpa, "mine", "allow: [ipv6, jit]\n"),
    }, &f);
    try testing.expectEqual(3, got.len);
    for ([_][]const u8{
        "ipv6",
        "jit",
        "pty",
    }, got) |want, g| try testing.expectEqualStrings(want, g);
    try testing.expectError(error.Form, allowances(gpa, &.{
        try testForm(gpa, "vm", "allow: [nested-kvm]\n"),
    }, &f));
}

test "modules: the arch's, tagged, the bitten apart, in order, as given" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const forms = [_]Form{
        try testForm(gpa, "minimal", "modules:\n  - virtio_net virtio_blk\n  - aarch64 " ++
            "virtio_mmio\n" ++
            "  - x86_64 ia32_only\n  - \"@xfs xfs\"\n"),
        try testForm(gpa, "prod", "modules:\n  - ena # AWS\n  - aarch64 @hyperv hv_netvsc\n" ++
            "  - \"@btrfs btrfs crc32c\"\n  - \"@Up not_a_tag\"\n  - aarch64 @hyperv hv_netvsc\n"),
    };
    const m = try modules(gpa, &forms, .aarch64);
    const native = [_][]const u8{
        "virtio_net",        "virtio_blk", "virtio_mmio", "ena",
        "@hyperv:hv_netvsc", "@Up",        "not_a_tag",   "@hyperv:hv_netvsc",
    };
    try testing.expectEqual(native.len, m.native.len);
    for (native, m.native) |want, g| try testing.expectEqualStrings(want, g);
    const bitten = [_][]const u8{ "@xfs:xfs", "@btrfs:btrfs", "@btrfs:crc32c" };
    try testing.expectEqual(bitten.len, m.bitten.len);
    for (bitten, m.bitten) |want, g| try testing.expectEqualStrings(want, g);
    const x = try modules(gpa, &forms, .x86_64);
    try testing.expectEqualStrings("ia32_only", x.native[2]);
}

test "net: users as uids, ports as numbers, sorted, once each; what cannot compile fails" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const passwd = "root:x:0:0:root:/root:/sbin/nologin\n_update:x:69:69::/var/empty:/sbin/nolog" ++
        "in\n" ++
        "web:x:300:300::/var/empty:/sbin/nologin\n";
    var f: Failure = .{};
    const got = try net(gpa, &.{
        try testForm(gpa, "prod", "net:\n  - connect _update tcp/443 udp/53 tcp/53\n"),
        try testForm(gpa, "web", "net:\n  - listen tcp/08080 # leading zeros\n" ++
            "  - listen tcp/5432 loopback\n  - connect web tcp/443 public\n  - connect all " ++
            "icmp\n" ++
            "  - metadata web\n  - connect _update tcp/443\n  - listen root udp/51820\n"),
    }, passwd, &f);
    try testing.expectEqualStrings(
        "connect 300 tcp 443 public\nconnect 69 tcp 443\nconnect 69 tcp 53\nconnect 69 udp 53\n" ++
            "connect all icmp\nlisten 0 udp 51820\nlisten tcp 5432 loopback\nlisten tcp 8080\n" ++
            "metadata 300\n",
        got,
    );
    for ([_][]const u8{
        "listen udp/53",          "listen tcp/0",
        "listen tcp/65536",       "listen loopback",
        "connect nobody tcp/443", "connect web icmp public",
        "connect web public",     "metadata nobody",
        "serve tcp/80",           "connect web sctp/9",
        "listen tcp/",            "listen tcp/99999999999999999999",
        "listen nobody udp/53",   "listen root udp/0",
        "listen root tcp/53",     "listen root udp/53 loopback",
    }) |line| {
        const forms = [_]Form{try testForm(gpa, "bad", try gpa.print("net:\n  - {s}\n", .{line}))};
        try testing.expectError(error.Form, net(gpa, &forms, passwd, &f));
        try testing.expect(mem.endsWith(u8, f.text, line));
    }
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
    for ([_][]const u8{ "/usr/bin/bash", "./usr", "../etc", "usr/", "usr/..", "usr/." }) |p| {
        const forms = [_]Form{try testForm(gpa, "bad", try gpa.print("prune:\n  - {s}\n", .{p}))};
        try testing.expectError(error.Form, prune(gpa, &forms, &f));
    }
}

test "weaknesses: the form's own, then its kind's and its arch's from posture-known" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const top = try testForm(gpa, "sshd", "weaknesses:\n  programs-no-shell: a shell for logins\n");
    const known = "# comment: dev and * lines\ndev programs-no-shell programs-no-interpreters\n" ++
        "* ?files-x ?boot-secure-boot boot-rollback-protected boot-sig-enforced\n" ++
        "x86_64 kernel-y\naarch64 kernel-z\n";
    try testing.expectEqualStrings(
        "programs-no-shell a shell for logins\n?files-x every form on aarch64 " ++
            "(test/posture-known)\n" ++
            "?boot-secure-boot Secure Boot is phase 5 of the boot design, not built: " ++
            "Alpine's kernel is not signed for it\n" ++
            "boot-rollback-protected no TPM counter guards the slot serial yet: " ++
            "phase 5 of the boot design\n" ++
            "boot-sig-enforced Alpine builds this kernel without signature enforcement; " ++
            "phase 4 builds werewolf's own\n" ++
            "kernel-z every form on aarch64 (test/posture-known)\n",
        try weaknesses(gpa, top, .{ .arch = .aarch64, .posture_known = known }),
    );
    const dev = "a DEV=1 build: busybox-full and the debug shell";
    try testing.expectEqualStrings(
        "programs-no-shell a shell for logins\nprograms-no-shell " ++ dev ++ "\n" ++
            "programs-no-interpreters " ++ dev ++ "\nkernel-y " ++ dev ++ "\n",
        try weaknesses(gpa, top, .{ .arch = .x86_64, .dev = true, .posture_known = known }),
    );
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
    try testing.expect(id >= 1 << 16 and id < 1 << 31);
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

test serviceDirOwner {
    try testing.expectEqualStrings("db", serviceDirOwner("/data/svc/db").?);
    try testing.expectEqualStrings("db", serviceDirOwner("/run/svc/db/run/x.sock").?);
    try testing.expectEqual(null, serviceDirOwner("/data/svc"));
    try testing.expectEqual(null, serviceDirOwner("/data/svc/"));
    try testing.expectEqual(null, serviceDirOwner("/etc/nginx"));
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
        \\allow: [ipv6]
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
        .{ "etc/werewolf/allow/ipv6", "" },
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

    const cmdline_want = "debugfs=off proc_mem.force_override=never slab_nomerge " ++
        "page_alloc.shuffle=1 kvm-arm.mode=none loglevel=5\n";
    for ([_][2][]const u8{
        .{ "form", "web\n" },
        .{ "net", "connect 80 tcp 443\nlisten tcp 80\n" },
        .{ "pledge", "stdio inet listen\n" },
        .{ "module-params", "" },
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
