//! compose: what an image holds beyond its packages, derived from its
//! forms (docs/design/custom-updates.md). The allowances, sshd's and the
//! bastion's files, the accounts init seeds and each service's supervise
//! link; and the records in /usr/share/werewolf that init, fence, posture,
//! modload and the updater read: the network policy, the promises, the
//! modules, the kernel arguments. One function of the chain and the image's
//! accounts, called by the build (build/host/form compose) and, once forms
//! are packages, by the updater, so a slot built on a machine holds what
//! the build's did.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const form = @import("form");
const seal = @import("seal");
const service = @import("service");

const Form = form.Form;
const Failure = form.Failure;
const Error = form.Error;

pub const Arch = enum { aarch64, x86_64 };

/// What a build is besides its chain.
pub const Build = struct {
    arch: Arch,
    /// A DEV=1 build: busybox-full and the debug shell.
    dev: bool = false,
    /// test/posture-known: the posture checks every form of a kind fails.
    posture_known: []const u8 = "",
};

/// Writes what the chain derives into two trees: ro, laid over the
/// packages and the forms' rootfs, which the updater carries forward by
/// its overlay list; and meta, werewolf's records, /usr/share/werewolf.
/// root is where the forms' directories resolve; image, the image's root,
/// its packages installed, for its accounts.
pub fn compose(
    io: Io,
    gpa: Allocator,
    root: Dir,
    forms: []const Form,
    image: Dir,
    ro: Dir,
    meta: Dir,
    b: Build,
    f: *Failure,
) !void {
    const allowed = try allowances(gpa, forms, f);
    const passwd = try image.readFileAlloc(io, "etc/passwd", gpa, .limited(1 << 20));
    const group = try image.readFileAlloc(io, "etc/group", gpa, .limited(1 << 20));
    const shadow = try image.readFileAlloc(io, "etc/shadow", gpa, .limited(1 << 20));

    // ro: the allowances, an empty file each, where init, fence and
    // posture read them.
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
    // apko's accounts, from which init seeds /run/werewolf, where the
    // image's /etc/passwd, group and shadow link.
    try ro.createDirPath(io, "usr/share/werewolf/etc");
    const users = try accounts(gpa, passwd, f);
    try unique(gpa, "group", group, f);
    try put(io, ro, "usr/share/werewolf/etc/passwd", users);
    try put(io, ro, "usr/share/werewolf/etc/group", group);
    try put(io, ro, "usr/share/werewolf/etc/shadow", shadow);
    // Each service's supervise directory, a link into /run/runit, where
    // runit can write.
    for (try serviceNames(io, gpa, root, forms)) |s| {
        try ro.createDirPath(io, try gpa.print("etc/sv/{s}", .{s}));
        const target = try gpa.print("/run/runit/supervise.{s}", .{s});
        try ro.symLink(io, target, try gpa.print("etc/sv/{s}/supervise", .{s}), .{});
    }

    // meta: the records.
    var rec = try meta.createDirPathOpen(io, "usr/share/werewolf", .{});
    defer rec.close(io);
    const top = forms[forms.len - 1];
    try put(io, rec, "form", try gpa.print("{s}\n", .{top.name}));
    const mods = try modules(gpa, forms, b.arch);
    try put(io, rec, "modules", try lines(gpa, mods.native));
    try put(io, rec, "modules-bitten", try lines(gpa, mods.bitten));
    try put(io, rec, "prune", try lines(gpa, try prune(gpa, forms, f)));
    try put(io, rec, "weaknesses", try weaknesses(gpa, top, b));
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

/// Each item a line.
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

/// The chain's allowances, sorted, each once: what it takes back of
/// werewolf's defaults (lib/allow.zig). Refused: nested-kvm without kvm.
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

/// The kernel's hardening that has no runtime switch, on the command line
/// of every way the image boots. No debugfs; no forced writes through
/// /proc/PID/mem, how a program rewrites its own code; on x86_64 no 32-bit
/// system calls; on aarch64 no KVM, which the kernel builds in and starts
/// whenever a host lends the guest EL2, unless the form allows it, and
/// nested only if it allows that too. Each kernel cache kept apart
/// (slab_nomerge), so an object freed in one cannot be taken over by an
/// attacker's of another type that shares it, and pages handed out in a
/// shuffled order: neither costs a program anything. init_on_alloc and the
/// kernel stack's random offset are Alpine's kernel's defaults already;
/// init_on_free, which costs allocation-heavy work, is left off by choice
/// (docs/security.md). No IPv6, unless the form allows it.
///
/// The console shows the kernel's warnings and worse; dmesg keeps every
/// message. The kernel writes its console as it goes, and a cloud's serial
/// port takes a millisecond a line: on GCP its boot's notices and info took
/// half its time (0.23 s against 0.11 s). Panics, stalls, BUG and the
/// power-down line, which test/boot reads, are all errors or worse.
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

/// Parameters the image loads modules with: on x86_64, where KVM is a
/// module and allowed, its nested virtualization, which Linux turns on by
/// default, on only where allowed.
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

/// Tags for what only a distro's disk needs, after bite: the modules of
/// its filesystem. bitten holds them, for stage0-bitten.zst; native the
/// rest, for werewolf's own disk and a direct boot.
const bitten_tags = [_][]const u8{ "@xfs:", "@btrfs:" };

pub const Modules = struct { native: []const []const u8, bitten: []const []const u8 };

/// The leaf modules the chain's form.yaml names for arch, in order: a line
/// `ARCH MODULE...` is that arch's alone; one `@TAG MODULE...` gives each
/// module as `@TAG:MODULE`, which only a stage0 that finds that tag loads.
pub fn modules(gpa: Allocator, forms: []const Form, arch: Arch) Allocator.Error!Modules {
    var native: std.ArrayList([]const u8) = .empty;
    var bitten: std.ArrayList([]const u8) = .empty;
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
        }
    };
    return .{ .native = native.items, .bitten = bitten.items };
}

/// `@` and lowercase letters or digits.
fn isTag(word: []const u8) bool {
    if (word.len < 2 or word[0] != '@') return false;
    for (word[1..]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c)) return false;
    return true;
}

/// A line up to a #.
fn uncommented(line: []const u8) []const u8 {
    return line[0 .. mem.findScalar(u8, line, '#') orelse line.len];
}

/// A line's words, between spaces and tabs.
fn words(gpa: Allocator, line: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeAny(u8, line, " \t");
    while (it.next()) |w| try out.append(gpa, w);
    return out.items;
}

/// Files the chain's packages bring that nothing runs, a path each, as each
/// is in the image: relative and clean.
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

/// The posture checks the machine is expected to fail, each with its
/// excuse: the form's own, then those every form of its kind fails
/// (test/posture-known: the `dev` line for a DEV=1 build, `*` for one as
/// it ships, and the arch's line).
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
        while (it.next()) |id| try out.print(gpa, "{s} {s}\n", .{ id, excuse });
    }
    return out.items;
}

/// The machine's promises: every service's pledge, as one line. Each
/// service file is read whole, as leash reads it: one leash would refuse
/// fails, rather than give the machine the wrong promises; and so does one
/// that listens where the chain's net does not, whose bind fence would
/// refuse at boot.
pub fn pledge(io: Io, gpa: Allocator, root: Dir, forms: []const Form, f: *Failure) ![]const u8 {
    var declared: std.ArrayList(u16) = .empty;
    for (forms) |fm| for (try fm.items(gpa, "net")) |line| {
        var why: []const u8 = "";
        const l = (form.listen(gpa, line, &why) catch |err| switch (err) {
            error.Invalid => return f.fail(
                gpa,
                "{s}/form.yaml: net: {s}: {s}",
                .{ fm.dir, line, why },
            ),
            error.OutOfMemory => return error.OutOfMemory,
        }) orelse continue;
        try declared.appendSlice(gpa, l.ports);
    };
    var promises: seal.Set = .empty;
    for (try form.services(io, gpa, root, forms, f)) |s| {
        const parsed = try parseService(gpa, s, f);
        for (parsed.listen) |p| if (mem.findScalar(u16, declared.items, p) == null)
            return f.fail(
                gpa,
                "{s}: listen tcp/{d}, which no net line declares: fence refuses the bind " ++
                    "(`listen tcp/{d} loopback` for the machine alone)",
                .{ s.path, p, p },
            );
        promises.setUnion(parsed.pledge);
    }
    var out: std.ArrayList(u8) = .empty;
    var it = promises.iterator();
    var sep: []const u8 = "";
    while (it.next()) |p| : (sep = " ") try out.print(gpa, "{s}{t}", .{ sep, p });
    try out.append(gpa, '\n');
    return out.items;
}

/// The services with a root, an image baked in: `root NAME DIR USER`, then
/// `write NAME PATH` for each path, what init binds beneath each image root
/// and fence allows there (cmd/init/oci.zig, cmd/fence).
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

/// The services' names along the chain, sorted, each once: what each form's
/// rootfs/etc/sv holds.
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
    const out = set.keys();
    sortStrings(out);
    return out;
}

/// The image's passwd as init seeds it: an account other than root's in
/// group 0, which reads /etc/shadow (Alpine's sync, shutdown, halt and
/// operator), given nogroup instead, so only root has gid 0 (posture's
/// files-accounts). Refused: a name or uid there twice, as two forms of a
/// bundle can make it.
pub fn accounts(gpa: Allocator, passwd: []const u8, f: *Failure) Error![]const u8 {
    try unique(gpa, "passwd", passwd, f);
    var out: std.ArrayList(u8) = .empty;
    var it = records(passwd);
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

/// A file's lines, the empty one after its last newline left out.
fn records(text: []const u8) mem.SplitIterator(u8, .scalar) {
    return mem.splitScalar(
        u8,
        if (mem.endsWith(u8, text, "\n")) text[0 .. text.len - 1] else text,
        '\n',
    );
}

/// Refuses an account file, passwd or group, that names one account, or
/// one id, twice.
fn unique(gpa: Allocator, file: []const u8, text: []const u8, f: *Failure) Error!void {
    var names: std.array_hash_map.String(void) = .empty;
    var ids: std.array_hash_map.String(void) = .empty;
    var it = records(text);
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

/// The chain's network policy, as fence enforces it: users as uids from
/// the image's own passwd, ports as numbers, a line each, sorted, each
/// once. `listen tcp/PORT... [loopback]`, `connect USER|all
/// PROTO/PORT|icmp... [public]`, `metadata USER...` (forms/README.md).
pub fn net(gpa: Allocator, forms: []const Form, passwd: []const u8, f: *Failure) Error![]const u8 {
    var uids: std.array_hash_map.String([]const u8) = .empty;
    var pw = records(passwd);
    while (pw.next()) |line| {
        var fi = mem.splitScalar(u8, line, ':');
        const name = fi.next() orelse "";
        _ = fi.next();
        try uids.put(gpa, name, fi.next() orelse "");
    }
    var out: std.ArrayList([]const u8) = .empty;
    for (forms) |fm| for (try fm.items(gpa, "net")) |item| {
        const line = uncommented(item);
        if (!try netLine(gpa, try words(gpa, line), &uids, &out)) return f.fail(
            gpa,
            "form {s}: form.yaml's net cannot compile: {s}",
            .{ forms[forms.len - 1].name, line },
        );
    };
    sortStrings(out.items);
    var text: std.ArrayList(u8) = .empty;
    for (out.items, 0..) |line, i| {
        if (i > 0 and mem.eql(u8, line, out.items[i - 1])) continue;
        try text.print(gpa, "{s}\n", .{line});
    }
    return text.items;
}

/// One net line's words compiled onto out; false for a line that cannot be.
fn netLine(
    gpa: Allocator,
    w: []const []const u8,
    uids: *const std.array_hash_map.String([]const u8),
    out: *std.ArrayList([]const u8),
) Allocator.Error!bool {
    if (w.len == 0) return true;
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

/// PREFIX followed by a port, 1 to 65535, in digits; or null.
fn port(word: []const u8, prefix: []const u8) ?u16 {
    if (!mem.startsWith(u8, word, prefix) or word.len == prefix.len) return null;
    for (word[prefix.len..]) |c| if (!std.ascii.isDigit(c)) return null;
    const n = std.fmt.parseInt(u32, word[prefix.len..], 10) catch return null;
    return if (n >= 1 and n <= 65535) @intCast(n) else null;
}

const testing = std.testing;

/// A form from form.yaml's text alone, for the functions that read only
/// its spec.
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
            "  - metadata web\n  - connect _update tcp/443\n"),
    }, passwd, &f);
    try testing.expectEqualStrings(
        "connect 300 tcp 443 public\nconnect 69 tcp 443\nconnect 69 tcp 53\nconnect 69 udp 53\n" ++
            "connect all icmp\nlisten tcp 5432 loopback\nlisten tcp 8080\nmetadata 300\n",
        got,
    );
    for ([_][]const u8{
        "listen udp/53",          "listen tcp/0",
        "listen tcp/65536",       "listen loopback",
        "connect nobody tcp/443", "connect web icmp public",
        "connect web public",     "metadata nobody",
        "serve tcp/80",           "connect web sctp/9",
        "listen tcp/",            "listen tcp/99999999999999999999",
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
        "* ?files-x\nx86_64 kernel-y\naarch64 kernel-z\n";
    try testing.expectEqualStrings(
        "programs-no-shell a shell for logins\n?files-x every form on aarch64 " ++
            "(test/posture-known)\n" ++
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

test "compose: ro and meta from a chain and the image's accounts" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    for ([_][3][]const u8{
        .{ "minimal", "", "" },
        .{
            "web",
            "base: minimal\nallow: [ipv6]\nnet:\n  - listen tcp/80\n",
            "pledge stdio inet listen\n",
        },
    }) |c| {
        try tmp.dir.createDirPath(
            io,
            try gpa.print("forms/{s}/rootfs/etc/sv/{s}", .{ c[0], c[0] }),
        );
        try tmp.dir.writeFile(
            io,
            .{ .sub_path = try gpa.print("forms/{s}/apko.yaml", .{c[0]}), .data = "" },
        );
        if (c[1].len > 0) try tmp.dir.writeFile(
            io,
            .{ .sub_path = try gpa.print("forms/{s}/form.yaml", .{c[0]}), .data = c[1] },
        );
        if (c[2].len > 0) try tmp.dir.writeFile(io, .{
            .sub_path = try gpa.print("forms/{s}/rootfs/etc/sv/{s}/service", .{ c[0], c[0] }),
            .data = try gpa.print(
                "exec /usr/bin/{s}\nuser {s}\nlisten tcp/80\n{s}",
                .{ c[0], c[0], c[2] },
            ),
        });
    }
    try tmp.dir.createDirPath(io, "image/etc");
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "image/etc/passwd", .data = "root:x:0:0::/root:/x\nweb:x:80:80::/:/x\n" },
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "image/etc/group", .data = "root:x:0:\nweb:x:80:\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "image/etc/shadow", .data = "root:*:::::::\n" });
    var f: Failure = .{};
    const forms = try form.chain(io, gpa, tmp.dir, "web", &f);
    var image = try tmp.dir.openDir(io, "image", .{});
    defer image.close(io);
    var ro = try tmp.dir.createDirPathOpen(io, "ro", .{});
    defer ro.close(io);
    var meta = try tmp.dir.createDirPathOpen(io, "meta", .{});
    defer meta.close(io);
    try compose(io, gpa, tmp.dir, forms, image, ro, meta, .{ .arch = .aarch64 }, &f);

    try ro.access(io, "etc/werewolf/allow/ipv6", .{});
    var buf: [64]u8 = undefined;
    for ([_][]const u8{ "minimal", "web" }) |s| try testing.expectEqualStrings(
        try gpa.print("/run/runit/supervise.{s}", .{s}),
        buf[0..try ro.readLink(io, try gpa.print("etc/sv/{s}/supervise", .{s}), &buf)],
    );
    for ([_][2][]const u8{
        .{ "usr/share/werewolf/form", "web\n" },
        .{ "usr/share/werewolf/net", "listen tcp 80\n" },
        .{ "usr/share/werewolf/pledge", "stdio inet listen\n" },
        .{ "usr/share/werewolf/module-params", "" },
        .{ "usr/share/werewolf/cmdlin" ++
            "e", "debugfs=off proc_mem.force_override=never slab_nomerge " ++
            "page_alloc.shuffle=1 kvm-arm.mode=none loglevel=5\n" },
    }) |want| try testing.expectEqualStrings(
        want[1],
        try meta.readFileAlloc(io, want[0], gpa, .limited(4096)),
    );
    try testing.expectError(error.FileNotFound, meta.access(io, "usr/share/werewolf/oci", .{}));
    try testing.expectError(error.FileNotFound, meta.access(io, "usr/share/werewolf/dev", .{}));
}
