//! adhoc turns command-line flags (forms, packages, OCI images) into a form
//! directory and hands it to build, run, create or pack as FORM, so a one-shot
//! machine and a kept form build the same way. See README.md and
//! docs/design/adhoc.md.
//!
//!     howl run --with caddy                          # one form, as it is
//!     howl run --with caddy,valkey,postgresql        # forms to combine
//!     howl run --with python --package py3.13-flask  # packages to add
//!     howl run --oci web=ghcr.io/acme/web:1.4 \      # an image to run
//!              --web.listen tcp/8080
//!     howl create shop --with caddy,valkey           # prod, with both
//!     howl form --with caddy,valkey -o forms/shop/   # keep the form

const std = @import("std");
const howl = @import("howl.zig");
const oci = @import("oci.zig");
const forms = @import("form");
const compose = @import("compose");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Why = howl.Why;

pub const Verb = enum { build, run, create, form, pack };

const syntax =
    "[--with FORM,...] [--package PKG,...] [--oci NAME=REF --NAME.DIRECTIVE 'LINE'...] " ++
    "[--link A:B,...]; form adds -o DIR, and -n shows the form";

/// default_pledge is an image service's pledge unless --NAME.pledge says otherwise.
const default_pledge = "stdio rpath wpath inet unix connect listen proc";
const default_memory = "512";

/// Line is one line of an image's service file, as the operator gave it.
const Line = struct { key: []const u8, words: []const u8 };

/// line_keys are the service-file directives --NAME.KEY may set (cmd/leash).
const line_keys = [_][]const u8{
    "listen", "connect", "write",  "read",   "run",    "env",    "secret",
    "exec",   "dir",     "memory", "nofile", "pledge", "before", "requires",
};

const Image = struct {
    name: []const u8,
    ref: []const u8,
    lines: []const Line = &.{},
    /// pinned is set while the form is made.
    pinned: []const u8 = "",

    fn user(i: Image, gpa: Allocator) ![]const u8 {
        return gpa.print("_oci-{s}", .{i.name});
    }

    /// each returns the words of the operator's lines with key.
    fn each(i: Image, key: []const u8, gpa: Allocator) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        for (i.lines) |l| if (std.mem.eql(u8, l.key, key)) try out.append(gpa, l.words);
        return out.items;
    }

    fn has(i: Image, key: []const u8) bool {
        for (i.lines) |l| if (std.mem.eql(u8, l.key, key)) return true;
        return false;
    }

    /// ports returns the tcp/PORT words of the image's listen lines.
    fn ports(i: Image, gpa: Allocator) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        for (i.lines) |l| if (std.mem.eql(u8, l.key, "listen")) {
            var words = std.mem.tokenizeAny(u8, l.words, " \t");
            while (words.next()) |w| if (std.mem.startsWith(u8, w, "tcp/")) try out.append(gpa, w);
        };
        return out.items;
    }
};

const Link = struct { from: []const u8, to: []const u8 };
/// Weakness is a posture check the form fails, and the excuse form.yaml gives.
const Weakness = struct { check: []const u8, excuse: []const u8 };
/// list_keys are the form.yaml lists that --KEY LINE adds to. dev is left out
/// because --dev is the verbs' debug-shell flag.
const list_keys = [_][]const u8{ "net", "prune", "modules", "programs" };
/// ListLine adds a line to a form.yaml list; MapLine sets a scalar in a map.
const ListLine = struct { key: []const u8, line: []const u8 };
const MapLine = struct { key: []const u8, sub: []const u8, value: []const u8 };

/// Plan is what the ad-hoc flags asked for; the verb's own flags stay in rest.
const Plan = struct {
    verb: Verb,
    base: []const u8 = "prod",
    with: []const []const u8 = &.{},
    packages: []const []const u8 = &.{},
    images: []Image = &.{},
    links: []const Link = &.{},
    lists: []const ListLine = &.{},
    maps: []const MapLine = &.{},
    /// weaknesses are the chain's, restated while the form is made.
    weaknesses: []const Weakness = &.{},
    /// ours reports whether any ad-hoc flag was given.
    ours: bool = false,
    positionals: usize = 0,
    /// name is create's machine name, which also names the form's directory.
    name: ?[]const u8 = null,
    /// out is form's -o DIR.
    out: ?[]const u8 = null,
    show_only: bool = false,
    /// arch is --arch or the host's, and selects the images' platform too.
    /// It is null on a host werewolf does not build for, unless --arch is given.
    arch: ?howl.Arch,
    /// rest holds the verb's own arguments, in order.
    rest: []const []const u8,
    /// line is the whole command line, recorded in the form's first comment.
    line: []const u8,

    fn dir(p: Plan, gpa: Allocator) ![]const u8 {
        return switch (p.verb) {
            .form => std.mem.trimEnd(u8, p.out.?, "/"),
            .create => gpa.print("build/adhoc/{s}", .{p.name.?}),
            .run => "build/adhoc/run",
            .build => "build/adhoc/adhoc",
            .pack => "build/adhoc/pack",
        };
    }

    fn image(p: Plan, name: []const u8) ?*Image {
        for (p.images) |*i| if (std.mem.eql(u8, i.name, name)) return i;
        return null;
    }
};

/// take consumes the ad-hoc flags in args and returns the verb's arguments, with
/// the generated directory as FORM. It returns null when nothing is left to do:
/// for -n, and for the form verb.
pub fn take(
    io: Io,
    gpa: Allocator,
    verb: Verb,
    args: []const []const u8,
    why: *Why,
) !?[]const []const u8 {
    // run's form when none is named, and the base its flags build on, on
    // every engine: playground, which Lima manages and anyone may log in to.
    const fallback = if (verb == .run) "playground" else "prod";
    var p = try plan(gpa, verb, args, fallback, why);
    if (try references(&p, fallback, why)) |ref| {
        // A single form with nothing added runs unchanged, so -n has nothing
        // to show. pack has its own -n, so leave it to pack.
        const asked = p.show_only or (verb != .pack and for (args) |a| {
            if (std.mem.eql(u8, a, "-n")) break true;
        } else false);
        if (asked) {
            howl.say(io, "{s} as it is: nothing to generate", .{ref});
            return null;
        }
        if (!p.ours) return try std.mem.concat(gpa, []const u8, &.{ &.{ref}, args });
        var same: std.ArrayList([]const u8) = .empty;
        try same.append(gpa, ref);
        if (p.name) |n| try same.append(gpa, n);
        try same.appendSlice(gpa, p.rest);
        return same.items;
    }
    const dir = try p.dir(gpa);
    if (verb == .form) {
        if (Dir.cwd().access(io, dir, .{})) |_| return why.refuse(
            "{s} exists: a form is written where nothing is, so nothing is lost under it",
            .{dir},
        ) else |_| {}
    } else Dir.cwd().deleteTree(io, dir) catch {};
    Dir.cwd().createDirPath(io, dir) catch |err|
        return why.refuse("{s}: {s}", .{ dir, @errorName(err) });
    // The directory did not exist before, so remove it on any refusal.
    errdefer Dir.cwd().deleteTree(io, dir) catch {};

    // Resolve and check every image before pulling any, so a refusal costs
    // no download.
    for (p.images) |*i| {
        i.pinned = try oci.resolve(io, gpa, i.ref, why);
        if (!std.mem.eql(u8, i.pinned, i.ref))
            howl.say(io, "{s}: {s} is {s}", .{ i.name, i.ref, i.pinned });
    }
    const arch = @tagName(p.arch orelse return why.refuse(
        "{s}: give --arch",
        .{howl.not_built_here},
    ));
    const configs = try gpa.alloc(oci.Config, p.images.len);
    for (p.images, configs) |i, *c| {
        c.* = try oci.config(io, gpa, i.pinned, arch, why);
        try checklist(i, c.*, why);
    }

    // Write the form once so its chain can be read, then again with the
    // weaknesses that depend on the chain.
    try write(io, gpa, dir, "form.yaml", try renderForm(gpa, p), why);
    try write(io, gpa, dir, "apko.yaml", try renderApko(gpa, p), why);
    const chain = try howl.chain(io, gpa, dir, why);
    try inherit(gpa, &p, chain);
    try write(io, gpa, dir, "form.yaml", try renderForm(gpa, p), why);
    for (p.images, configs) |i, c| try bake(io, gpa, p, i, c, dir, why);
    // Read the chain as the build will, so the build's refusals come now.
    const c = try check(io, gpa, dir, why);

    var out: Io.Writer.Allocating = .init(gpa);
    const w = &out.writer;
    try w.print("howl: {s}/form.yaml:\n", .{dir});
    try indent(w, try renderForm(gpa, p));
    if (p.packages.len > 0 or p.images.len > 0) {
        try w.print("howl: {s}/apko.yaml:\n", .{dir});
        try indent(w, try renderApko(gpa, p));
    }
    for (p.images) |i| {
        const svc = try gpa.print("{s}/rootfs/etc/sv/{s}/service", .{ dir, i.name });
        try w.print("howl: {s}:\n", .{svc});
        try indent(w, Dir.cwd().readFileAlloc(io, svc, gpa, .limited(64 << 10)) catch "");
    }
    try w.print("howl: {d} services", .{c.services});
    if (c.memory > 0) try w.print(", memory limits {d} MiB in all", .{c.memory});
    try w.writeAll("\n");
    if (verb != .form) try w.print(
        "howl: keep it: howl form {s} -o forms/{s}/\n",
        .{ try flags(gpa, p), if (p.name) |n| n else "NAME" },
    );
    Io.File.stderr().writeStreamingAll(io, out.written()) catch {};
    // With -n, leave nothing at -o: the directory was written only to
    // check the chain.
    if (p.show_only and verb == .form) Dir.cwd().deleteTree(io, dir) catch {};
    if (p.show_only or verb == .form) return null;

    var next: std.ArrayList([]const u8) = .empty;
    try next.append(gpa, dir);
    if (p.name) |n| try next.append(gpa, n);
    try next.appendSlice(gpa, p.rest);
    return next.items;
}

/// form is `howl form`: it writes the form to -o DIR and builds nothing.
pub fn form(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    _ = try take(io, gpa, .form, args, why);
}

/// plan parses the ad-hoc flags and positionals in args. If there are no
/// ad-hoc flags and the verb is not form, it returns early with ours false.
fn plan(gpa: Allocator, verb: Verb, args: []const []const u8, base: []const u8, why: *Why) !Plan {
    var p: Plan = .{
        .verb = verb,
        .base = base,
        .rest = &.{},
        .arch = howl.hostArch(),
        .line = try std.mem.join(gpa, " ", args),
    };
    var rest: std.ArrayList([]const u8) = .empty;
    var positional: std.ArrayList([]const u8) = .empty;
    var images: std.ArrayList(Image) = .empty;
    var lines: std.ArrayList(struct { image: []const u8, line: Line, flag: []const u8 }) = .empty;
    var lists_: std.ArrayList(ListLine) = .empty;
    var links: std.ArrayList(Link) = .empty;
    var ours = verb == .form;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len == 0 or a[0] != '-') {
            try positional.append(gpa, a);
            continue;
        }
        if (std.mem.eql(u8, a, "-n")) {
            // -n is the verb's own (pack's check) unless an ad-hoc flag
            // appears; that is decided below, once the line is read.
            try rest.append(gpa, a);
            continue;
        }
        var name = a;
        var value: ?[]const u8 = null;
        if (std.mem.findScalar(u8, a, '=')) |eq| {
            name = a[0..eq];
            value = a[eq + 1 ..];
        }
        const dot = if (std.mem.startsWith(u8, name, "--"))
            std.mem.findScalar(u8, name, '.')
        else
            null;
        const is_list = for (list_keys) |k| {
            if (name.len > 2 and std.mem.eql(u8, name[2..], k)) break true;
        } else false;
        const is_with = std.mem.eql(u8, name, "--with");
        const is_packages = std.mem.eql(u8, name, "--package");
        const is_oci = std.mem.eql(u8, name, "--oci");
        const is_link = std.mem.eql(u8, name, "--link");
        const is_out = verb == .form and std.mem.eql(u8, name, "-o");
        if (!is_with and !is_packages and !is_oci and !is_link and !is_out and !is_list and
            dot == null)
        {
            // Pass the verb's own flag, and its value if it takes one.
            try rest.append(gpa, a);
            if (std.mem.eql(u8, name, "--arch") or std.mem.eql(u8, name, "-arch")) {
                const v = value orelse if (i + 1 < args.len) args[i + 1] else "";
                p.arch = howl.archName(v) orelse return why.refuse(howl.arch_refusal, .{v});
            }
            if (value == null and !takesNothing(a) and i + 1 < args.len) {
                i += 1;
                try rest.append(gpa, args[i]);
            }
            continue;
        }
        // In --oci NAME=REF, the = belongs to the value, not the flag.
        if (is_oci and value != null) value = null;
        const v = value orelse v: {
            i += 1;
            if (i == args.len) return why.refuse("{s} wants a value", .{a});
            break :v args[i];
        };
        ours = true;
        if (is_out) {
            if (p.out != null) return why.refuse("-o given twice", .{});
            p.out = v;
        } else if (is_oci) {
            const eq = std.mem.findScalar(u8, v, '=') orelse
                return why.refuse("--oci {s}: NAME=REF, the name yours", .{v});
            const n = v[0..eq];
            const ref = v[eq + 1 ..];
            if (!forms.isName(n) or n.len > 24) return why.refuse(
                "--oci {s}: a name is a-z, 0-9 and -, at most 24",
                .{n},
            );
            if (!oci.isRef(ref)) return why.refuse("--oci {s}: not an image reference", .{ref});
            for (images.items) |have| if (std.mem.eql(u8, have.name, n))
                return why.refuse("--oci {s}: twice", .{n});
            try images.append(gpa, .{ .name = n, .ref = ref });
        } else if (is_link) {
            for (try split(gpa, v)) |pair| {
                const colon = std.mem.findScalar(u8, pair, ':') orelse
                    return why.refuse("--link {s}: A:B, A reaching B", .{pair});
                try links.append(gpa, .{ .from = pair[0..colon], .to = pair[colon + 1 ..] });
            }
        } else if (is_list) {
            if (std.mem.trim(
                u8,
                v,
                " \t",
            ).len == 0) return why.refuse("{s}: an empty line", .{name});
            try lists_.append(gpa, .{ .key = name[2..], .line = std.mem.trim(u8, v, " \t") });
        } else if (dot) |d| {
            const key = name[d + 1 ..];
            if (key.len == 0 or d == 2) return why.refuse("{s}: --KEY.SUB VALUE", .{name});
            if (std.mem.trim(
                u8,
                v,
                " \t",
            ).len == 0) return why.refuse("{s}: an empty line", .{name});
            try lines.append(gpa, .{
                .image = name[2..d],
                .line = .{ .key = key, .words = std.mem.trim(u8, v, " \t") },
                .flag = name,
            });
        } else {
            // --with and --package may repeat or join names with commas.
            const list = try split(gpa, v);
            if (list.len == 0) return why.refuse("{s}: a name, or names separated by commas", .{a});
            const into: *[]const []const u8 = if (is_with) &p.with else &p.packages;
            into.* = try std.mem.concat(gpa, []const u8, &.{ into.*, list });
        }
    }
    const pos = positional.items;
    // Forms are named with --with; create's one positional is the machine.
    switch (verb) {
        .create => if (pos.len == 1) {
            p.name = pos[0];
        } else return why.refuse("create NAME {s}", .{syntax}),
        else => if (pos.len > 0) return why.refuse(
            "{s}: forms are named with --with: howl {t} --with {s}",
            .{ pos[0], verb, pos[0] },
        ),
    }
    p.positionals = pos.len;
    if (!ours) return p;
    p.ours = true;
    // An ad-hoc flag was given, so -n means show the form and stop.
    var kept: std.ArrayList([]const u8) = .empty;
    for (rest.items) |a| if (std.mem.eql(u8, a, "-n")) {
        p.show_only = true;
    } else try kept.append(gpa, a);
    p.rest = kept.items;
    p.images = images.items;
    p.links = links.items;

    if (verb == .form and
        p.out == null) return why.refuse("form writes to -o DIR: form {s}", .{syntax});
    if (p.out) |o| {
        const named = std.fs.path.basename(std.mem.trimEnd(u8, o, "/"));
        if (!forms.isName(named)) return why.refuse(
            "-o {s}: a form is named after its directory, of a-z, 0-9 and -",
            .{o},
        );
    }
    for (p.with, 0..) |m, k| {
        // Accept a name in forms/ or a kept form's directory, which has a slash.
        if (!forms.isName(m) and std.mem.findScalar(u8, m, '/') == null)
            return why.refuse("--with {s}: not a form's name", .{m});
        for (p.with[0..k]) |seen| if (std.mem.eql(u8, m, seen))
            return why.refuse("--with {s}: twice", .{m});
    }
    for (p.packages, 0..) |pkg, k| {
        if (!isPackage(pkg)) return why.refuse(
            "--package {s}: a Wolfi package is [A-Za-z0-9][A-Za-z0-9._+-]*, pinned as " ++
                "NAME=VERSION",
            .{pkg},
        );
        for (p.packages[0..k]) |seen| if (std.mem.eql(u8, pkg, seen))
            return why.refuse("--package {s}: twice", .{pkg});
    }
    // --NAME.KEY goes to image NAME's service file if NAME is an image;
    // otherwise it sets a scalar in form.yaml's map NAME. Each only once.
    var maps: std.ArrayList(MapLine) = .empty;
    for (lines.items) |l| {
        const img = p.image(l.image) orelse {
            for ([_][]const u8{ "base", "with" } ++ list_keys) |k|
                if (std.mem.eql(u8, l.image, k)) return why.refuse(
                    "{s}: {s} is not a map in form.yaml; --{s} LINE adds to a list",
                    .{ l.flag, l.image, l.image },
                );
            // Weaknesses are not inherited; the chain's are restated, and
            // any new one must be written in form.yaml by hand.
            if (std.mem.eql(u8, l.image, "weaknesses")) return why.refuse(
                "{s}: weaknesses are not the line's; form -o DIR, then edit DIR/form.yaml",
                .{l.flag},
            );
            for (maps.items) |have| if (std.mem.eql(u8, have.key, l.image) and
                std.mem.eql(u8, have.sub, l.line.key))
                return why.refuse("{s}: twice", .{l.flag});
            try maps.append(gpa, .{ .key = l.image, .sub = l.line.key, .value = l.line.words });
            continue;
        };
        const known = for (line_keys) |k| {
            if (std.mem.eql(u8, k, l.line.key)) break true;
        } else false;
        if (!known) return why.refuse(
            "{s}: an image's line is one of listen connect write read run env secret exec " ++
                "dir memory nofile pledge before requires",
            .{l.flag},
        );
        for ([_][]const u8{ "exec", "dir", "memory", "nofile", "pledge" }) |once|
            if (std.mem.eql(u8, l.line.key, once) and img.has(once))
                return why.refuse("{s}: twice; the service takes one", .{l.flag});
        var more: std.ArrayList(Line) = .empty;
        try more.appendSlice(gpa, img.lines);
        try more.append(gpa, l.line);
        img.lines = more.items;
    }
    p.maps = maps.items;
    p.lists = lists_.items;
    for (p.images) |img| for (list_keys) |k| if (std.mem.eql(u8, img.name, k))
        return why.refuse(
            "--oci {s}: a form.yaml key's name; call the image something else",
            .{img.name},
        );
    for (p.links) |l| {
        if (p.image(l.from) == null) return why.refuse(
            "--link {s}:{s}: no image {s}",
            .{ l.from, l.to, l.from },
        );
        const to = p.image(l.to) orelse return why.refuse(
            "--link {s}:{s}: no image {s}; a link to a form's service is not built yet, " ++
                "say --{s}.connect and the form's loopback port",
            .{ l.from, l.to, l.to, l.from },
        );
        if (std.mem.eql(
            u8,
            l.from,
            l.to,
        )) return why.refuse("--link {s}:{s}: to itself", .{ l.from, l.to });
        if ((try to.ports(gpa)).len == 0) return why.refuse(
            "--link {s}:{s}: {s} listens on nothing; say --{s}.listen 'tcp/PORT loopback'",
            .{ l.from, l.to, l.to, l.to },
        );
    }
    // Refuse two images listening on one port.
    for (p.images, 0..) |a, k| for (try a.ports(
        gpa,
    )) |pa| for (p.images[0..k]) |b| for (try b.ports(gpa)) |pb|
        if (std.mem.eql(u8, pa, pb)) return why.refuse(
            "{s} and {s} both listen on {s}: one machine serves a port once",
            .{ b.name, a.name, pa },
        );
    return p;
}

/// references returns the form to use unchanged when at most one --with is given
/// and nothing is added. Otherwise it sets p.base (the single --with, or
/// fallback) and returns null, meaning a form must be generated.
fn references(p: *Plan, fallback: []const u8, why: *Why) !?[]const u8 {
    const content = p.packages.len > 0 or p.images.len > 0 or p.lists.len > 0 or
        p.maps.len > 0 or p.links.len > 0;
    if (p.with.len <= 1 and !content and p.verb != .form)
        return if (p.with.len == 1) p.with[0] else fallback;
    for (p.with) |m| if (std.mem.findScalar(u8, m, '/') != null) return why.refuse(
        "--with {s}: a kept form's directory runs as it is; to build on it, name it or edit it",
        .{m},
    );
    if (p.with.len == 1) {
        p.base = p.with[0];
        p.with = &.{};
    } else p.base = fallback;
    return null;
}

/// checklist refuses an image that declares ports or volumes unless the operator
/// gave a listen or write line, since the image's config grants nothing. The
/// refusal lists the lines to add, loopback first.
fn checklist(i: Image, c: oci.Config, why: *Why) !void {
    if ((c.exposed.len == 0 and c.volumes.len == 0) or i.has("listen") or i.has("write")) return;
    var text: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&text);
    w.print("{s}: the image", .{i.name}) catch {};
    if (c.exposed.len > 0) {
        w.writeAll(" exposes") catch {};
        for (c.exposed) |e| w.print(" {s}", .{e}) catch {};
    }
    if (c.volumes.len > 0) {
        w.writeAll(if (c.exposed.len > 0) " and writes" else " writes") catch {};
        for (c.volumes) |v| w.print(" {s}", .{v}) catch {};
    }
    w.writeAll("; nothing is granted. Say what you want:\n") catch {};
    for (c.exposed) |e| {
        const port = e[0 .. std.mem.findScalar(u8, e, '/') orelse e.len];
        w.print(
            "    --{s}.listen 'tcp/{s} loopback'   for a linked image alone\n",
            .{ i.name, port },
        ) catch {};
        w.print("    --{s}.listen tcp/{s}              public\n", .{ i.name, port }) catch {};
    }
    for (c.volumes) |v| w.print("    --{s}.write {s}\n", .{ i.name, v }) catch {};
    return why.refuse("{s}", .{std.mem.trimEnd(u8, w.buffered(), "\n")});
}

/// renderForm returns form.yaml: base, with, net (with each image's network
/// policy), the other lists and maps, and the restated weaknesses.
fn renderForm(gpa: Allocator, p: Plan) ![]const u8 {
    var f: Io.Writer.Allocating = .init(gpa);
    const w = &f.writer;
    try w.print(
        "# Generated by howl from the command line (docs/design/adhoc.md):\n#   howl {t} {s}\n" ++
            "# Edit it as any form; forms/README.md says what each key is.\nbase: {s}\n",
        .{ p.verb, p.line, p.base },
    );
    if (p.with.len > 0) try w.print("with: [{s}]\n", .{try std.mem.join(gpa, ", ", p.with)});
    var net: std.ArrayList([]const u8) = .empty;
    for (p.lists) |l| if (std.mem.eql(u8, l.key, "net")) try net.append(gpa, l.line);
    for (p.images) |i| {
        for (try i.each("listen", gpa)) |l| try net.append(gpa, try gpa.print("listen {s}", .{l}));
        for (try i.each("connect", gpa)) |c|
            try net.append(gpa, try gpa.print("connect {s} {s}", .{ try i.user(gpa), c }));
    }
    if (net.items.len > 0) {
        try w.writeAll("net:\n");
        for (net.items) |l| try w.print("  - {s}\n", .{l});
    }
    for (list_keys[1..]) |k| {
        var first = true;
        for (p.lists) |l| if (std.mem.eql(u8, l.key, k)) {
            if (first) try w.print("{s}:\n", .{k});
            first = false;
            try w.print("  - {s}\n", .{l.line});
        };
    }
    // Quote map scalars, since a value may hold [ or ,.
    var done: std.ArrayList([]const u8) = .empty;
    for (p.maps) |m| {
        const seen = for (done.items) |d| {
            if (std.mem.eql(u8, d, m.key)) break true;
        } else false;
        if (seen) continue;
        try done.append(gpa, m.key);
        try w.print("{s}:\n", .{m.key});
        for (p.maps) |n| if (std.mem.eql(u8, n.key, m.key))
            try w.print("  {s}: \"{s}\"\n", .{ n.sub, n.value });
    }
    if (p.weaknesses.len > 0) {
        try w.writeAll("\n# The chain's own weaknesses, restated: a form's are never inherited.\n");
        try w.writeAll("weaknesses:\n");
        for (p.weaknesses) |x| try w.print("  {s}: {s}\n", .{ x.check, x.excuse });
    }
    return f.written();
}

/// renderApko returns apko.yaml: the added packages and an account for each
/// image. Each account gets compose.defaultId, the id the build would give
/// it, so an image keeps its owner whatever else the command line names.
fn renderApko(gpa: Allocator, p: Plan) ![]const u8 {
    var a: Io.Writer.Allocating = .init(gpa);
    const w = &a.writer;
    try w.writeAll("# Generated by howl; the chain's packages come through base and with.\n");
    if (p.packages.len == 0) {
        try w.writeAll("contents:\n  packages: []\n");
    } else {
        try w.writeAll("contents:\n  packages:\n");
        for (p.packages) |pkg| try w.print("    - {s}\n", .{pkg});
    }
    if (p.images.len == 0) return a.written();
    try w.writeAll(
        "\n# Each image runs as a user of its own, no service's and no one's to share.\n",
    );
    try w.writeAll("accounts:\n  groups:\n");
    for (p.images) |i| {
        const user = try i.user(gpa);
        try w.print("    - groupname: {s}\n      gid: {d}\n", .{ user, compose.defaultId(user) });
    }
    try w.writeAll("  users:\n");
    for (p.images) |i| {
        const user = try i.user(gpa);
        const id = compose.defaultId(user);
        try w.print(
            "    - username: {s}\n      uid: {d}\n      gid: {d}\n      homedir: /var/empty\n" ++
                "      shell: /sbin/nologin\n",
            .{ user, id, id },
        );
    }
    return a.written();
}

/// inherit copies the chain's weaknesses into p, each once, the later form's
/// excuse winning. They must be restated because weaknesses are not inherited.
fn inherit(gpa: Allocator, p: *Plan, chain: []const forms.Form) !void {
    var out: std.ArrayList(Weakness) = .empty;
    for (chain[0 .. chain.len - 1]) |f| for (f.weaknesses()) |e| {
        const excuse = if (e.value == .scalar) e.value.scalar.raw else continue;
        const have = for (out.items) |*have| {
            if (std.mem.eql(u8, have.check, e.key)) break have;
        } else null;
        if (have) |h|
            h.excuse = excuse
        else
            try out.append(gpa, .{ .check = e.key, .excuse = excuse });
    };
    p.weaknesses = out.items;
}

/// bake pulls the image into rootfs/oci/NAME, prepares its bind points, and
/// writes its leash service: root, exec, dir, user, pledge, memory, the image's
/// environment, then the operator's lines.
fn bake(
    io: Io,
    gpa: Allocator,
    p: Plan,
    i: Image,
    c: oci.Config,
    dir: []const u8,
    why: *Why,
) !void {
    const tree = try gpa.print("{s}/rootfs/oci/{s}", .{ dir, i.name });
    const u = try oci.pull(io, gpa, i.pinned, @tagName(p.arch.?), tree, why);
    howl.say(io, "{s}: {s}: {d} files, {d} bytes{s}", .{
        i.name,
        i.pinned,
        u.files,
        u.bytes,
        if (u.left_out > 0) ", device nodes and FIFOs left out" else "",
    });
    const writes = try i.each("write", gpa);
    for (writes) |path| if (path.len == 0 or path[0] != '/' or
        std.mem.findScalar(u8, path, ' ') != null)
        return why.refuse("--{s}.write {s}: one absolute path a line", .{ i.name, path });
    try oci.prepare(io, gpa, tree, i.name, writes, why);

    var override: ?[]const []const u8 = null;
    const execs = try i.each("exec", gpa);
    if (execs.len > 0) override = try splitLine(gpa, execs[0], i.name, why);
    const argv = try oci.entrypoint(io, gpa, tree, i.name, c, override, why);

    var s: Io.Writer.Allocating = .init(gpa);
    const w = &s.writer;
    try w.print(
        "# {s}, from howl form: the image's own entrypoint and environment,\n",
        .{i.pinned},
    );
    try w.writeAll("# then what its operator said (docs/design/adhoc.md).\n");
    try w.print("root    /oci/{s}\n", .{i.name});
    try w.writeAll("exec   ");
    for (argv) |a| try word(w, a, why);
    try w.writeAll("\n");
    const dirs = try i.each("dir", gpa);
    try w.print(
        "dir     {s}\n",
        .{if (dirs.len > 0) dirs[0] else if (c.workdir.len > 0) c.workdir else "/data"},
    );
    try w.print("user    {s}\n", .{try i.user(gpa)});
    const pledge = try i.each("pledge", gpa);
    try w.print("pledge  {s}\n", .{if (pledge.len > 0) pledge[0] else default_pledge});
    const memory = try i.each("memory", gpa);
    try w.print("memory  {s}\n", .{if (memory.len > 0) memory[0] else default_memory});
    var has_path = false;
    var has_home = false;
    for (c.env) |e| {
        if (std.mem.startsWith(u8, e, "PATH=")) has_path = true;
        if (std.mem.startsWith(u8, e, "HOME=")) has_home = true;
        try w.writeAll("env    ");
        try word(w, e, why);
        try w.writeAll("\n");
    }
    if (!has_path) try w.print("env     PATH={s}\n", .{oci.default_path});
    if (!has_home) try w.writeAll("env     HOME=/data\n");
    for (i.lines) |l| {
        if (std.mem.eql(u8, l.key, "exec") or std.mem.eql(u8, l.key, "dir") or
            std.mem.eql(u8, l.key, "pledge") or std.mem.eql(u8, l.key, "memory")) continue;
        // leash takes only TCP ports. The rest of a listen or connect line
        // (loopback, udp, public) is fence's, in form.yaml's net.
        if (std.mem.eql(u8, l.key, "listen") or std.mem.eql(u8, l.key, "connect")) {
            var tcp: std.ArrayList([]const u8) = .empty;
            var words = std.mem.tokenizeAny(u8, l.words, " \t");
            while (words.next()) |x| if (std.mem.startsWith(u8, x, "tcp/")) try tcp.append(gpa, x);
            if (tcp.items.len == 0) continue;
            try w.print("{s} {s}\n", .{ l.key, try std.mem.join(gpa, " ", tcp.items) });
        } else try w.print("{s} {s}\n", .{ l.key, l.words });
    }
    // --link A:B lets A connect to B's ports on loopback.
    for (p.links) |l| if (std.mem.eql(u8, l.from, i.name)) {
        const to = p.image(l.to).?;
        try w.print("connect {s}\n", .{try std.mem.join(gpa, " ", try to.ports(gpa))});
    };
    const sv = try gpa.print("{s}/rootfs/etc/sv/{s}", .{ dir, i.name });
    Dir.cwd().createDirPath(
        io,
        sv,
    ) catch |err| return why.refuse("{s}: {s}", .{ sv, @errorName(err) });
    try write(io, gpa, sv, "service", s.written(), why);
    for ([_][2][]const u8{
        .{ "run", "/usr/lib/werewolf/leash" },
        .{ "finish", "/usr/lib/werewolf/leash-reap" },
    }) |link| Dir.cwd().symLink(
        io,
        link[1],
        try gpa.print("{s}/{s}", .{ sv, link[0] }),
        .{},
    ) catch |err|
        return why.refuse("{s}/{s}: {s}", .{ sv, link[0], @errorName(err) });
}

/// splitLine splits line into words as cmd/leash does: at blanks, except inside
/// double quotes.
fn splitLine(gpa: Allocator, line: []const u8, name: []const u8, why: *Why) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var at: usize = 0;
    while (at < line.len) {
        if (line[at] == ' ' or line[at] == '\t') {
            at += 1;
        } else if (line[at] == '"') {
            const end = std.mem.findScalarPos(u8, line, at + 1, '"') orelse
                return why.refuse("--{s}.exec: a quote is not closed", .{name});
            try out.append(gpa, line[at + 1 .. end]);
            at = end + 1;
        } else {
            var end = at;
            while (end < line.len and line[end] != ' ' and line[end] != '\t') : (end += 1) {
                if (line[end] == '"') return why.refuse(
                    "--{s}.exec: a quote inside a word",
                    .{name},
                );
            }
            try out.append(gpa, line[at..end]);
            at = end;
        }
    }
    return out.items;
}

/// word writes s as one word of a service line, quoted if it holds a blank. The
/// format has no escapes, so a quote or control character is refused.
fn word(w: *Io.Writer, s: []const u8, why: *Why) !void {
    if (std.mem.findScalar(u8, s, '"') != null or std.mem.findAny(u8, s, "\n\r\t") != null)
        return why.refuse("{s}: a service line cannot hold a quote or a control character", .{s});
    if (std.mem.findScalar(u8, s, ' ') != null)
        try w.print(" \"{s}\"", .{s})
    else
        try w.print(" {s}", .{s});
}

fn write(
    io: Io,
    gpa: Allocator,
    dir: []const u8,
    name: []const u8,
    text: []const u8,
    why: *Why,
) !void {
    const path = try gpa.print("{s}/{s}", .{ dir, name });
    Dir.cwd().writeFile(io, .{ .sub_path = path, .data = text }) catch |err|
        return why.refuse("{s}: {s}", .{ path, @errorName(err) });
}

/// flags returns the flags that make the same form, for the `howl form` hint.
fn flags(gpa: Allocator, p: Plan) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    const w = &out.writer;
    if (p.with.len > 0)
        try w.print("--with {s}", .{try std.mem.join(gpa, ",", p.with)})
    else if (!std.mem.eql(u8, p.base, "prod"))
        try w.print("--with {s}", .{p.base});
    if (p.packages.len > 0) try w.print(
        " --package {s}",
        .{try std.mem.join(gpa, ",", p.packages)},
    );
    for (p.images) |i| {
        try w.print(" --oci {s}={s}", .{ i.name, if (i.pinned.len > 0) i.pinned else i.ref });
        for (i.lines) |l| try w.print(" --{s}.{s} '{s}'", .{ i.name, l.key, l.words });
    }
    for (p.links) |l| try w.print(" --link {s}:{s}", .{ l.from, l.to });
    for (p.lists) |l| try w.print(" --{s} '{s}'", .{ l.key, l.line });
    for (p.maps) |m| try w.print(" --{s}.{s} '{s}'", .{ m.key, m.sub, m.value });
    return std.mem.trimStart(u8, out.written(), " ");
}

const Checked = struct { services: usize, memory: u64 };

/// check reads the chain as the build would, and refuses what the build refuses.
/// It also refuses two forms listening on one port, which the build allows but
/// the machine would fail at boot. It returns the service count and memory total.
fn check(io: Io, gpa: Allocator, dir: []const u8, why: *Why) !Checked {
    const c = try howl.chain(io, gpa, dir, why);
    // Include loopback ports: two services binding one port collide either way.
    const Port = struct { port: u16, form: []const u8 };
    var ports: std.ArrayList(Port) = .empty;
    for (c) |f| for (try f.items(gpa, "net")) |line| {
        var bad: []const u8 = "";
        const l = (forms.listen(gpa, line, &bad) catch |err| switch (err) {
            error.Invalid => return why.refuse("{s}/form.yaml: {s}", .{ f.dir, bad }),
            else => return err,
        }) orelse continue;
        for (l.ports) |port| {
            for (ports.items) |have| if (have.port == port and !std.mem.eql(u8, have.form, f.name))
                return why.refuse(
                    "{s} and {s} both listen on tcp/{d}: one machine serves a port once",
                    .{ have.form, f.name, port },
                );
            try ports.append(gpa, .{ .port = port, .form = f.name });
        }
    };
    var memory: u64 = 0;
    var failure: forms.Failure = .{};
    const svcs = forms.services(io, gpa, Dir.cwd(), c, &failure) catch |err| switch (err) {
        error.Form => return why.refuse("{s}", .{failure.text}),
        error.OutOfMemory => return error.OutOfMemory,
    };
    for (svcs) |s| {
        var lines = std.mem.splitScalar(u8, s.text, '\n');
        while (lines.next()) |line| {
            var words = std.mem.tokenizeAny(u8, line, " \t");
            if (!std.mem.eql(u8, words.next() orelse continue, "memory")) continue;
            memory += std.fmt.parseInt(u64, words.next() orelse continue, 10) catch continue;
        }
    }
    return .{ .services = svcs.len, .memory = memory };
}

/// takesNothing reports whether flag is a verb flag with no value; others take
/// the next word.
fn takesNothing(flag: []const u8) bool {
    for ([_][]const u8{ "--dev", "--build", "--yes", "--verbose", "-v", "-h", "--help" }) |f|
        if (std.mem.eql(u8, flag, f)) return true;
    return false;
}

/// split splits list at commas, trimming blanks and dropping empty words.
fn split(gpa: Allocator, list: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, list, ',');
    while (it.next()) |w| {
        const t = std.mem.trim(u8, w, " ");
        if (t.len > 0) try out.append(gpa, t);
    }
    return out.items;
}

/// isPackage reports whether s is a Wolfi package name, optionally pinned as
/// NAME=VERSION.
fn isPackage(s: []const u8) bool {
    if (s.len == 0 or s.len > 128 or !std.ascii.isAlphanumeric(s[0])) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._+-=~", c) == null)
        return false;
    return std.mem.findScalar(u8, s, '=') == null or
        (s[s.len - 1] != '=' and std.mem.count(u8, s, "=") == 1);
}

fn indent(w: *Io.Writer, text: []const u8) !void {
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, text, "\n"), '\n');
    while (lines.next()) |line| try w.print("    {s}\n", .{line});
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

fn expectWords(want: []const []const u8, got: []const []const u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expectEqualStrings(w, g);
}

test "a line with none of our flags is left alone" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: Why = .{};
    const p = try plan(
        arena.allocator(),
        .create,
        &.{ "edge", "--domain", "a.example", "-n" },
        "prod",
        &why,
    );
    try testing.expect(!p.ours);
    try testing.expectEqual(1, p.positionals);
    const bare = try plan(
        arena.allocator(),
        .run,
        &.{ "--on", "lima", "--dev" },
        "playground",
        &why,
    );
    try testing.expect(!bare.ours);
    try testing.expectEqual(0, bare.positionals);
    const with = try plan(arena.allocator(), .run, &.{ "--with", "valkey" }, "playground", &why);
    try testing.expect(with.ours);
    try testing.expectEqualStrings("playground", with.base);
}

test "positionals: create names the machine; run and build name a base" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    var c = try plan(gpa, .create, &.{ "shop", "--with", "caddy,valkey" }, "prod", &why);
    try testing.expectEqualStrings("shop", c.name.?);
    try testing.expectEqualStrings("build/adhoc/shop", try c.dir(gpa));
    try testing.expectEqual(null, try references(&c, "prod", &why));
    try testing.expectEqualStrings("prod", c.base);
    try expectWords(&.{ "caddy", "valkey" }, c.with);
    var one = try plan(gpa, .create, &.{ "shop", "--with", "caddy" }, "prod", &why);
    try testing.expectEqualStrings("caddy", (try references(&one, "prod", &why)).?);
    var one_more = try plan(
        gpa,
        .create,
        &.{ "shop", "--with", "caddy", "--package", "curl" },
        "prod",
        &why,
    );
    try testing.expectEqual(null, try references(&one_more, "prod", &why));
    try testing.expectEqualStrings("caddy", one_more.base);
    try testing.expectEqual(0, one_more.with.len);
    var none = try plan(gpa, .run, &.{"--dev"}, "playground", &why);
    try testing.expectEqualStrings("playground", (try references(&none, "playground", &why)).?);
    var kept = try plan(gpa, .run, &.{ "--with", "forms/shop/" }, "prod", &why);
    try testing.expectEqualStrings("forms/shop/", (try references(&kept, "prod", &why)).?);
    var kept_more = try plan(
        gpa,
        .run,
        &.{ "--with", "forms/shop/", "--package", "curl" },
        "prod",
        &why,
    );
    try testing.expectError(error.Refused, references(&kept_more, "prod", &why));
    var formed = try plan(gpa, .form, &.{ "--with", "caddy", "-o", "forms/x" }, "prod", &why);
    try testing.expectEqual(null, try references(&formed, "prod", &why));
    try testing.expectEqualStrings("caddy", formed.base);
    const c2 = try plan(
        gpa,
        .create,
        &.{ "--dev", "shop", "--with=caddy", "--with=valkey", "--domain", "x", "--on", "gcp" },
        "prod",
        &why,
    );
    try testing.expectEqualStrings("shop", c2.name.?);
    try expectWords(&.{ "caddy", "valkey" }, c2.with);
    try expectWords(&.{ "--dev", "--domain", "x", "--on", "gcp" }, c2.rest);
    const r = try plan(
        gpa,
        .run,
        &.{ "--with", "python", "--package", "py3.13-flask, py3.13-psycopg", "-n" },
        "prod",
        &why,
    );
    try expectWords(&.{"python"}, r.with);
    try expectWords(&.{ "py3.13-flask", "py3.13-psycopg" }, r.packages);
    try testing.expect(r.show_only);
    try testing.expectEqual(0, r.rest.len);
    try testing.expectEqualStrings("build/adhoc/run", try r.dir(gpa));
    const rr = try plan(
        gpa,
        .run,
        &.{
            "--with",
            "caddy",
            "--with",
            "valkey,postgresql",
            "--package",
            "curl",
            "--package",
            "jq",
        },
        "prod",
        &why,
    );
    try expectWords(&.{ "caddy", "valkey", "postgresql" }, rr.with);
    try expectWords(&.{ "curl", "jq" }, rr.packages);
    const f = try plan(
        gpa,
        .form,
        &.{ "--with", "caddy,valkey", "-o", "forms/shop/" },
        "prod",
        &why,
    );
    try testing.expectEqualStrings("forms/shop", try f.dir(gpa));
}

test "images, their lines and links" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const p = try plan(gpa, .run, &.{
        "--oci",           "web=ghcr.io/acme/web:1.4",
        "--oci",
        "worker=ghcr.io/acme/worker@sha256:" ++
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--web.listen",    "tcp/8080",
        "--web.listen",    "tcp/9090 loopback",
        "--web.env",       "LOG_LEVEL=info",
        "--worker.memory", "256",
        "--link",          "worker:web",
        "--arch",          "x86_64",
    }, "prod", &why);
    try testing.expectEqual(2, p.images.len);
    try testing.expectEqual(howl.Arch.x86_64, p.arch.?);
    try expectWords(&.{ "tcp/8080", "tcp/9090" }, try p.images[0].ports(gpa));
    try expectWords(&.{ "tcp/8080", "tcp/9090 loopback" }, try p.images[0].each("listen", gpa));
    try testing.expect(p.images[1].has("memory"));
    try testing.expectEqualStrings("worker", p.links[0].from);
    try expectWords(&.{ "--arch", "x86_64" }, p.rest);
    const f = try renderForm(gpa, p);
    try testing.expect(std.mem.find(
        u8,
        f,
        "net:\n  - listen tcp/8080\n  - listen tcp/9090 loopback\n",
    ) != null);
    try testing.expectEqualStrings(
        "--oci web=ghcr.io/acme/web:1.4 --web.listen 'tcp/8080' --web.listen 'tcp/9090 " ++
            "loopback' " ++
            "--web.env 'LOG_LEVEL=info' --oci worker=ghcr.io/acme/worker@sha256:" ++
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
            " --worker.memory '256' --link worker:web",
        try flags(gpa, p),
    );
}

test "refusals name the flag" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    for ([_]struct { Verb, []const []const u8, []const u8 }{
        .{ .create, &.{ "--with", "caddy" }, "create NAME" },
        .{ .create, &.{ "a", "b", "--with", "caddy" }, "create NAME" },
        .{
            .run,
            &.{ "caddy", "--with", "valkey" },
            "forms are named with --with: howl run --with caddy",
        },
        .{ .run, &.{ "--with", "caddy,caddy" }, "twice" },
        .{ .run, &.{ "--with", "Caddy" }, "not a form's name" },
        .{ .run, &.{ "--package", "a b" }, "a Wolfi package" },
        .{ .run, &.{ "--package", "x=" }, "a Wolfi package" },
        .{ .run, &.{"--package"}, "wants a value" },
        .{ .run, &.{ "--package", "curl", "--package", "curl" }, "twice" },
        .{ .form, &.{ "--with", "caddy,valkey" }, "-o DIR" },
        .{ .form, &.{ "--with", "caddy", "-o", "forms/My Shop" }, "named after its directory" },
        .{ .run, &.{ "--oci", "nginx" }, "NAME=REF" },
        .{ .run, &.{ "--oci", "Web=nginx" }, "a name is" },
        .{ .run, &.{ "--oci", "web=nginx", "--oci", "web=caddy" }, "twice" },
        .{ .run, &.{ "--oci", "web=nginx", "--web.frob", "x" }, "an image's line is one of" },
        .{ .run, &.{ "--oci", "web=nginx", "--web.memory", "1", "--web.memory", "2" }, "twice" },
        .{ .run, &.{ "--oci", "web=nginx", "--link", "web:db" }, "no image db" },
        .{
            .run,
            &.{ "--oci", "web=nginx", "--oci", "db=x", "--link", "web:db" },
            "listens on nothing",
        },
        .{
            .run,
            &.{ "--oci", "a=x", "--oci", "b=y", "--a.listen", "tcp/80", "--b.listen", "tcp/80" },
            "both listen",
        },
    }) |case| {
        var why: Why = .{};
        try testing.expectError(error.Refused, plan(gpa, case[0], case[1], "prod", &why));
        try testing.expect(std.mem.find(u8, why.text, case[2]) != null);
    }
}

test "the files say where they came from" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const p = try plan(
        gpa,
        .run,
        &.{ "--with", "python,valkey", "--package", "py3.13-flask" },
        "prod",
        &why,
    );
    try testing.expectEqualStrings(
        "# Generated by howl from the command line (docs/design/adhoc.md):\n" ++
            "#   howl run --with python,valkey --package py3.13-flask\n" ++
            "# Edit it as any form; forms/README.md says what each key is.\n" ++
            "base: prod\nwith: [python, valkey]\n",
        try renderForm(gpa, p),
    );
    try testing.expectEqualStrings(
        "# Generated by howl; the chain's packages come through base and with.\n" ++
            "contents:\n  packages:\n    - py3.13-flask\n",
        try renderApko(gpa, p),
    );
    try testing.expectEqualStrings(
        "--with python,valkey --package py3.13-flask",
        try flags(gpa, p),
    );
}

test "the chain's weaknesses are restated, each once, the later excuse winning" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const a: forms.Node = .{ .map = &.{.{ .key = "weaknesses", .value = .{ .map = &.{
        .{
            .key = "programs-no-shell",
            .value = .{ .scalar = .{ .raw = "a shell", .text = "a shell" } },
        },
        .{ .key = "network-no-login", .value = .{ .scalar = .{ .raw = "sshd", .text = "sshd" } } },
    } } }} };
    const b: forms.Node = .{ .map = &.{.{ .key = "weaknesses", .value = .{ .map = &.{
        .{
            .key = "programs-no-shell",
            .value = .{ .scalar = .{ .raw = "\"busybox\"", .text = "busybox" } },
        },
    } } }} };
    const mine: forms.Node = .{ .map = &.{} };
    var p: Plan = .{ .verb = .run, .arch = .aarch64, .rest = &.{}, .line = "" };
    try inherit(gpa, &p, &.{
        .{ .name = "sshd", .dir = "forms/sshd", .spec = a },
        .{ .name = "prod-ssh", .dir = "forms/prod-ssh", .spec = b },
        .{ .name = "run", .dir = "build/adhoc/run", .spec = mine },
    });
    try testing.expectEqual(2, p.weaknesses.len);
    try testing.expectEqualStrings("programs-no-shell", p.weaknesses[0].check);
    try testing.expectEqualStrings("\"busybox\"", p.weaknesses[0].excuse);
    try testing.expectEqualStrings("network-no-login", p.weaknesses[1].check);
    try testing.expect(std.mem.find(
        u8,
        try renderForm(gpa, p),
        "weaknesses:\n  programs-no-shell: \"busybox\"\n  network-no-login: sshd\n",
    ) != null);
}

test "form.yaml's lists and maps, by shape" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const p = try plan(gpa, .run, &.{
        "--with",
        "prod-ssh",
        "--sshd.pubkey-auth-options",
        "none",
        "--sshd.max-auth-tries=3",
        "--net",
        "connect bastion tcp/5432",
        "--prune",
        "usr/bin/bash",
        "--net",
        "listen tcp/8443 loopback",
    }, "prod", &why);
    try testing.expectEqual(2, p.maps.len);
    try testing.expectEqualStrings("sshd", p.maps[0].key);
    try testing.expectEqualStrings("pubkey-auth-options", p.maps[0].sub);
    try testing.expectEqualStrings("3", p.maps[1].value);
    try testing.expectEqual(3, p.lists.len);
    const f = try renderForm(gpa, p);
    try testing.expect(std.mem.find(
        u8,
        f,
        "net:\n  - connect bastion tcp/5432\n  - listen tcp/8443 loopback\n",
    ) != null);
    try testing.expect(std.mem.find(u8, f, "prune:\n  - usr/bin/bash\n") != null);
    try testing.expect(std.mem.find(
        u8,
        f,
        "sshd:\n  pubkey-auth-options: \"none\"\n  max-auth-tries: \"3\"\n",
    ) != null);
    try testing.expectEqualStrings(
        "--with prod-ssh --net 'connect bastion tcp/5432' --prune 'usr/bin/bash' --net 'listen " ++
            "tcp/8443 loopback' " ++
            "--sshd.pubkey-auth-options 'none' --sshd.max-auth-tries '3'",
        try flags(gpa, p),
    );
    for ([_][]const []const u8{
        &.{ "--sshd.x", "1", "--sshd.x", "2" },
        &.{ "--net.x", "1" },
        &.{ "--base.x", "1" },
        &.{ "--weaknesses.x", "1" },
        &.{ "--.x", "1" },
        &.{ "--sshd.", "1" },
        &.{ "--net", " " },
        &.{ "--oci", "net=nginx" },
    }) |bad| {
        var w: Why = .{};
        try testing.expectError(error.Refused, plan(gpa, .run, bad, "prod", &w));
    }
}

test "the checklist refuses an image's words unanswered" {
    var why: Why = .{};
    const i: Image = .{ .name = "web", .ref = "x" };
    try testing.expectError(
        error.Refused,
        checklist(i, .{ .exposed = &.{"8080/tcp"}, .volumes = &.{"/var/cache"} }, &why),
    );
    try testing.expect(std.mem.find(u8, why.text, "--web.listen 'tcp/8080 loopback'") != null);
    try testing.expect(std.mem.find(u8, why.text, "--web.write /var/cache") != null);
    try checklist(i, .{}, &why);
    const answered: Image = .{
        .name = "web",
        .ref = "x",
        .lines = &.{.{ .key = "listen", .words = "tcp/8080" }},
    };
    try checklist(answered, .{ .exposed = &.{"8080/tcp"} }, &why);
}

test splitLine {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: Why = .{};
    try expectWords(
        &.{ "/usr/sbin/nginx", "-g", "daemon off;", "-e", "/dev/stderr" },
        try splitLine(
            arena.allocator(),
            "/usr/sbin/nginx  -g \"daemon off;\" -e /dev/stderr",
            "web",
            &why,
        ),
    );
    try testing.expectError(error.Refused, splitLine(arena.allocator(), "/a \"b", "web", &why));
    try testing.expectError(error.Refused, splitLine(arena.allocator(), "/a b\"c\"", "web", &why));
}

test isPackage {
    for ([_][]const u8{
        "py3.13-flask",
        "nginx-mainline",
        "openjdk-21-jre",
        "valkey=9.1.0-r0",
        "a+b",
    }) |ok|
        try testing.expect(isPackage(ok));
    for ([_][]const u8{ "", "-x", "a b", "x=", "a=b=c", "../etc", "a;b" }) |bad|
        try testing.expect(!isPackage(bad));
}
