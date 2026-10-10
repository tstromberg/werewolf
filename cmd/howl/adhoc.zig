//! adhoc turns a command line into a form directory and hands it to build,
//! run, create or pack as FORM, so a one-shot machine and a kept form build
//! the same way. The flags are form.yaml's keys (lib/form.zig keys): `-f
//! FILE` reads a manifest, flags layer over it, and `-n` prints what they
//! make. See README.md, docs/design/adhoc.md and docs/design/manifest.md.
//!
//!     howl run --with caddy                            # one form, as it is
//!     howl run --with caddy,valkey,postgresql          # forms to combine
//!     howl run --with python --packages py3.13-flask   # packages to add
//!     howl run --services.web.image ghcr.io/acme/web:1.4 \
//!              --services.web.listen tcp/8080          # an image to run
//!     howl create shop -f shop.yaml --updates.every 1h # a manifest, and more
//!     howl form --with caddy,valkey -o forms/shop/     # keep the form

const std = @import("std");
const howl = @import("howl.zig");
const oci = @import("oci.zig");
const forms = @import("form");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Why = howl.Why;
const Node = forms.Node;

pub const Verb = enum { build, run, create, form, pack };

const syntax =
    "[-f FILE] [--with FORM,...] [--packages PKG,...] [--KEY LINE] [--KEY.SUB VALUE] " ++
    "[--services.NAME.KEY LINE] [--users.NAME.keys LINE]...; form adds -o DIR, and -n shows " ++
    "the form";

/// service_keys are the keys a service takes from the line: leash's
/// directives (cmd/leash/README.md), `image` and `link` (lib/form.zig
/// render), and `user` and `group`. `root` is an image's, never the line's.
const service_keys = [_][]const u8{
    "image",  "link",   "user",   "group",  "exec",     "dir",    "listen",  "connect",
    "write",  "read",   "run",    "env",    "secret",   "config", "setting", "render",
    "memory", "nofile", "pledge", "before", "requires", "share",  "cpu",     "narrow",
};
/// service_once are the service keys that take one value, so a second is refused.
const service_once = [_][]const u8{
    "image", "user", "group", "exec", "dir", "memory", "nofile", "pledge", "share", "cpu", "render",
};

/// Line is one line of a service's file, as the manifest gives it.
const Line = struct { key: []const u8, words: []const u8 };

/// Image is a service of the manifest that runs an OCI image: its
/// reference, the lines beside it, and the services it links to.
const Image = struct {
    name: []const u8,
    ref: []const u8,
    lines: []const Line = &.{},
    links: []const []const u8 = &.{},
    /// pinned is set while the form is made.
    pinned: []const u8 = "",

    /// each returns the words of the lines with key.
    fn each(i: Image, key: []const u8, gpa: Allocator) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        for (i.lines) |l| if (std.mem.eql(u8, l.key, key)) try out.append(gpa, l.words);
        return out.items;
    }

    fn has(i: Image, key: []const u8) bool {
        for (i.lines) |l| if (std.mem.eql(u8, l.key, key)) return true;
        return false;
    }
};

/// Weakness is a posture check the form fails, and the excuse form.yaml gives.
const Weakness = struct { check: []const u8, excuse: []const u8 };

/// Edit is one flag's change to the manifest: the value set at path, or
/// added to the list there. flag is the flag as typed, for refusals and the
/// `howl form` hint; a flag that takes nothing has none.
const Edit = struct { flag: []const u8, path: []const []const u8, value: ?[]const u8, add: bool };

/// Plan is what the line asked for; the verb's own flags stay in rest.
const Plan = struct {
    verb: Verb,
    base: []const u8 = "prod",
    /// file is -f FILE, the manifest the flags layer over.
    file: ?[]const u8 = null,
    /// edits are the flags, in order; apply lays them over the file.
    edits: []const Edit = &.{},
    /// spec is the manifest the file and the flags make, once applied.
    spec: Node = .{ .map = &.{} },
    with: []const []const u8 = &.{},
    images: []Image = &.{},
    /// ours reports whether -f or any flag of ours was given.
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

    /// items returns the values of the manifest's list key, each unquoted.
    fn items(p: Plan, gpa: Allocator, key: []const u8) ![]const []const u8 {
        return texts(gpa, p.spec.get(key) orelse return &.{});
    }
};

/// take consumes the manifest's flags in args and returns the verb's
/// arguments, with the generated directory as FORM. It returns null when
/// nothing is left to do: for -n, and for the form verb.
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
    const text = if (p.file) |file|
        Dir.cwd().readFileAlloc(io, file, gpa, .limited(256 << 10)) catch |err|
            return why.refuse("-f {s}: {s}", .{ file, @errorName(err) })
    else
        "";
    try apply(gpa, &p, text, why);
    if (try references(gpa, &p, fallback, why)) |ref| {
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
    // no download. A tag is pinned in the manifest as the digest it named.
    for (p.images) |*i| {
        i.pinned = try oci.resolve(io, gpa, i.ref, why);
        if (!std.mem.eql(u8, i.pinned, i.ref))
            howl.say(io, "{s}: {s} is {s}", .{ i.name, i.ref, i.pinned });
        const path = [_][]const u8{ "services", i.name, "image" };
        p.spec = try put(gpa, p.spec, &path, try scalar(gpa, i.pinned), false);
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

/// plan reads the line: -f, the manifest's flags as edits, and the
/// positionals; the verb's own flags go to rest. If none is ours and the
/// verb is not form, it returns early with ours false.
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
    var edits: std.ArrayList(Edit) = .empty;
    var ours = verb == .form;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len == 0 or a[0] != '-') {
            try positional.append(gpa, a);
            continue;
        }
        if (std.mem.eql(u8, a, "-n")) {
            // -n is the verb's own (pack's check) unless a flag of ours
            // appears; that is decided below, once the line is read.
            try rest.append(gpa, a);
            continue;
        }
        var name = a;
        var value: ?[]const u8 = null;
        if (std.mem.startsWith(u8, a, "--")) if (std.mem.findScalar(u8, a, '=')) |eq| {
            name = a[0..eq];
            value = a[eq + 1 ..];
        };
        const is_file = std.mem.eql(u8, name, "-f");
        const is_out = verb == .form and std.mem.eql(u8, name, "-o");
        const key = if (std.mem.startsWith(u8, name, "--")) name[2..] else "";
        const dot = std.mem.findScalar(u8, key, '.');
        const head = key[0 .. dot orelse key.len];
        const sub: ?[]const u8 = if (dot) |d| key[d + 1 ..] else null;
        // --app DIR and --dev are the verbs' flags, whatever form.yaml's keys say.
        const kind: ?forms.Shape = if (std.mem.eql(u8, head, "app") or std.mem.eql(u8, head, "dev"))
            null
        else
            forms.keyShape(head);
        if (!is_file and !is_out and kind == null) {
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
        ours = true;
        // --users.NAME.admin takes no value: the flag is the fact.
        const admin = kind == .maps and std.mem.eql(u8, head, "users") and
            sub != null and std.mem.endsWith(u8, sub.?, ".admin");
        const v = value orelse if (admin) "true" else v: {
            i += 1;
            if (i == args.len or (args[i].len > 0 and args[i][0] == '-'))
                return why.refuse("{s} wants a value", .{a});
            break :v args[i];
        };
        if (is_file) {
            if (p.file != null) return why.refuse("-f given twice", .{});
            p.file = v;
            continue;
        }
        if (is_out) {
            if (p.out != null) return why.refuse("-o given twice", .{});
            p.out = v;
            continue;
        }
        const line = std.mem.trim(u8, v, " \t");
        if (line.len == 0) return why.refuse("{s}: an empty value", .{name});
        switch (kind.?) {
            .file => return why.refuse(
                "{s}: {s} holds structure the line cannot: form -o DIR, then edit DIR/form.yaml",
                .{ name, head },
            ),
            .scalar => return why.refuse(
                "{s}: the base is --with's one form, or the manifest's",
                .{name},
            ),
            .list => {
                if (sub != null) return why.refuse(
                    "{s}: {s} is a list; --{s} LINE adds a line to it",
                    .{ name, head, head },
                );
                // --with and --packages may repeat or join names with commas.
                const joined = std.mem.eql(u8, head, "with") or std.mem.eql(u8, head, "packages");
                const words: []const []const u8 = if (joined) try split(gpa, line) else &.{line};
                if (words.len == 0) return why.refuse(
                    "{s}: a name, or names separated by commas",
                    .{a},
                );
                for (words) |w| try edits.append(gpa, .{
                    .flag = name,
                    .path = try gpa.dupe([]const u8, &.{head}),
                    .value = w,
                    .add = true,
                });
            },
            .map => {
                if (std.mem.eql(u8, head, "weaknesses")) return why.refuse(
                    "{s}: weaknesses are not the line's; form -o DIR, then edit DIR/form.yaml",
                    .{name},
                );
                const s = sub orelse {
                    // A map given one value: updates off alone.
                    if (std.mem.eql(u8, head, "updates") and std.mem.eql(u8, line, "off")) {
                        try edits.append(gpa, .{
                            .flag = name,
                            .path = try gpa.dupe([]const u8, &.{head}),
                            .value = line,
                            .add = false,
                        });
                        continue;
                    }
                    return why.refuse("{s}: {s} is a map: --{s}.SUB VALUE", .{ name, head, head });
                };
                if (s.len == 0 or std.mem.findScalar(u8, s, '.') != null)
                    return why.refuse("{s}: --{s}.SUB VALUE", .{ name, head });
                try edits.append(gpa, .{
                    .flag = name,
                    .path = try gpa.dupe([]const u8, &.{ head, s }),
                    .value = line,
                    .add = false,
                });
            },
            .maps => {
                const users = std.mem.eql(u8, head, "users");
                const shape = if (users)
                    "--users.NAME.keys LINE, or --users.NAME.admin"
                else
                    "--services.NAME.KEY LINE";
                const s = sub orelse return why.refuse("{s}: {s}", .{ name, shape });
                const dot2 = std.mem.findScalar(u8, s, '.') orelse
                    return why.refuse("{s}: {s}", .{ name, shape });
                const who = s[0..dot2];
                const what = s[dot2 + 1 ..];
                if (!forms.isName(who) or who.len > 24) return why.refuse(
                    "{s}: a name is a-z, 0-9 and -, at most 24",
                    .{name},
                );
                if (std.mem.findScalar(u8, what, '.') != null or what.len == 0)
                    return why.refuse("{s}: {s}", .{ name, shape });
                var add = true;
                if (users) {
                    if (std.mem.eql(u8, what, "admin")) {
                        add = false;
                    } else if (!std.mem.eql(u8, what, "keys")) return why.refuse(
                        "{s}: a person has keys and admin, not {s}",
                        .{ name, what },
                    );
                } else {
                    if (!isOneOf(what, &service_keys)) return why.refuse(
                        "{s}: a service's line is one of {s}",
                        .{ name, try std.mem.join(gpa, " ", &service_keys) },
                    );
                    add = !isOneOf(what, &service_once);
                }
                try edits.append(gpa, .{
                    .flag = if (admin) a else name,
                    .path = try gpa.dupe([]const u8, &.{ head, who, what }),
                    .value = if (admin) null else line,
                    .add = add,
                });
            },
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
    p.edits = edits.items;
    p.rest = rest.items;
    if (!ours) return p;
    p.ours = true;
    // A flag of ours was given, so -n means show the form and stop.
    var kept: std.ArrayList([]const u8) = .empty;
    for (rest.items) |a| if (std.mem.eql(u8, a, "-n")) {
        p.show_only = true;
    } else try kept.append(gpa, a);
    p.rest = kept.items;
    if (verb == .form and
        p.out == null) return why.refuse("form writes to -o DIR: form {s}", .{syntax});
    if (p.out) |o| {
        const named = std.fs.path.basename(std.mem.trimEnd(u8, o, "/"));
        if (!forms.isName(named)) return why.refuse(
            "-o {s}: a form is named after its directory, of a-z, 0-9 and -",
            .{o},
        );
    }
    return p;
}

/// apply lays the edits over text, the -f manifest (empty when none), and
/// checks what they make: the forms and packages named, the services'
/// images and links, and that each person has keys. The build checks the
/// rest when the chain is read.
fn apply(gpa: Allocator, p: *Plan, text: []const u8, why: *Why) !void {
    if (p.file) |file| {
        var diag: forms.Diagnostic = .{};
        p.spec = forms.parse(gpa, text, &diag) catch |err| switch (err) {
            error.Syntax => return why.refuse("{s}:{d}: {s}", .{ file, diag.line, diag.why }),
            error.OutOfMemory => return error.OutOfMemory,
        };
        for (p.spec.map) |e| if (forms.keyShape(e.key) == null)
            return why.refuse("{s}: no key {s} (forms/README.md lists them)", .{ file, e.key });
        if (p.spec.get("base")) |b| if (b == .scalar) {
            p.base = b.scalar.text;
        };
    }
    for (p.edits, 0..) |e, k| {
        // A value set twice on the line is a mistake; set over the file's,
        // it is the point. --updates off and --updates.every are one or the other.
        if (!e.add) for (p.edits[0..k]) |seen| if (!seen.add and samePath(seen.path, e.path))
            return why.refuse("{s}: twice", .{e.flag});
        if (std.mem.eql(u8, e.path[0], "updates")) for (p.edits[0..k]) |seen|
            if (std.mem.eql(u8, seen.path[0], "updates") and seen.path.len != e.path.len)
                return why.refuse("{s} and {s}: one or the other", .{ seen.flag, e.flag });
        p.spec = try put(gpa, p.spec, e.path, try scalar(gpa, e.value orelse "true"), e.add);
    }
    p.with = try p.items(gpa, "with");
    for (p.with, 0..) |m, k| {
        // Accept a name in forms/ or a kept form's directory, which has a slash.
        if (!forms.isName(m) and std.mem.findScalar(u8, m, '/') == null)
            return why.refuse("--with {s}: not a form's name", .{m});
        for (p.with[0..k]) |seen| if (std.mem.eql(u8, m, seen))
            return why.refuse("--with {s}: twice", .{m});
    }
    const packages = try p.items(gpa, "packages");
    for (packages, 0..) |pkg, k| {
        if (!isPackage(pkg)) return why.refuse(
            "--packages {s}: a Wolfi package is [A-Za-z0-9][A-Za-z0-9._+-]*, pinned as " ++
                "NAME=VERSION",
            .{pkg},
        );
        for (packages[0..k]) |seen| if (std.mem.eql(u8, pkg, seen))
            return why.refuse("--packages {s}: twice", .{pkg});
    }
    if (p.spec.get("users")) |users| if (users == .map) for (users.map) |u| {
        const keys = if (u.value == .map) u.value.get("keys") else null;
        if (keys == null or (try texts(gpa, keys.?)).len == 0) return why.refuse(
            "users.{s} has no keys; add --users.{s}.keys LINE",
            .{ u.key, u.key },
        );
    };
    // Each service with an image is one to bake; a link is an image's,
    // to a service of the manifest that listens on loopback.
    var images: std.ArrayList(Image) = .empty;
    const services = p.spec.get("services") orelse Node{ .map = &.{} };
    if (services != .map) return why.refuse("services maps each service's name to its lines", .{});
    for (services.map) |s| {
        if (s.value != .map) return why.refuse("services.{s}: a map of lines", .{s.key});
        const ref = s.value.get("image");
        if (ref == null and s.value.get("link") != null) return why.refuse(
            "services.{s}.link: link is an image's; a service of your own says connect",
            .{s.key},
        );
        if (ref) |r| try images.append(gpa, .{
            .name = s.key,
            .ref = if (r == .scalar) r.scalar.text else return why.refuse(
                "services.{s}.image: one reference, REPO[:TAG][@sha256:...]",
                .{s.key},
            ),
            .lines = try lines(gpa, s.value),
            .links = try texts(gpa, s.value.get("link") orelse Node{ .list = &.{} }),
        });
    }
    p.images = images.items;
    for (p.images) |i| {
        if (!oci.isRef(i.ref)) return why.refuse(
            "services.{s}.image {s}: not an image reference",
            .{ i.name, i.ref },
        );
        for (i.links) |to| {
            const target = services.get(to) orelse return why.refuse(
                "services.{s}.link {s}: no service {s}",
                .{ i.name, to, to },
            );
            if (std.mem.eql(u8, to, i.name))
                return why.refuse("services.{s}.link {s}: to itself", .{ i.name, to });
            if ((try ports(gpa, target)).len == 0) return why.refuse(
                "services.{s}.link {s}: {s} listens on nothing; say --services.{s}.listen " ++
                    "'tcp/PORT loopback'",
                .{ i.name, to, to, to },
            );
        }
    }
    // Refuse two services listening on one port.
    for (services.map, 0..) |a, k| for (try ports(gpa, a.value)) |pa|
        for (services.map[0..k]) |b| for (try ports(gpa, b.value)) |pb|
            if (std.mem.eql(u8, pa, pb)) return why.refuse(
                "{s} and {s} both listen on {s}: one machine serves a port once",
                .{ b.key, a.key, pa },
            );
}

/// references returns the form to use unchanged when at most one --with is
/// given and nothing is added. Otherwise it settles the manifest's base
/// (the single --with, the file's, or fallback) and returns null, meaning
/// a form must be generated.
fn references(gpa: Allocator, p: *Plan, fallback: []const u8, why: *Why) !?[]const u8 {
    const content = p.file != null or for (p.spec.map) |e| {
        if (!std.mem.eql(u8, e.key, "with")) break true;
    } else false;
    if (p.with.len <= 1 and !content and p.verb != .form)
        return if (p.with.len == 1) p.with[0] else fallback;
    for (p.with) |m| if (std.mem.findScalar(u8, m, '/') != null) return why.refuse(
        "--with {s}: a kept form's directory runs as it is; to build on it, name it or edit it",
        .{m},
    );
    if (p.spec.get("base") == null) {
        if (p.file == null and p.with.len == 1) {
            p.base = p.with[0];
            p.spec = try without(gpa, p.spec, "with");
            p.with = &.{};
        } else p.base = fallback;
        p.spec = try putFirst(gpa, p.spec, "base", try scalar(gpa, p.base));
    }
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
            "    --services.{s}.listen 'tcp/{s} loopback'   for a linked image alone\n",
            .{ i.name, port },
        ) catch {};
        w.print(
            "    --services.{s}.listen tcp/{s}              public\n",
            .{ i.name, port },
        ) catch {};
    }
    for (c.volumes) |v| w.print("    --services.{s}.write {s}\n", .{ i.name, v }) catch {};
    return why.refuse("{s}", .{std.mem.trimEnd(u8, w.buffered(), "\n")});
}

/// renderForm writes the manifest as form.yaml: where it came from, then
/// the keys as they stand.
fn renderForm(gpa: Allocator, p: Plan) ![]const u8 {
    var f: Io.Writer.Allocating = .init(gpa);
    const w = &f.writer;
    try w.print(
        "# Generated by howl from the command line (docs/design/adhoc.md):\n#   howl {t} {s}\n" ++
            "# Edit it as any form; forms/README.md says what each key is.\n",
        .{ p.verb, p.line },
    );
    try forms.write(w, p.spec);
    return f.written();
}

/// inherit restates the chain's weaknesses in the manifest, each once, the
/// later form's excuse winning and the manifest's own over all: a form's
/// weaknesses are not inherited.
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
    const own = p.spec.get("weaknesses") orelse Node{ .map = &.{} };
    for (out.items) |x| if (own.get(x.check) == null) {
        p.spec = try put(gpa, p.spec, &.{ "weaknesses", x.check }, .{ .scalar = .{
            .raw = x.excuse,
            .text = x.excuse,
        } }, false);
    };
}

/// bake pulls the image into rootfs/oci/NAME, prepares its bind points, and
/// writes its record, from which compose renders the service.
fn bake(
    io: Io,
    gpa: Allocator,
    p: Plan,
    i: Image,
    c: oci.Config,
    dir: []const u8,
    why: *Why,
) !void {
    const writes = try i.each("write", gpa);
    for (writes) |path| if (path.len == 0 or path[0] != '/' or
        std.mem.findScalar(u8, path, ' ') != null)
        return why.refuse("services.{s}.write {s}: one absolute path a line", .{ i.name, path });
    var override: ?[]const []const u8 = null;
    const execs = try i.each("exec", gpa);
    if (execs.len > 0) override = try splitLine(gpa, execs[0], i.name, why);
    try oci.bakeTree(io, gpa, .{
        .pinned = i.pinned,
        .arch = @tagName(p.arch.?),
        .config = c,
        .dir = try gpa.print("{s}/rootfs", .{dir}),
        .name = i.name,
        .writes = writes,
        .override = override,
    }, why);
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
                return why.refuse("services.{s}.exec: a quote is not closed", .{name});
            try out.append(gpa, line[at + 1 .. end]);
            at = end + 1;
        } else {
            var end = at;
            while (end < line.len and line[end] != ' ' and line[end] != '\t') : (end += 1) {
                if (line[end] == '"') return why.refuse(
                    "services.{s}.exec: a quote inside a word",
                    .{name},
                );
            }
            try out.append(gpa, line[at..end]);
            at = end;
        }
    }
    return out.items;
}

// --- the manifest tree --------------------------------------------------------

/// scalar returns text as a node form.yaml's parser reads back unchanged:
/// as it is, or double-quoted where a plain value would be misread.
fn scalar(gpa: Allocator, text: []const u8) !Node {
    return .{ .scalar = .{ .raw = try yamlScalar(gpa, text), .text = text } };
}

/// yamlScalar returns s as form.yaml's parser reads it back unchanged: as
/// it is, or double-quoted where a plain value would be misread (a YAML
/// indicator first, `: ` within, a colon last, or a quote first).
fn yamlScalar(gpa: Allocator, s: []const u8) ![]const u8 {
    const plain = s.len > 0 and std.mem.findScalar(u8, "[]{}&*!|>%@`,\"'#", s[0]) == null and
        !((s[0] == '-' or s[0] == '?' or s[0] == ':') and (s.len == 1 or s[1] == ' ')) and
        std.mem.find(u8, s, ": ") == null and s[s.len - 1] != ':';
    if (plain) return s;
    var out: std.ArrayList(u8) = .empty;
    try out.append(gpa, '"');
    for (s) |c| {
        if (c == '"' or c == '\\') try out.append(gpa, '\\');
        try out.append(gpa, c);
    }
    try out.append(gpa, '"');
    return out.items;
}

/// put returns node with value at path, the maps on the way made as
/// needed; with add, value joins the list there instead, a value there
/// becoming its first item. A map's keys keep their order.
fn put(gpa: Allocator, node: Node, path: []const []const u8, value: Node, add: bool) !Node {
    if (path.len == 0) {
        if (!add) return value;
        const had: []const Node = switch (node) {
            .list => |l| l,
            .scalar => &.{node},
            .map => &.{},
        };
        return .{ .list = try std.mem.concat(gpa, Node, &.{ had, &.{value} }) };
    }
    const map: []const forms.Entry = if (node == .map) node.map else &.{};
    const out = try gpa.alloc(forms.Entry, map.len + 1);
    @memcpy(out[0..map.len], map);
    for (out[0..map.len]) |*e| if (std.mem.eql(u8, e.key, path[0])) {
        e.value = try put(gpa, e.value, path[1..], value, add);
        return .{ .map = out[0..map.len] };
    };
    out[map.len] = .{
        .key = path[0],
        .value = try put(gpa, .{ .map = &.{} }, path[1..], value, add),
    };
    return .{ .map = out };
}

/// putFirst returns the map with key: value as its first entry.
fn putFirst(gpa: Allocator, node: Node, key: []const u8, value: Node) !Node {
    return .{ .map = try std.mem.concat(
        gpa,
        forms.Entry,
        &.{ &.{.{ .key = key, .value = value }}, node.map },
    ) };
}

/// without returns the map less key.
fn without(gpa: Allocator, node: Node, key: []const u8) !Node {
    var out: std.ArrayList(forms.Entry) = .empty;
    for (node.map) |e| if (!std.mem.eql(u8, e.key, key)) try out.append(gpa, e);
    return .{ .map = out.items };
}

fn samePath(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

/// texts returns the unquoted values of node: a list's items, or the one.
fn texts(gpa: Allocator, node: Node) ![]const []const u8 {
    const values: []const Node = switch (node) {
        .list => |l| l,
        .scalar => &.{node},
        .map => &.{},
    };
    var out: std.ArrayList([]const u8) = .empty;
    for (values) |v| if (v == .scalar) try out.append(gpa, v.scalar.text);
    return out.items;
}

/// lines returns a service's lines beside its image and links.
fn lines(gpa: Allocator, spec: Node) ![]const Line {
    var out: std.ArrayList(Line) = .empty;
    for (spec.map) |d| {
        if (std.mem.eql(u8, d.key, "image") or std.mem.eql(u8, d.key, "link")) continue;
        for (try texts(gpa, d.value)) |words|
            try out.append(gpa, .{ .key = d.key, .words = words });
    }
    return out.items;
}

/// ports returns the tcp/PORT words of a service's listen lines.
fn ports(gpa: Allocator, spec: Node) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (try texts(gpa, spec.get("listen") orelse return &.{})) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t");
        while (words.next()) |w| if (std.mem.startsWith(u8, w, "tcp/")) try out.append(gpa, w);
    }
    return out.items;
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

/// flags returns the flags that make the same form, for the `howl form` hint:
/// -f and the line's, an image's tag as the digest it was pinned to.
fn flags(gpa: Allocator, p: Plan) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    const w = &out.writer;
    if (p.file) |f| try w.print("-f {s}", .{f});
    // --with and --packages take their names joined, as they were typed.
    for ([_][]const u8{ "with", "packages" }) |key| {
        var names: std.ArrayList([]const u8) = .empty;
        for (p.edits) |e| if (e.path.len == 1 and std.mem.eql(u8, e.path[0], key))
            try names.append(gpa, e.value.?);
        if (names.items.len > 0)
            try w.print(" --{s} {s}", .{ key, try std.mem.join(gpa, ",", names.items) });
    }
    for (p.edits) |e| {
        if (e.path.len == 1 and (std.mem.eql(u8, e.path[0], "with") or
            std.mem.eql(u8, e.path[0], "packages"))) continue;
        const v = e.value orelse {
            try w.print(" {s}", .{e.flag});
            continue;
        };
        const pinned = if (e.path.len == 3 and std.mem.eql(u8, e.path[2], "image"))
            (if (p.image(e.path[1])) |i| (if (i.pinned.len > 0) i.pinned else v) else v)
        else
            v;
        try w.print(" {s} {s}", .{ e.flag, try quoted(gpa, pinned) });
    }
    return std.mem.trimStart(u8, out.written(), " ");
}

/// quoted returns v as a shell word: as it is when plain, else in single quotes.
fn quoted(gpa: Allocator, v: []const u8) ![]const u8 {
    for (v) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._+-=/:@,", c) == null)
        return gpa.print("'{s}'", .{v});
    return v;
}

const Checked = struct { services: usize, memory: u64 };

/// check reads the chain as the build would, and refuses what the build refuses.
/// It also refuses two forms listening on one port, which the build allows but
/// the machine would fail at boot. It returns the service count and memory total.
fn check(io: Io, gpa: Allocator, dir: []const u8, why: *Why) !Checked {
    const c = try howl.chain(io, gpa, dir, why);
    // Include loopback ports: two services binding one port collide either way.
    const Port = struct { port: u16, form: []const u8 };
    var ports_: std.ArrayList(Port) = .empty;
    var failure: forms.Failure = .{};
    for (c) |f| for (forms.netLines(gpa, &.{f}, &failure) catch |err| switch (err) {
        error.Form => return why.refuse("{s}", .{failure.text}),
        else => return err,
    }) |line| {
        var bad: []const u8 = "";
        const l = (forms.listen(gpa, line, &bad) catch |err| switch (err) {
            error.Invalid => return why.refuse("{s}/form.yaml: {s}", .{ f.dir, bad }),
            else => return err,
        }) orelse continue;
        for (l.ports) |port| {
            for (ports_.items) |have| if (have.port == port and !std.mem.eql(u8, have.form, f.name))
                return why.refuse(
                    "{s} and {s} both listen on tcp/{d}: one machine serves a port once",
                    .{ have.form, f.name, port },
                );
            try ports_.append(gpa, .{ .port = port, .form = f.name });
        }
    };
    var memory: u64 = 0;
    const svcs = forms.services(io, gpa, Dir.cwd(), c, &failure) catch |err| switch (err) {
        error.Form => return why.refuse("{s}", .{failure.text}),
        error.OutOfMemory => return error.OutOfMemory,
    };
    for (svcs) |s| {
        var it = std.mem.splitScalar(u8, s.text, '\n');
        while (it.next()) |line| {
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

fn isOneOf(s: []const u8, set: []const []const u8) bool {
    for (set) |k| if (std.mem.eql(u8, s, k)) return true;
    return false;
}

fn indent(w: *Io.Writer, text: []const u8) !void {
    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, text, "\n"), '\n');
    while (it.next()) |line| try w.print("    {s}\n", .{line});
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

fn expectWords(want: []const []const u8, got: []const []const u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expectEqualStrings(w, g);
}

/// body is the form rendered, less the comment it opens with.
fn body(gpa: Allocator, p: Plan) ![]const u8 {
    const f = try renderForm(gpa, p);
    return f[std.mem.find(u8, f, "base:").?..];
}

/// planned is plan and apply, with text as -f's file.
fn planned(
    gpa: Allocator,
    verb: Verb,
    args: []const []const u8,
    text: []const u8,
    why: *Why,
) !Plan {
    var p = try plan(gpa, verb, args, if (verb == .run) "playground" else "prod", why);
    try apply(gpa, &p, text, why);
    return p;
}

test "a line with none of our flags is left alone" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const p = try planned(gpa, .create, &.{ "edge", "--domain", "a.example", "-n" }, "", &why);
    try testing.expect(!p.ours);
    try testing.expectEqual(1, p.positionals);
    const bare = try planned(gpa, .run, &.{ "--on", "lima", "--dev", "--app", "./x" }, "", &why);
    try testing.expect(!bare.ours);
    try expectWords(&.{ "--on", "lima", "--dev", "--app", "./x" }, bare.rest);
    const with = try planned(gpa, .run, &.{ "--with", "valkey" }, "", &why);
    try testing.expect(with.ours);
    try testing.expectEqualStrings("playground", with.base);
}

test "positionals: create names the machine; run and build name a base" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    var c = try planned(gpa, .create, &.{ "shop", "--with", "caddy,valkey" }, "", &why);
    try testing.expectEqualStrings("shop", c.name.?);
    try testing.expectEqualStrings("build/adhoc/shop", try c.dir(gpa));
    try testing.expectEqual(null, try references(gpa, &c, "prod", &why));
    try testing.expectEqualStrings("prod", c.base);
    try expectWords(&.{ "caddy", "valkey" }, c.with);
    var one = try planned(gpa, .create, &.{ "shop", "--with", "caddy" }, "", &why);
    try testing.expectEqualStrings("caddy", (try references(gpa, &one, "prod", &why)).?);
    var one_more = try planned(
        gpa,
        .create,
        &.{ "shop", "--with", "caddy", "--packages", "curl" },
        "",
        &why,
    );
    try testing.expectEqual(null, try references(gpa, &one_more, "prod", &why));
    try testing.expectEqualStrings("caddy", one_more.base);
    try testing.expectEqual(0, one_more.with.len);
    try testing.expectEqualStrings("base: caddy\npackages:\n  - curl\n", try body(gpa, one_more));
    var none = try planned(gpa, .run, &.{"--dev"}, "", &why);
    const fallback = try references(gpa, &none, "playground", &why);
    try testing.expectEqualStrings("playground", fallback.?);
    var kept = try planned(gpa, .run, &.{ "--with", "forms/shop/" }, "", &why);
    try testing.expectEqualStrings("forms/shop/", (try references(gpa, &kept, "prod", &why)).?);
    var kept_more = try planned(
        gpa,
        .run,
        &.{ "--with", "forms/shop/", "--packages", "curl" },
        "",
        &why,
    );
    try testing.expectError(error.Refused, references(gpa, &kept_more, "prod", &why));
    var formed = try planned(gpa, .form, &.{ "--with", "caddy", "-o", "forms/x" }, "", &why);
    try testing.expectEqual(null, try references(gpa, &formed, "prod", &why));
    try testing.expectEqualStrings("caddy", formed.base);
    const c2 = try planned(
        gpa,
        .create,
        &.{ "--dev", "shop", "--with=caddy", "--with=valkey", "--domain", "x", "--on", "gcp" },
        "",
        &why,
    );
    try testing.expectEqualStrings("shop", c2.name.?);
    try expectWords(&.{ "caddy", "valkey" }, c2.with);
    try expectWords(&.{ "--dev", "--domain", "x", "--on", "gcp" }, c2.rest);
    const r = try planned(
        gpa,
        .run,
        &.{ "--with", "python", "--packages", "py3.13-flask, py3.13-psycopg", "-n" },
        "",
        &why,
    );
    try expectWords(&.{"python"}, r.with);
    try expectWords(&.{ "py3.13-flask", "py3.13-psycopg" }, try r.items(gpa, "packages"));
    try testing.expect(r.show_only);
    try testing.expectEqual(0, r.rest.len);
    try testing.expectEqualStrings("build/adhoc/run", try r.dir(gpa));
    const f = try planned(
        gpa,
        .form,
        &.{ "--with", "caddy,valkey", "-o", "forms/shop/" },
        "",
        &why,
    );
    try testing.expectEqualStrings("forms/shop", try f.dir(gpa));
}

test "images: their lines, links and ports, and the hint pinned" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var p = try planned(gpa, .run, &.{
        "--services.web.image",     "ghcr.io/acme/web:1.4",
        "--services.worker.image",  "ghcr.io/acme/worker@" ++ digest,
        "--services.web.listen",    "tcp/8080",
        "--services.web.listen",    "tcp/9090 loopback",
        "--services.web.env",       "LOG_LEVEL=info",
        "--services.worker.memory", "256",
        "--services.worker.link",   "web",
        "--arch",                   "x86_64",
    }, "", &why);
    try testing.expectEqual(2, p.images.len);
    try testing.expectEqual(howl.Arch.x86_64, p.arch.?);
    const web = p.spec.get("services").?.get("web").?;
    try expectWords(&.{ "tcp/8080", "tcp/9090" }, try ports(gpa, web));
    try expectWords(&.{ "tcp/8080", "tcp/9090 loopback" }, try p.images[0].each("listen", gpa));
    try testing.expect(p.images[1].has("memory"));
    try expectWords(&.{"web"}, p.images[1].links);
    try expectWords(&.{ "--arch", "x86_64" }, p.rest);
    try testing.expectEqual(null, try references(gpa, &p, "playground", &why));
    p.images[0].pinned = "ghcr.io/acme/web@" ++ digest;
    const f = try renderForm(gpa, p);
    try testing.expect(std.mem.find(
        u8,
        f,
        "base: playground\nservices:\n  web:\n    image: ghcr.io/acme/web:1.4\n    listen:\n" ++
            "      - tcp/8080\n      - tcp/9090 loopback\n    env:\n      - LOG_LEVEL=info\n" ++
            "  worker:\n    image: ghcr.io/acme/worker@sha256:",
    ) != null);
    try testing.expect(std.mem.find(u8, f, "    memory: 256\n    link:\n      - web\n") != null);
    try testing.expect(std.mem.find(u8, f, "net:") == null);
    try testing.expectEqualStrings(
        "--services.web.image ghcr.io/acme/web@" ++ digest ++
            " --services.worker.image ghcr.io/acme/worker@" ++ digest ++
            " --services.web.listen tcp/8080 --services.web.listen 'tcp/9090 loopback' " ++
            "--services.web.env LOG_LEVEL=info --services.worker.memory 256 " ++
            "--services.worker.link web",
        try flags(gpa, p),
    );
}

test "refusals name the flag" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const img = "--services.web.image";
    const mem_ = "--services.web.memory";
    const link = "--services.web.link";
    const listen = "--services.web.listen";
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
        .{ .run, &.{ "--packages", "a b" }, "a Wolfi package" },
        .{ .run, &.{ "--packages", "x=" }, "a Wolfi package" },
        .{ .run, &.{"--packages"}, "wants a value" },
        .{ .run, &.{ "--packages", "-n" }, "wants a value" },
        .{ .run, &.{ "--packages", "curl", "--packages", "curl" }, "twice" },
        .{ .form, &.{ "--with", "caddy,valkey" }, "-o DIR" },
        .{ .form, &.{ "--with", "caddy", "-o", "forms/My Shop" }, "named after its directory" },
        .{ .run, &.{ "--services.web", "nginx" }, "--services.NAME.KEY LINE" },
        .{ .run, &.{ "--services.Web.image", "nginx" }, "a name is" },
        .{ .run, &.{ img, "nginx", img, "caddy" }, "twice" },
        .{ .run, &.{ img, "nginx", "--services.web.frob", "x" }, "a service's line is one of" },
        .{ .run, &.{ img, "nginx", "--services.web.root", "/x" }, "a service's line is one of" },
        .{ .run, &.{ img, "nginx", mem_, "1", mem_, "2" }, "twice" },
        .{ .run, &.{ img, "nginx", "--services.web.link", "db" }, "no service db" },
        .{ .run, &.{ img, "nginx", "--services.web.link", "web" }, "to itself" },
        .{ .run, &.{ img, "nginx", "--services.db.image", "x", link, "db" }, "listens on nothing" },
        .{ .run, &.{ "--services.web.exec", "/x", link, "db" }, "link is an image's" },
        .{ .run, &.{ img, "not an image", listen, "tcp/80" }, "not an image reference" },
        .{
            .run,
            &.{
                "--services.a.image",  "x",      "--services.b.image",  "y",
                "--services.a.listen", "tcp/80", "--services.b.listen", "tcp/80",
            },
            "both listen",
        },
        .{ .run, &.{ "--accounts.x", "1" }, "holds structure" },
        .{ .run, &.{ "--bastion", "1" }, "holds structure" },
        .{ .run, &.{ "--base", "x" }, "the base is" },
        .{ .run, &.{ "--weaknesses.x", "1" }, "not the line's" },
        .{ .run, &.{ "--net.x", "1" }, "is a list" },
        .{ .run, &.{ "--sshd", "1" }, "is a map" },
        .{ .run, &.{ "--sshd.", "1" }, "--sshd.SUB VALUE" },
        .{ .run, &.{ "--sshd.a.b", "1" }, "--sshd.SUB VALUE" },
        .{ .run, &.{ "--sshd.x", "1", "--sshd.x", "2" }, "twice" },
        .{ .run, &.{ "--net", " " }, "an empty value" },
    }) |case| {
        var why: Why = .{};
        try testing.expectError(error.Refused, planned(gpa, case[0], case[1], "", &why));
        try testing.expect(std.mem.find(u8, why.text, case[2]) != null);
    }
}

test "the file says where it came from" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    var p = try planned(
        gpa,
        .run,
        &.{ "--with", "python,valkey", "--packages", "py3.13-flask" },
        "",
        &why,
    );
    try testing.expectEqual(null, try references(gpa, &p, "playground", &why));
    try testing.expectEqualStrings(
        "# Generated by howl from the command line (docs/design/adhoc.md):\n" ++
            "#   howl run --with python,valkey --packages py3.13-flask\n" ++
            "# Edit it as any form; forms/README.md says what each key is.\n" ++
            "base: playground\nwith:\n  - python\n  - valkey\npackages:\n  - py3.13-flask\n",
        try renderForm(gpa, p),
    );
    try testing.expectEqualStrings(
        "--with python,valkey --packages py3.13-flask",
        try flags(gpa, p),
    );
}

test "people: --users.NAME.keys repeats, --users.NAME.admin takes no value" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const k1 = "sk-ssh-ed25519@openssh.com AAAA1 tom@yubikey";
    const k2 = "sk-ssh-ed25519@openssh.com AAAA2 tom@spare";
    const p = try planned(gpa, .run, &.{
        "--with",            "sshd",             "--users.tom.keys", k1,
        "--users.tom.admin", "--users.tom.keys", k2,                 "--users.ann.keys",
        k1,
    }, "", &why);
    const f = try renderForm(gpa, p);
    try testing.expect(std.mem.find(u8, f, "users:\n  tom:\n    keys:\n      - " ++ k1 ++
        "\n      - " ++
        k2 ++ "\n    admin: true\n  ann:\n    keys:\n      - " ++ k1 ++ "\n") != null);
    try testing.expectEqualStrings(
        "--with sshd --users.tom.keys '" ++ k1 ++ "' --users.tom.admin --users.tom.keys '" ++ k2 ++
            "' --users.ann.keys '" ++ k1 ++ "'",
        try flags(gpa, p),
    );
    for ([_][]const []const u8{
        &.{"--users.tom.admin"}, // no keys
        &.{ "--users.tom.shell", "/bin/sh" },
        &.{ "--users.Tom.keys", k1 },
        &.{ "--users.tom", k1 },
    }) |args| try testing.expectError(error.Refused, planned(gpa, .run, args, "", &why));
}

test "updates: --updates off alone, or --updates.every, once" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const p = try planned(gpa, .run, &.{ "--with", "python", "--updates", "off" }, "", &why);
    try testing.expect(std.mem.find(u8, try renderForm(gpa, p), "\nupdates: off\n") != null);
    try testing.expectEqualStrings("--with python --updates off", try flags(gpa, p));
    const e = try planned(gpa, .run, &.{ "--with", "python", "--updates.every", "1h" }, "", &why);
    const every = try renderForm(gpa, e);
    try testing.expect(std.mem.find(u8, every, "\nupdates:\n  every: 1h\n") != null);
    for ([_][]const []const u8{
        &.{ "--updates", "off", "--updates", "off" },
        &.{ "--updates", "off", "--updates.every", "1h" },
        &.{ "--updates.every", "1h", "--updates", "off" },
        &.{ "--updates", "on" },
        &.{"--updates"},
    }) |args| try testing.expectError(error.Refused, planned(gpa, .run, args, "", &why));
}

test "-f: the manifest as written, the flags layered over it, the hint -f" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const text =
        \\# shop.yaml
        \\with: [sshd]
        \\updates:
        \\  every: 2h
        \\sshd:
        \\  max-auth-tries: 4
        \\services:
        \\  web:
        \\    exec: /usr/bin/web
        \\    user: web
        \\    listen: tcp/8080
        \\
    ;
    var p = try planned(gpa, .create, &.{
        "shop",              "-f",
        "shop.yaml",         "--services.web.listen",
        "tcp/9090 loopback", "--updates",
        "off",               "--sshd.max-auth-tries",
        "3",                 "--with",
        "valkey",            "--services.web.memory",
        "64",
    }, text, &why);
    try testing.expect(p.ours);
    try expectWords(&.{ "sshd", "valkey" }, p.with);
    try testing.expectEqual(null, try references(gpa, &p, "prod", &why));
    try testing.expectEqualStrings(
        "base: prod\nwith:\n  - sshd\n  - valkey\nupdates: off\nsshd:\n  max-auth-tries: 3\n" ++
            "services:\n  web:\n    exec: /usr/bin/web\n    user: web\n    listen:\n" ++
            "      - tcp/8080\n      - tcp/9090 loopback\n    memory: 64\n",
        try body(gpa, p),
    );
    try testing.expectEqualStrings(
        "-f shop.yaml --with valkey --services.web.listen 'tcp/9090 loopback' --updates off " ++
            "--sshd.max-auth-tries 3 --services.web.memory 64",
        try flags(gpa, p),
    );
    // A file's base stands; with one, a single --with is not the base.
    const file = [_][]const u8{ "-f", "x.yaml" };
    var based = try planned(gpa, .run, &(file ++ .{ "--with", "caddy" }), "base: python\n", &why);
    try testing.expectEqual(null, try references(gpa, &based, "playground", &why));
    try testing.expectEqualStrings("python", based.base);
    try expectWords(&.{"caddy"}, based.with);
    // A file alone is generated, never run as it is; a bad one is refused by name.
    var alone = try planned(gpa, .run, &file, "with: [caddy]\n", &why);
    try testing.expectEqual(null, try references(gpa, &alone, "playground", &why));
    try testing.expectError(error.Refused, planned(gpa, .run, &file, "frob: 1\n", &why));
    try testing.expect(std.mem.find(u8, why.text, "x.yaml: no key frob") != null);
    try testing.expectError(error.Refused, planned(gpa, .run, &file, "- a\n", &why));
    try testing.expect(std.mem.startsWith(u8, why.text, "x.yaml:"));
    try testing.expectError(error.Refused, planned(gpa, .run, &(file ++ file), "", &why));
}

test "the chain's weaknesses are restated, each once, the later excuse winning, its own over all" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const a: Node = .{ .map = &.{.{ .key = "weaknesses", .value = .{ .map = &.{
        .{
            .key = "programs-no-shell",
            .value = .{ .scalar = .{ .raw = "a shell", .text = "a shell" } },
        },
        .{ .key = "network-no-login", .value = .{ .scalar = .{ .raw = "sshd", .text = "sshd" } } },
    } } }} };
    const b: Node = .{ .map = &.{.{ .key = "weaknesses", .value = .{ .map = &.{
        .{
            .key = "programs-no-shell",
            .value = .{ .scalar = .{ .raw = "\"busybox\"", .text = "busybox" } },
        },
    } } }} };
    const mine: Node = .{ .map = &.{.{ .key = "weaknesses", .value = .{ .map = &.{
        .{ .key = "network-no-login", .value = .{ .scalar = .{ .raw = "mine", .text = "mine" } } },
    } } }} };
    var p: Plan = .{ .verb = .run, .arch = .aarch64, .rest = &.{}, .line = "", .spec = mine };
    try inherit(gpa, &p, &.{
        .{ .name = "sshd", .dir = "forms/sshd", .spec = a },
        .{ .name = "prod-ssh", .dir = "forms/prod-ssh", .spec = b },
        .{ .name = "run", .dir = "build/adhoc/run", .spec = mine },
    });
    try testing.expect(std.mem.find(
        u8,
        try renderForm(gpa, p),
        "weaknesses:\n  network-no-login: mine\n  programs-no-shell: \"busybox\"\n",
    ) != null);
}

test "form.yaml's lists and maps, by shape" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const p = try planned(gpa, .run, &.{
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
        "--check.memory",
        "512",
    }, "", &why);
    const f = try renderForm(gpa, p);
    try testing.expect(std.mem.find(
        u8,
        f,
        "sshd:\n  pubkey-auth-options: none\n  max-auth-tries: 3\nnet:\n  - connect bastion " ++
            "tcp/5432\n  - listen tcp/8443 loopback\nprune:\n  - usr/bin/bash\ncheck:\n" ++
            "  memory: 512\n",
    ) != null);
    try testing.expectEqualStrings(
        "--with prod-ssh --sshd.pubkey-auth-options none --sshd.max-auth-tries 3 --net " ++
            "'connect bastion tcp/5432' --prune usr/bin/bash --net 'listen tcp/8443 loopback' " ++
            "--check.memory 512",
        try flags(gpa, p),
    );
}

test "put: a value set, a line added, a value there becoming the list's first" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var n: Node = .{ .map = &.{} };
    const listen = [_][]const u8{ "services", "web", "listen" };
    const memory = [_][]const u8{ "services", "web", "memory" };
    n = try put(gpa, n, &listen, try scalar(gpa, "tcp/80"), true);
    n = try put(gpa, n, &listen, try scalar(gpa, "tcp/443 loopback"), true);
    n = try put(gpa, n, &memory, try scalar(gpa, "64"), false);
    n = try put(gpa, n, &memory, try scalar(gpa, "128"), false);
    n = try put(gpa, n, &.{"updates"}, try scalar(gpa, "off"), false);
    const web = n.get("services").?.get("web").?;
    try expectWords(&.{ "tcp/80", "tcp/443 loopback" }, try texts(gpa, web.get("listen").?));
    try testing.expectEqualStrings("128", web.get("memory").?.scalar.text);
    try testing.expectEqualStrings("off", n.get("updates").?.scalar.text);
    n = try put(gpa, n, &.{ "updates", "every" }, try scalar(gpa, "1h"), false);
    try testing.expectEqualStrings("1h", n.get("updates").?.get("every").?.scalar.text);
    try testing.expectEqualStrings("\"- x\"", (try scalar(gpa, "- x")).scalar.raw);
    try testing.expectEqualStrings("\"a: b\"", (try scalar(gpa, "a: b")).scalar.raw);
    try testing.expectEqualStrings("tcp/80", (try scalar(gpa, "tcp/80")).scalar.raw);
}

test "the checklist refuses an image's words unanswered" {
    var why: Why = .{};
    const i: Image = .{ .name = "web", .ref = "x" };
    try testing.expectError(
        error.Refused,
        checklist(i, .{ .exposed = &.{"8080/tcp"}, .volumes = &.{"/var/cache"} }, &why),
    );
    const hint = "--services.web.listen 'tcp/8080 loopback'";
    try testing.expect(std.mem.find(u8, why.text, hint) != null);
    try testing.expect(std.mem.find(u8, why.text, "--services.web.write /var/cache") != null);
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
