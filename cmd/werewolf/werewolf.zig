//! werewolf: make what a werewolf machine needs, on the machine that makes
//! it (docs/design/cli.md). Built for this host, not the image.
//!
//!     werewolf build FORM [-o DIR] [--arch ARCH] [--format qcow2|raw|vhd|vmdk] [--app DIR]
//!     werewolf pack FORM [-o FILE] [-n] [--on TARGET] [CONFIG...]
//!     werewolf run FORM [--dev] [--app DIR] [CONFIG...]
//!     werewolf build-apk RECIPE [--arch ARCH]
//!
//! build-apk builds a form's own package from a melange recipe (apk.zig).
//!
//! run boots FORM under QEMU here, as make run does, with the config tar
//! the same flags as pack's make, checked as pack checks it, and nothing
//! else: not ./config. --dev adds the debug shell. Ctrl-a x ends it.
//!
//! build makes FORM as a release is made, with make's _dist-form, never
//! with a debug shell: its boot disk and slot in DIR (dist), named as a
//! release names them, beside the release's manifest, FORM-ARCH.json, which
//! lists every package and file's sha256. The same inputs give the same
//! files. --format converts the disk with qemu-img: raw, vhd (fixed, for
//! Azure) or vmdk; the manifest names the qcow2 it came from.
//!
//! pack writes the config tar a machine of FORM boots with: its secrets
//! and settings, which init finds on any block device or in the cloud's
//! user data (docs/cloud.md). The flags are not written into this program.
//! FORM's service files declare them, and pack reads FORM's chain in
//! ./forms to learn them:
//!
//!     config  host-key /run/config/bastion/host_key      --host-key FILE
//!     setting destinations addrport... as PermitOpen     --destinations ADDR:PORT,...
//!
//! Others do not come from a form: --config DIR, a directory of files as
//! they go in the tar; --hostname NAME; --ip CIDR, --gw ADDR and --dns
//! ADDR, a static network for init where none gives one by DHCP
//! (lib/network.zig); --data-key FILE; --root-keys FILE, root's
//! authorized_keys, which init gives sshd; and --update-policy FILE,
//! checked as slot-update applies it, over the form's own
//! (lib/update-policy.zig). A FILE flag
//! reads a file, or - for standard input, never a value on the line, so no
//! secret is in ps or a shell history. A setting is checked with the
//! guest's own functions (lib/settings.zig), so what pack accepts the
//! machine accepts. Everything is checked before anything is written.
//!
//! The tar is the same for the same inputs: ustar, regular files only,
//! 0600, root's, dated 1970, sorted. It fits the strictest reader, the
//! cloud's (cmd/cloud-metadata): names of letters, digits and . _ - /, at
//! most 100 bytes. pack lists what it packs, marking a file nothing on
//! the machine reads, and says which targets the tar fits; --on TARGET
//! refuses one it does not. -n checks and writes nothing.

const std = @import("std");
const settings = @import("settings");
const update_policy = @import("update-policy");
const network = @import("network");
const lima = @import("lima.zig");
const bhyve = @import("bhyve.zig");
const firecracker = @import("firecracker.zig");
const proxmox = @import("proxmox.zig");
const gcp = @import("gcp.zig");
const aws = @import("aws.zig");
const azure = @import("azure.zig");
const app = @import("app.zig");
const apk = @import("apk.zig");
const forms = @import("form");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const json = std.json;

const usage =
    \\usage: werewolf build FORM [-o DIR] [--arch ARCH] [--format qcow2|raw|vhd|vmdk] [--app DIR]
    \\       werewolf pack FORM [-o FILE] [-n] [--on TARGET] [CONFIG...]
    \\       werewolf pack FORM -h          the flags FORM takes
    \\       werewolf run FORM [--dev] [--app DIR] [CONFIG...]
    \\       werewolf create FORM NAME [--on lima|bhyve|firecracker|proxmox|gcp|aws|azure|qemu] [--arch ARCH] [--size TYPE] [CONFIG...]
    \\       werewolf delete NAME [--on lima|bhyve|firecracker|proxmox|gcp|aws|azure]
    \\       werewolf console NAME [--on lima|bhyve|firecracker|proxmox|gcp|aws|azure]
    \\       werewolf upload DISK --on gcp|aws|azure
    \\       werewolf build-apk RECIPE [--arch ARCH]   a form's own package, from a melange recipe
    \\
;

/// What init extracts from a config disk, at most, per file.
const max_disk_file = 1 << 20;
/// What cloud-metadata accepts from user data (cmd/cloud-metadata).
const max_cloud_file = 32 << 10;
const max_cloud_total = 48 << 10;
const max_cloud_entries = 32;
const max_name = 100;

/// The environment, for what names a Proxmox node (proxmox.zig).
var environ: *const std.process.Environ.Map = undefined;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    environ = init.environ_map;
    const args = init.minimal.args.toSlice(gpa) catch fatal(io, "out of memory", .{});
    if (args.len < 2) fatal(io, "{s}", .{usage});
    const verb = std.meta.stringToEnum(
        enum {
            build,
            pack,
            run,
            create,
            delete,
            console,
            upload,
            @"build-apk",
            _bhyve,
            _firecracker,
        },
        args[1],
    ) orelse
        fatal(io, "no verb {s}\n{s}", .{ args[1], usage });
    var why: Why = .{};
    const done = switch (verb) {
        .build => build(io, gpa, args[2..], &why),
        .pack => pack(io, gpa, args[2..], &why),
        .run => runForm(io, gpa, args[2..], &why),
        .create => create(io, gpa, args[2..], &why),
        .delete => delete(io, gpa, args[2..], &why),
        .console => console(io, gpa, args[2..], &why),
        .upload => upload(io, gpa, args[2..], &why),
        .@"build-apk" => apk.build(io, gpa, args[2..], &why),
        // create's supervisors on bhyve and Firecracker, not verbs for anyone.
        ._bhyve => if (args.len < 5)
            why.refuse("_bhyve NAME CONFIG BHYVE...", .{})
        else
            bhyve.keep(io, gpa, args[2], args[3], args[4..]),
        ._firecracker => if (args.len != 3)
            why.refuse("_firecracker DIR", .{})
        else
            firecracker.keep(io, gpa, args[2]),
    };
    done catch |err| switch (err) {
        error.Refused => fatal(io, "{s}", .{why.text}),
        else => fatal(io, "{s}", .{@errorName(err)}),
    };
}

fn fatal(io: Io, comptime fmt: []const u8, args: anytype) noreturn {
    say(io, fmt, args);
    std.process.exit(1);
}

pub fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    const line = std.mem.print(&buf, "werewolf: " ++ fmt ++ "\n", args) catch return;
    Io.File.stderr().writeStreamingAll(io, line) catch {};
}

/// Why pack refused, for the one line that says so.
pub const Why = struct {
    buf: [512]u8 = undefined,
    text: []const u8 = "",

    pub fn refuse(w: *Why, comptime fmt: []const u8, args: anytype) error{Refused} {
        w.text = std.mem.print(&w.buf, fmt, args) catch "(too long to say)";
        return error.Refused;
    }
};

// --- the form's interface ----------------------------------------------------------

/// A file a service declared: --FLAG FILE puts it at path in the tar. An
/// optional one the service runs without.
const File = struct {
    flag: []const u8,
    path: []const u8,
    service: []const u8,
    optional: bool = false,
};

/// A service with settings: its settings.json goes at path in the tar.
const Settings = struct {
    service: []const u8,
    path: []const u8,
    decl: []settings.Setting,
};

/// The flags a form takes, and where each lands.
const Interface = struct {
    files: []const File,
    settings: []const Settings,
    /// The form's own etc/werewolf/update-policy.json, if it has one: what
    /// an operator's update-policy.json is applied over.
    policy: ?[]const u8 = null,
};

/// The files werewolf's own programs read from a config tar, each filled
/// by a flag of werewolf's: init's hostname, network, data.key and root's
/// authorized_keys, and slot-update's update-policy.json.
const own_files = [_][]const u8{
    "hostname",
    "network",
    "data.key",
    "authorized_keys",
    "update-policy.json",
};

/// The universal flags, which no service may declare.
const reserved = [_][]const u8{
    "config",
    "hostname",
    "ip",
    "gw",
    "dns",
    "data-key",
    "root-keys",
    "update-policy",
    "on",
    "arch",
    "size",
    "app",
};

/// A form's chain, base first, as the build lays it (lib/form.zig): the
/// form in ./forms, or in the directory form names.
fn chain(io: Io, gpa: Allocator, form: []const u8, why: *Why) ![]const forms.Form {
    Dir.cwd().access(io, "forms", .{}) catch
        return why.refuse("no ./forms: run werewolf in a werewolf checkout", .{});
    var f: forms.Failure = .{};
    return forms.chain(io, gpa, Dir.cwd(), form, &f) catch |err| switch (err) {
        error.Form => why.refuse("{s}", .{f.text}),
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// A service's name and its file, as the image will hold it.
const Service = struct { name: []const u8, text: []const u8 };

/// The service files of a chain, as the image lays them over each other:
/// a later form's etc/sv/NAME replaces an earlier one's whole, and one with
/// no service file (runit's own run) leaves none.
fn services(io: Io, gpa: Allocator, c: []const forms.Form) ![]const Service {
    var found: std.array_hash_map.String(?[]const u8) = .empty;
    for (c) |form| {
        var sv = Dir.cwd().openDir(
            io,
            try gpa.print("{s}/rootfs/etc/sv", .{form.dir}),
            .{ .iterate = true },
        ) catch
            continue;
        defer sv.close(io);
        var it = sv.iterate();
        while (try it.next(io)) |e| {
            if (e.kind != .directory) continue;
            const text = sv.readFileAlloc(
                io,
                try gpa.print("{s}/service", .{e.name}),
                gpa,
                .limited(64 << 10),
            ) catch null;
            try found.put(gpa, try gpa.dupe(u8, e.name), text);
        }
    }
    var out: std.ArrayList(Service) = .empty;
    var it = found.iterator();
    while (it.next()) |e| if (e.value_ptr.*) |text|
        try out.append(gpa, .{ .name = e.key_ptr.*, .text = text });
    std.mem.sortUnstable(Service, out.items, {}, struct {
        fn lt(_: void, a: Service, b: Service) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
    return out.items;
}

/// The flags the services declare: their `config` lines, and their
/// `setting` and `render` lines, checked as leash checks them.
fn interface(gpa: Allocator, svcs: []const Service, why: *Why) !Interface {
    var files: std.ArrayList(File) = .empty;
    var sets: std.ArrayList(Settings) = .empty;
    for (svcs) |svc| {
        var decl: std.ArrayList(settings.Setting) = .empty;
        var render: ?settings.Render = null;
        var settings_path: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, svc.text, '\n');
        var n: usize = 0;
        while (lines.next()) |line| {
            n += 1;
            const words = try split(gpa, line);
            if (words.len == 0) continue;
            const key = words[0];
            const rest = words[1..];
            var bad: []const u8 = "";
            if (std.mem.eql(u8, key, "config")) {
                const optional = rest.len == 3 and std.mem.eql(u8, rest[2], "optional");
                if ((rest.len != 2 and !optional) or
                    !std.mem.startsWith(u8, rest[1], "/run/config/"))
                    return why.refuse(
                        "{s}, line {d}: config NAME /run/config/PATH [optional]",
                        .{ svc.name, n },
                    );
                const path = rest[1]["/run/config/".len..];
                if (!isTarName(path)) return why.refuse(
                    "{s}, line {d}: {s} cannot be in a config tar",
                    .{ svc.name, n, rest[1] },
                );
                if (std.mem.eql(u8, rest[0], settings.input_file)) {
                    settings_path = path;
                } else try files.append(
                    gpa,
                    .{ .flag = rest[0], .path = path, .service = svc.name, .optional = optional },
                );
            } else if (std.mem.eql(u8, key, "setting")) {
                try decl.append(gpa, settings.parseSetting(rest, &bad) catch
                    return why.refuse("{s}, line {d}: {s}", .{ svc.name, n, bad }));
            } else if (std.mem.eql(u8, key, "render")) {
                render = settings.parseRender(rest, &bad) catch
                    return why.refuse("{s}, line {d}: {s}", .{ svc.name, n, bad });
            }
        }
        const r = render orelse {
            if (decl.items.len > 0) return why.refuse("{s}: setting without render", .{svc.name});
            continue;
        };
        var bad: []const u8 = "";
        settings.declare(gpa, decl.items, r, &bad) catch |err| switch (err) {
            error.Invalid => return why.refuse("{s}: {s}", .{ svc.name, bad }),
            else => return err,
        };
        const path = settings_path orelse
            return why.refuse("{s}: settings come from a `config settings PATH` line", .{svc.name});
        try sets.append(gpa, .{ .service = svc.name, .path = path, .decl = decl.items });
    }

    // Every flag means one thing, and every path in the tar has one source.
    var flags: std.ArrayList(struct { []const u8, []const u8 }) = .empty;
    for (files.items) |f| try flags.append(gpa, .{ f.flag, f.service });
    for (sets.items) |s| for (s.decl) |d| try flags.append(gpa, .{ d.name, s.service });
    for (flags.items, 0..) |a, i| {
        for (reserved) |r| if (std.mem.eql(u8, a[0], r))
            return why.refuse("{s} declares --{s}, which is werewolf's own", .{ a[1], a[0] });
        for (flags.items[0..i]) |b| if (std.mem.eql(u8, a[0], b[0]))
            return why.refuse(
                "--{s} is declared by {s} and by {s}: rename one",
                .{ a[0], b[1], a[1] },
            );
    }
    var paths: std.ArrayList([]const u8) = .empty;
    for (files.items) |f| try paths.append(gpa, f.path);
    for (sets.items) |s| try paths.append(gpa, s.path);
    for (paths.items, 0..) |a, i| {
        for (own_files) |own| if (std.mem.eql(u8, a, own))
            return why.refuse("a service declares {s}, which is werewolf's own", .{a});
        for (paths.items[0..i]) |b| if (std.mem.eql(u8, a, b))
            return why.refuse("two declarations put files at {s}", .{a});
    }
    return .{ .files = files.items, .settings = sets.items };
}

/// A service file's words, for the lines pack reads: no quotes are needed
/// in a config, setting or render line, and a # starts a comment.
fn split(gpa: Allocator, line: []const u8) ![]const []const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeAny(u8, line, " \t\r");
    while (it.next()) |w| {
        if (w[0] == '#') break;
        try words.append(gpa, w);
    }
    return words.items;
}

// --- the inputs -----------------------------------------------------------------------

const Target = enum { disk, gcp, aws, azure };

/// What --on names: a hypervisor reads the tar from a disk; a cloud from
/// user data, through cloud-metadata.
fn target(name: []const u8) ?Target {
    for ([_][]const u8{ "disk", "qemu", "lima", "bhyve", "firecracker", "proxmox" }) |d|
        if (std.mem.eql(u8, name, d)) return .disk;
    return std.meta.stringToEnum(Target, name);
}

const Options = struct {
    form: []const u8 = "",
    /// create's machine's name, the word after FORM.
    name: ?[]const u8 = null,
    out: ?[]const u8 = null,
    check: bool = false,
    help: bool = false,
    on: ?Target = null,
    /// --on as given: what create runs on, where on is what the tar must fit.
    platform: ?[]const u8 = null,
    config: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
    /// A static network: init's network file.
    ip: ?[]const u8 = null,
    gw: ?[]const u8 = null,
    dns: ?[]const u8 = null,
    data_key: ?[]const u8 = null,
    update_policy: ?[]const u8 = null,
    root_keys: ?[]const u8 = null,
    /// create --on gcp's: the machine's architecture, and its type.
    arch: ?[]const u8 = null,
    size: ?[]const u8 = null,
    /// build, run and create's: a directory, laid where the form keeps its
    /// application (app.zig).
    app: ?[]const u8 = null,
    /// --FLAG VALUE pairs the form declares, in order.
    flags: []const [2][]const u8 = &.{},
};

/// The command line, without its verb. FORM is the one word that is not a
/// flag or a flag's value.
fn options(gpa: Allocator, args: []const []const u8, why: *Why) !Options {
    var o: Options = .{};
    var flags: std.ArrayList([2][]const u8) = .empty;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-n")) {
            o.check = true;
            continue;
        }
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            o.help = true;
            continue;
        }
        if (a.len == 0 or a[0] != '-') {
            if (o.form.len == 0) {
                o.form = a;
            } else if (o.name == null) {
                o.name = a;
            } else return why.refuse(
                "{s}: a form and at most a name ({s} {s} already)",
                .{ a, o.form, o.name.? },
            );
            continue;
        }
        var name = a;
        var value: ?[]const u8 = null;
        if (std.mem.findScalar(u8, a, '=')) |eq| {
            name = a[0..eq];
            value = a[eq + 1 ..];
        }
        if (!std.mem.startsWith(u8, name, "--") and !std.mem.eql(u8, name, "-o"))
            return why.refuse("{s}: flags are --NAME, or -o, -n, -h", .{a});
        const v = value orelse v: {
            i += 1;
            if (i == args.len) return why.refuse("{s} wants a value", .{a});
            break :v args[i];
        };
        const flag = if (std.mem.eql(u8, name, "-o")) "o" else name[2..];
        const slot: ?*?[]const u8 = if (std.mem.eql(u8, flag, "o"))
            &o.out
        else if (std.mem.eql(u8, flag, "config"))
            &o.config
        else if (std.mem.eql(u8, flag, "hostname"))
            &o.hostname
        else if (std.mem.eql(u8, flag, "ip"))
            &o.ip
        else if (std.mem.eql(u8, flag, "gw"))
            &o.gw
        else if (std.mem.eql(u8, flag, "dns"))
            &o.dns
        else if (std.mem.eql(u8, flag, "data-key"))
            &o.data_key
        else if (std.mem.eql(u8, flag, "update-policy"))
            &o.update_policy
        else if (std.mem.eql(u8, flag, "root-keys"))
            &o.root_keys
        else if (std.mem.eql(u8, flag, "arch"))
            &o.arch
        else if (std.mem.eql(u8, flag, "size"))
            &o.size
        else if (std.mem.eql(u8, flag, "app"))
            &o.app
        else
            null;
        if (slot) |s| {
            if (s.* != null) return why.refuse("--{s} given twice", .{flag});
            s.* = v;
        } else if (std.mem.eql(u8, flag, "on")) {
            if (o.on != null) return why.refuse("--on given twice", .{});
            o.on = target(v) orelse
                return why.refuse(
                    "--on {s}: disk qemu lima bhyve firecracker proxmox gcp aws azure",
                    .{v},
                );
            o.platform = v;
        } else try flags.append(gpa, .{ flag, v });
    }
    if (o.form.len == 0) return why.refuse("no form\n{s}", .{usage});
    o.flags = flags.items;
    return o;
}

/// A path in the tar and what goes there.
const Entry = struct { path: []const u8, data: []const u8, from: []const u8 };

/// Read what the flags name, check it against the form, and return the
/// tar's entries, sorted. Nothing is written.
fn gather(io: Io, gpa: Allocator, iface: Interface, o: Options, why: *Why) ![]const Entry {
    var entries: std.ArrayList(Entry) = .empty;
    var stdin_used: ?[]const u8 = null;

    if (o.config) |dir| try readConfigDir(io, gpa, dir, &entries, why);
    if (o.hostname) |h| {
        if (settings.reason(
            .hostname,
            .{ .string = h },
        )) |r| return why.refuse("--hostname {s}: {s}", .{ h, r });
        try add(
            gpa,
            &entries,
            .{ .path = "hostname", .data = try gpa.print("{s}\n", .{h}), .from = "--hostname" },
            why,
        );
    }
    if (o.ip != null or o.gw != null or o.dns != null) {
        const ip = o.ip orelse return why.refuse("--gw and --dns want --ip", .{});
        var buf: [network.max_len]u8 = undefined;
        const text = network.format(
            &buf,
            .{ .ip = ip, .gw = o.gw orelse "", .dns = o.dns orelse "" },
        ) catch
            return why.refuse("--ip, --gw, --dns: over {d} bytes", .{network.max_len});
        try add(
            gpa,
            &entries,
            .{ .path = "network", .data = try gpa.dupe(u8, text), .from = "--ip" },
            why,
        );
    }
    if (o.data_key) |f| try add(gpa, &entries, .{
        .path = "data.key",
        .data = try readInput(io, gpa, f, "--data-key", &stdin_used, why),
        .from = "--data-key",
    }, why);

    if (o.root_keys) |f| try add(gpa, &entries, .{
        .path = "authorized_keys",
        .data = try readInput(io, gpa, f, "--root-keys", &stdin_used, why),
        .from = "--root-keys",
    }, why);
    if (o.update_policy) |f| try add(gpa, &entries, .{
        .path = "update-policy.json",
        .data = try readInput(io, gpa, f, "--update-policy", &stdin_used, why),
        .from = "--update-policy",
    }, why);

    // Settings flags collect per service; file flags go straight in.
    const values = try gpa.alloc(std.json.ObjectMap, iface.settings.len);
    @memset(values, .empty);
    flag: for (o.flags) |fv| {
        const flag, const value = fv;
        for (iface.files) |f| if (std.mem.eql(u8, f.flag, flag)) {
            const from = try gpa.print("--{s}", .{flag});
            try add(gpa, &entries, .{
                .path = f.path,
                .data = try readInput(io, gpa, value, from, &stdin_used, why),
                .from = from,
            }, why);
            continue :flag;
        };
        for (iface.settings, values) |s, *obj| for (s.decl) |d| if (std.mem.eql(u8, d.name, flag)) {
            try setValue(gpa, obj, d, value, why);
            continue :flag;
        };
        return why.refuse(
            "{s} takes no --{s}; werewolf pack {s} -h lists what it does",
            .{ o.form, flag, o.form },
        );
    }
    for (iface.settings, values) |s, obj| {
        if (obj.count() == 0) continue;
        const doc: json.Value = .{ .object = obj };
        try add(gpa, &entries, .{
            .path = s.path,
            .data = try json.Stringify.valueAlloc(gpa, doc, .{}),
            .from = "settings flags",
        }, why);
    }

    // What the machine would refuse, refused here: each service's settings,
    // as service-config checks them, and every file a service needs.
    for (iface.settings) |s| {
        const text = for (entries.items) |e| {
            if (std.mem.eql(u8, e.path, s.path)) break e.data;
        } else "{}";
        var diag: settings.Diagnostic = .{};
        _ = settings.parseValues(gpa, s.decl, text, &diag) catch |err| switch (err) {
            error.Invalid => return if (diag.index) |n|
                why.refuse("{s}: {s}[{d}]: {s}", .{ s.path, diag.setting, n, diag.why })
            else
                why.refuse("{s}: {s}: {s}", .{ s.path, diag.setting, diag.why }),
            else => return err,
        };
    }
    // The network, as init reads it.
    for (entries.items) |e| if (std.mem.eql(u8, e.path, "network")) {
        var reason: []const u8 = "";
        if (network.parse(e.data, &reason) == null) return why.refuse("network: {s}", .{reason});
    };
    // The updater's policy, as slot-update applies it: werewolf's limits,
    // then the form's file, then the operator's.
    for (entries.items) |e| if (std.mem.eql(u8, e.path, "update-policy.json")) {
        var policy: update_policy.Settings = .{};
        if (iface.policy) |text| if (try update_policy.apply(gpa, &policy, .form, text)) |r|
            return why.refuse(
                "{s}'s etc/werewolf/update-policy.json: {s}: {s}",
                .{ o.form, r.key, r.why },
            );
        if (try update_policy.apply(gpa, &policy, .operator, e.data)) |r|
            return why.refuse("update-policy.json: {s}: {s}", .{ r.key, r.why });
    };
    for (iface.files) |f| {
        if (f.optional) continue;
        for (entries.items) |e| {
            if (std.mem.eql(u8, e.path, f.path)) break;
        } else return why.refuse(
            "{s} needs {s}: --{s} FILE, or the file in --config DIR",
            .{ f.service, f.path, f.flag },
        );
    }

    std.mem.sortUnstable(Entry, entries.items, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);
    return entries.items;
}

/// One value of a setting given on the line: a list's values may be given
/// by commas or by repeating the flag; a string list's only by repeating,
/// since a string may hold a comma.
fn setValue(
    gpa: Allocator,
    obj: *json.ObjectMap,
    d: settings.Setting,
    text: []const u8,
    why: *Why,
) !void {
    var parts = std.mem.splitScalar(u8, text, ',');
    var whole = [_][]const u8{text};
    var items: std.ArrayList([]const u8) = .empty;
    if (d.list and d.type != .string) {
        while (parts.next()) |p| try items.append(gpa, p);
    } else try items.appendSlice(gpa, &whole);
    var reason: []const u8 = "";
    for (items.items) |item| {
        const v = settings.fromText(d.type, item, &reason) orelse
            return why.refuse("--{s} {s}: {s}", .{ d.name, item, reason });
        if (!d.list) {
            if (obj.contains(d.name)) return why.refuse("--{s} given twice", .{d.name});
            try obj.put(gpa, d.name, v);
            continue;
        }
        const slot = try obj.getOrPut(gpa, d.name);
        if (!slot.found_existing) slot.value_ptr.* = .{ .array = .init(gpa) };
        try slot.value_ptr.array.append(v);
    }
}

fn add(gpa: Allocator, entries: *std.ArrayList(Entry), e: Entry, why: *Why) !void {
    if (!isTarName(e.path)) return why.refuse(
        "{s}: a name in a config tar is [A-Za-z0-9._-/], at most 100",
        .{e.path},
    );
    if (e.data.len > max_disk_file) return why.refuse(
        "{s}: over 1 MiB, which init refuses",
        .{e.path},
    );
    for (entries.items) |o| {
        if (std.mem.eql(u8, o.path, e.path))
            return why.refuse(
                "{s} is given by {s} and by {s}: say it once",
                .{ e.path, o.from, e.from },
            );
        if (beneath(e.path, o.path) or beneath(o.path, e.path))
            return why.refuse("{s} and {s}: one is a file and a directory", .{ o.path, e.path });
    }
    try entries.append(gpa, e);
}

/// What a FILE flag names: a file, or - for standard input, once.
fn readInput(
    io: Io,
    gpa: Allocator,
    path: []const u8,
    flag: []const u8,
    stdin_used: *?[]const u8,
    why: *Why,
) ![]const u8 {
    if (std.mem.eql(u8, path, "-")) {
        if (stdin_used.*) |other| return why.refuse(
            "{s} and {s} both read standard input",
            .{ other, flag },
        );
        stdin_used.* = flag;
        var r = Io.File.stdin().readerStreaming(io, &.{});
        return r.interface.allocRemaining(gpa, .limited(max_disk_file + 1)) catch |err|
            why.refuse("{s} -: {s}", .{ flag, @errorName(err) });
    }
    return Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_disk_file + 1)) catch |err|
        why.refuse("{s} {s}: {s}", .{ flag, path, @errorName(err) });
}

/// --config DIR: its regular files, at the paths they have in it. Finder's
/// .DS_Store and AppleDouble ._ files are skipped; anything else not a
/// regular file or a directory is refused.
fn readConfigDir(
    io: Io,
    gpa: Allocator,
    path: []const u8,
    entries: *std.ArrayList(Entry),
    why: *Why,
) !void {
    var dir = Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err|
        return why.refuse("--config {s}: {s}", .{ path, @errorName(err) });
    defer dir.close(io);
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        if (std.mem.eql(u8, e.basename, ".DS_Store") or
            std.mem.startsWith(u8, e.basename, "._")) continue;
        switch (e.kind) {
            .directory => continue,
            .file => {},
            else => return why.refuse("--config {s}: {s} is not a regular file", .{ path, e.path }),
        }
        const name = try gpa.dupe(u8, e.path);
        if (std.fs.path.sep != '/') std.mem.replaceScalar(u8, name, std.fs.path.sep, '/');
        const data = e.dir.readFileAlloc(
            io,
            e.basename,
            gpa,
            .limited(max_disk_file + 1),
        ) catch |err|
            return why.refuse("--config {s}: {s}: {s}", .{ path, name, @errorName(err) });
        try add(
            gpa,
            entries,
            .{ .path = name, .data = data, .from = try gpa.print("--config {s}", .{path}) },
            why,
        );
    }
}

// --- the tar ----------------------------------------------------------------------------

/// POSIX ustar of the entries, as cloud-metadata writes one: root's, files
/// 0600, dated 1970, no directory entries (init makes the parents), then
/// the end.
fn writeTar(gpa: Allocator, entries: []const Entry) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (entries) |e| {
        var h: [512]u8 = @splat(0);
        @memcpy(h[0..e.path.len], e.path);
        _ = std.mem.print(h[100..108], "0000600\x00", .{}) catch unreachable;
        _ = std.mem.print(h[108..116], "0000000\x00", .{}) catch unreachable;
        _ = std.mem.print(h[116..124], "0000000\x00", .{}) catch unreachable;
        _ = std.mem.print(h[124..136], "{o:0>11}\x00", .{e.data.len}) catch unreachable;
        _ = std.mem.print(h[136..148], "00000000000\x00", .{}) catch unreachable;
        h[156] = '0';
        @memcpy(h[257..265], "ustar\x0000");
        @memset(h[148..156], ' ');
        var sum: usize = 0;
        for (h) |b| sum += b;
        _ = std.mem.print(h[148..156], "{o:0>6}\x00 ", .{sum}) catch unreachable;
        try out.appendSlice(gpa, &h);
        try out.appendSlice(gpa, e.data);
        try out.appendNTimes(gpa, 0, (512 - e.data.len % 512) % 512);
    }
    try out.appendNTimes(gpa, 0, 1024);
    return out.items;
}

/// Why the tar does not fit t, or null if it does. AWS caps user data at
/// 16 KiB and Azure at 64 KiB, both of base64; GCP's 256 KiB is above
/// what cloud-metadata takes.
fn misfit(entries: []const Entry, tar_len: usize, t: Target) ?[]const u8 {
    if (t == .disk) return null;
    if (entries.len > max_cloud_entries) return "more than 32 files";
    var total: usize = 0;
    for (entries) |e| {
        if (e.data.len > max_cloud_file) return "a file over 32 KiB";
        total += e.data.len;
    }
    if (total > max_cloud_total) return "over 48 KiB of files";
    const base64 = (tar_len + 2) / 3 * 4;
    if (t == .aws and base64 > 16 << 10) return "over AWS's 16 KiB of user data";
    if (t == .azure and base64 > 64 << 10) return "over Azure's 64 KiB of user data";
    return null;
}

// --- build ------------------------------------------------------------------------------

const DiskFormat = enum { qcow2, raw, vhd, vmdk };

const BuildOptions = struct {
    form: []const u8,
    app: ?[]const u8 = null,
    dir: []const u8 = "dist",
    arch: []const u8,
    format: DiskFormat = .qcow2,
};

/// build's command line: FORM, and -o, --arch, --format, each with a value.
/// host is this machine's arch, if werewolf builds for it.
fn buildOptions(args: []const []const u8, host: ?[]const u8, why: *Why) !BuildOptions {
    var form: ?[]const u8 = null;
    var o: BuildOptions = .{ .form = "", .arch = host orelse "" };
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len == 0 or a[0] != '-') {
            if (form != null) return why.refuse("{s}: one form at a time", .{a});
            form = a;
            continue;
        }
        i += 1;
        if (i == args.len) return why.refuse("{s} wants a value", .{a});
        const v = args[i];
        if (std.mem.eql(u8, a, "-o")) {
            o.dir = v;
        } else if (std.mem.eql(u8, a, "--arch")) {
            if (!std.mem.eql(u8, v, "aarch64") and !std.mem.eql(u8, v, "x86_64"))
                return why.refuse("--arch {s}: aarch64 or x86_64", .{v});
            o.arch = v;
        } else if (std.mem.eql(u8, a, "--app")) {
            o.app = v;
        } else if (std.mem.eql(u8, a, "--format")) {
            o.format = std.meta.stringToEnum(DiskFormat, v) orelse
                return why.refuse("--format {s}: qcow2 raw vhd vmdk", .{v});
        } else return why.refuse(
            "{s}: build takes -o, --arch, --format and --app\n{s}",
            .{ a, usage },
        );
    }
    o.form = form orelse return why.refuse("no form\n{s}", .{usage});
    if (o.arch.len == 0) return why.refuse(
        "this machine is neither aarch64 nor x86_64: --arch",
        .{},
    );
    return o;
}

fn build(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const o = try buildOptions(args, switch (@import("builtin").cpu.arch) {
        .aarch64 => "aarch64",
        .x86_64 => "x86_64",
        else => null,
    }, why);
    const f = o.form;
    const a = o.arch;
    const dir = o.dir;
    const format = o.format;
    _ = try chain(io, gpa, f, why);
    const ab = try appBuild(io, gpa, f, a, o.app, why);

    // make keeps the build graph; this only names the target, as it ships.
    try run(io, why, &.{
        make_cmd,
        "--no-print-directory",
        try gpa.print("FORM={s}", .{f}),
        try gpa.print("ARCH={s}", .{a}),
        "DEV=",
        ab.app,
        try gpa.print("DIST={s}", .{dir}),
        "_dist-form",
    });

    const name = try gpa.print("{s}/{s}-{s}.json", .{ dir, f, a });
    const text = Dir.cwd().readFileAlloc(io, name, gpa, .limited(1 << 20)) catch |err|
        return why.refuse("{s}: {s}", .{ name, @errorName(err) });
    const m = json.parseFromSliceLeaky(json.Value, gpa, text, .{}) catch
        return why.refuse("{s}: not JSON", .{name});
    if (m != .object) return why.refuse("{s}: not a manifest", .{name});
    const files = m.object.get("files") orelse return why.refuse("{s}: no files", .{name});
    const id = m.object.get("build") orelse return why.refuse("{s}: no build", .{name});
    if (files != .object or id != .string) return why.refuse("{s}: not a manifest", .{name});

    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    try w.print("{s} {s}: build {s}, {s}\n", .{ f, a, id.string, name });
    var it = files.object.iterator();
    while (it.next()) |e| try w.print("  {s}/{s}-{s}-{s}\n", .{ dir, f, a, e.key_ptr.* });
    if (format == .qcow2) return;

    if (files.object.get("disk.qcow2") == null)
        return why.refuse("{s} is released for direct boot, without a disk to convert", .{f});
    const src = try gpa.print("{s}/{s}-{s}-disk.qcow2", .{ dir, f, a });
    const dst = try gpa.print("{s}/{s}-{s}-disk.{t}", .{ dir, f, a, format });
    // VHD as Azure takes it: fixed, its size exactly the disk's.
    try run(io, why, switch (format) {
        .raw => &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", src, dst },
        .vhd => &.{
            "qemu-img",
            "convert",
            "-f",
            "qcow2",
            "-O",
            "vpc",
            "-o",
            "subformat=fixed,force_size=on",
            src,
            dst,
        },
        .vmdk => &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "vmdk", src, dst },
        .qcow2 => unreachable,
    });
    try w.print("  {s}, from disk.qcow2\n", .{dst});
}

/// Run argv, its output the user's on standard error, so that standard
/// output is werewolf's result alone, and refuse if it fails.
pub fn run(io: Io, why: *Why, argv: []const []const u8) !void {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .{ .file = Io.File.stderr() },
    }) catch |err|
        return why.refuse("{s}: {s}", .{ argv[0], @errorName(err) });
    const term = child.wait(io) catch |err| return why.refuse(
        "{s}: {s}",
        .{ argv[0], @errorName(err) },
    );
    if (term != .exited or
        term.exited != 0) return why.refuse("{s} failed; its output is above", .{argv[0]});
}

// --- pack -------------------------------------------------------------------------------

fn pack(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const o = try options(gpa, args, why);
    if (o.name) |n| return why.refuse("{s}: pack takes one form, and no name", .{n});
    if (o.arch != null or o.size != null) return why.refuse("--arch and --size are create's", .{});
    if (o.app != null) return why.refuse(
        "--app is build's, run's and create's: an application is in the image",
        .{},
    );
    const iface = try formInterface(io, gpa, o.form, why);
    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    if (o.help) return help(w, gpa, "pack", o.form, iface);
    if (o.out == null and
        !o.check) return why.refuse("say where: -o FILE, or -n to check only", .{});

    const entries = try gather(io, gpa, iface, o, why);
    const tar = try writeTar(gpa, entries);
    if (o.on) |t| if (misfit(
        entries,
        tar.len,
        t,
    )) |r| return why.refuse("not for {t}: {s}", .{ t, r });

    for (entries) |e| try w.print("{s}\t{d}{s}\n", .{
        e.path,
        e.data.len,
        if (declared(iface, e.path)) "" else "\tnothing reads it",
    });
    var fits: std.ArrayList(u8) = .empty;
    for ([_]Target{ .disk, .gcp, .azure, .aws }) |t| if (misfit(entries, tar.len, t) == null)
        try fits.print(gpa, " {t}", .{t});
    try w.print("{d} files, a {d}-byte tar, for:{s}\n", .{ entries.len, tar.len, fits.items });
    if (o.check) return;
    try writePrivate(io, gpa, o.out.?, tar, why);
    try w.print("wrote {s}\n", .{o.out.?});
}

/// The flags FORM takes, from its chain's files.
fn formInterface(io: Io, gpa: Allocator, form: []const u8, why: *Why) !Interface {
    const c = try chain(io, gpa, form, why);
    var iface = try interface(gpa, try services(io, gpa, c), why);
    // As the image lays the forms over each other: the last one's wins.
    for (c) |f| {
        const path = try gpa.print("{s}/rootfs/etc/werewolf/update-policy.json", .{f.dir});
        if (Dir.cwd().readFileAlloc(io, path, gpa, .limited(update_policy.max_input + 1))) |text| {
            iface.policy = text;
        } else |_| {}
    }
    return iface;
}

fn help(w: *Io.Writer, gpa: Allocator, verb: []const u8, form: []const u8, iface: Interface) !void {
    try w.print("{s}\nwerewolf {s} {s} takes:\n", .{ usage, verb, form });
    try row(w, "--config DIR", "files as they go in the tar");
    try row(w, "--hostname NAME", "hostname");
    try row(w, "--ip CIDR", "network: an address, where no DHCP gives one");
    try row(w, "--gw ADDR", "network: the default route");
    try row(w, "--dns ADDR", "network: the resolver");
    try row(w, "--data-key FILE", "data.key: /data in LUKS2");
    try row(w, "--root-keys FILE", "authorized_keys: root's, where the form runs sshd");
    try row(w, "--update-policy FILE", "update-policy.json: when updates install");
    for (iface.files) |f| try row(
        w,
        try gpa.print("--{s} FILE", .{f.flag}),
        try gpa.print("{s}{s}", .{ f.path, if (f.optional) "" else ", required" }),
    );
    for (iface.settings) |st| for (st.decl) |d| try row(
        w,
        try gpa.print("--{s} {t}{s}", .{ d.name, d.type, if (d.list) "..." else "" }),
        try gpa.print("{s}{s}", .{ st.path, if (d.required) ", required" else "" }),
    );
}

/// data, at path, 0600: written beside it, then renamed over it, so path
/// is never half a file.
pub fn writePrivate(io: Io, gpa: Allocator, path: []const u8, data: []const u8, why: *Why) !void {
    const tmp = try gpa.print("{s}.tmp", .{path});
    Dir.cwd().deleteFile(io, tmp) catch {};
    var f = Dir.cwd().createFile(
        io,
        tmp,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    ) catch |err|
        return why.refuse("{s}: {s}", .{ tmp, @errorName(err) });
    f.writeStreamingAll(io, data) catch |err| {
        f.close(io);
        return why.refuse("{s}: {s}", .{ tmp, @errorName(err) });
    };
    f.close(io);
    Dir.rename(Dir.cwd(), tmp, Dir.cwd(), path, io) catch |err|
        return why.refuse("{s}: {s}", .{ path, @errorName(err) });
}

// --- run ---------------------------------------------------------------------------------

/// Where run leaves the tar it attaches: build/, the checkout's.
const run_tar = "build/werewolf-run.tar";

/// FORM under QEMU here, as make run boots it, with the config tar the
/// flags make, checked as pack checks it. werewolf becomes make, and make
/// QEMU, so the console is this terminal's and Ctrl-a x ends it.
fn runForm(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    var dev = false;
    var rest: std.ArrayList([]const u8) = .empty;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--dev")) dev = true else try rest.append(gpa, a);
    }
    const o = try options(gpa, rest.items, why);
    if (o.out != null or o.check or o.on != null)
        return why.refuse("run takes no -o, -n or --on: it boots here, under QEMU", .{});
    if (o.name) |n| return why.refuse("{s}: run takes one form, and no name", .{n});
    if (o.arch != null or o.size != null) return why.refuse("--arch and --size are create's", .{});
    const iface = try formInterface(io, gpa, o.form, why);
    var out = Io.File.stdout().writerStreaming(io, &.{});
    if (o.help) return help(&out.interface, gpa, "run", o.form, iface);
    const entries = try gather(io, gpa, iface, o, why);
    const ab = try appBuild(io, gpa, o.form, hostArch(), o.app, why);
    return bootHere(io, gpa, o.form, dev, entries, ab.app, why);
}

/// FORM under QEMU here, in the foreground, with the tar of entries:
/// werewolf becomes make run, and make QEMU.
fn bootHere(
    io: Io,
    gpa: Allocator,
    form: []const u8,
    dev: bool,
    entries: []const Entry,
    app_arg: []const u8,
    why: *Why,
) !void {
    // The config is what the flags say, not whatever is in ./config.
    var qemu_config: []const u8 = "QEMU_CONFIG=";
    if (entries.len > 0) {
        Dir.cwd().createDirPath(io, "build") catch {};
        try writePrivate(io, gpa, run_tar, try writeTar(gpa, entries), why);
        qemu_config = "QEMU_CONFIG=-drive file=" ++ run_tar ++ ",format=raw,if=virtio,readonly=on";
    }
    say(io, "{s}{s}: ssh at 127.0.0.1:2222, http at 127.0.0.1:8080; Ctrl-a x quits", .{
        form,
        if (dev) ", with a shell" else "",
    });
    const err = std.process.replace(io, .{ .argv = &.{
        make_cmd,
        "--no-print-directory",
        try gpa.print("FORM={s}", .{form}),
        if (dev) "DEV=1" else "DEV=",
        app_arg,
        qemu_config,
        "run",
    } });
    return why.refuse("make: {s}", .{@errorName(err)});
}

// --- create, delete, console -----------------------------------------------------------

/// What --app makes of a build: make's APP= argument, and the name of
/// the form's build directory, FORM-app with an application, so the
/// form's own build is untouched.
const AppBuild = struct { app: []const u8, out: []const u8 };

fn appBuild(
    io: Io,
    gpa: Allocator,
    form: []const u8,
    arch: []const u8,
    src: ?[]const u8,
    why: *Why,
) !AppBuild {
    const dir = src orelse return .{ .app = "APP=", .out = form };
    const at = app.place(io, gpa, try chain(io, gpa, form, why)) catch
        return why.refuse("{s}: its etc/werewolf/app is not an absolute path", .{form});
    const where = at orelse return why.refuse(
        "{s} keeps no application (no etc/werewolf/app in its forms): build on app, python, " ++
            "node, jre, nginx or php",
        .{form},
    );
    var cwd_buf: [Dir.max_path_bytes]u8 = undefined;
    const cwd = cwd_buf[0..try std.process.currentPath(io, &cwd_buf)];
    const root = try gpa.print("{s}/build/{s}/apps/{s}", .{ cwd, arch, form });
    const staged = try app.stage(io, gpa, dir, root, where, why);
    say(io, "app {s}: {d} files, {d} bytes, sha256 {s}, at {s}", .{
        dir,
        staged.files,
        staged.bytes,
        staged.digest,
        where,
    });
    return .{ .app = try gpa.print("APP={s}", .{root}), .out = try gpa.print("{s}-app", .{form}) };
}

/// Where create keeps what it built for a machine: its disk, which names
/// its MAC, and its config tar, which holds secrets.
fn machineDir(gpa: Allocator, arch: []const u8, name: []const u8) ![]const u8 {
    return gpa.print("build/{s}/machines/{s}", .{ arch, name });
}

/// The GNU make the Makefile is written for: gmake on the BSDs, whose own
/// make is another program.
pub const make_cmd = switch (@import("builtin").os.tag) {
    .freebsd, .netbsd => "gmake",
    else => "make",
};

pub fn hostArch() []const u8 {
    return switch (@import("builtin").cpu.arch) {
        .aarch64 => "aarch64",
        else => "x86_64",
    };
}

/// What a machine runs on when --on does not say: Lima where it is
/// installed, bhyve on FreeBSD, or Firecracker on Linux with KVM, since
/// each keeps the machine; else QEMU here, in the foreground.
fn platform(io: Io, gpa: Allocator, given: ?[]const u8) []const u8 {
    if (given) |p| return p;
    if (lima.installed(io, gpa)) return "lima";
    if (bhyve.installed(io)) return "bhyve";
    return if (firecracker.installed(io, gpa)) "firecracker" else "qemu";
}

fn create(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    var o = try options(gpa, args, why);
    if (o.out != null or o.check)
        return why.refuse("create takes no -o or -n: werewolf pack writes a tar", .{});
    const iface = try formInterface(io, gpa, o.form, why);
    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    if (o.help) return help(w, gpa, "create", o.form, iface);
    const name = o.name orelse return why.refuse(
        "create FORM NAME: name the machine\n{s}",
        .{usage},
    );
    if (!isMachineName(name)) return why.refuse(
        "{s}: a machine's name is [a-z][a-z0-9-]*, at most 32",
        .{name},
    );

    const on = platform(io, gpa, o.platform);
    // A form with no DHCP client is given the hypervisor's own network in
    // its config tar, Lima's as make lima's template gives it on the
    // command line, or slirp's under bhyve, unless the flags or --config
    // DIR give one.
    const on_lima = std.mem.eql(u8, on, "lima");
    // A Firecracker machine's address is its tap's, on the kernel command
    // line; --dns alone is taken there, not in the tar.
    var fc_dns: ?[]const u8 = null;
    if (std.mem.eql(u8, on, "firecracker")) {
        if (o.ip != null or o.gw != null) return why.refuse(
            "--ip and --gw: a Firecracker machine's address is its tap's, 172.16.0.0/16",
            .{},
        );
        fc_dns = o.dns;
        o.dns = null;
    }
    const dhcp = !(on_lima or std.mem.eql(u8, on, "bhyve")) or try hasDhcp(io, gpa, o.form, why);
    if (!dhcp and o.ip == null and o.gw == null and o.dns == null) {
        const given = if (o.config) |d|
            if (Dir.cwd().access(io, try std.fs.path.join(gpa, &.{ d, "network" }), .{}))
                true
            else |_|
                false
        else
            false;
        if (!given) {
            o.ip = if (on_lima) lima.user_ip else bhyve.user_ip;
            o.gw = if (on_lima) lima.user_gw else bhyve.user_gw;
            o.dns = if (on_lima) lima.user_gw else bhyve.user_dns;
        }
    }
    const entries = try gather(io, gpa, iface, o, why);
    const tar = try writeTar(gpa, entries);
    if (target(on)) |t| if (misfit(
        entries,
        tar.len,
        t,
    )) |r| return why.refuse("not for {s}: {s}", .{ on, r });

    if (std.mem.eql(u8, on, "qemu")) {
        if (o.platform == null) say(
            io,
            "no Lima here: {s} boots under QEMU, in the foreground, and is not kept",
            .{name},
        );
        const ab = try appBuild(io, gpa, o.form, hostArch(), o.app, why);
        return bootHere(io, gpa, o.form, false, entries, ab.app, why);
    }
    if (std.mem.eql(u8, on, "gcp")) return createGcp(io, gpa, o, name, tar, w, why);
    if (std.mem.eql(u8, on, "aws")) return createAws(io, gpa, o, name, tar, w, why);
    if (std.mem.eql(u8, on, "azure")) return createAzure(io, gpa, o, name, entries, tar, w, why);
    if (std.mem.eql(u8, on, "bhyve")) return createBhyve(io, gpa, o, name, tar, w, why);
    if (std.mem.eql(u8, on, "proxmox")) return createProxmox(io, gpa, o, name, tar, w, why);
    if (std.mem.eql(u8, on, "firecracker"))
        return createFirecracker(io, gpa, o, name, tar, fc_dns, w, why);
    if (o.arch != null or o.size != null)
        return why.refuse(
            "--arch and --size are for --on gcp and aws: {s} runs this machine's arch",
            .{on},
        );
    if (!std.mem.eql(u8, on, "lima"))
        return why.refuse(
            "--on {s} is not built yet: werewolf build and werewolf pack make its two files",
            .{on},
        );
    if (!lima.installed(
        io,
        gpa,
    )) return why.refuse("--on lima: no limactl here, or not macOS (brew install lima)", .{});
    const arch = hostArch();
    const dir = try machineDir(gpa, arch, name);
    try Dir.cwd().createDirPath(io, dir);
    const m = lima.mac(name);
    var managed = try limaManages(io, gpa, o.form, why);
    if (try lima.exists(io, gpa, name)) {
        if (o.app != null) return why.refuse(
            "{s} exists, and an application is in the image: werewolf delete {s}, then create",
            .{ name, name },
        );
        managed = try reconfigure(io, gpa, name, o.form, dir, tar, why);
    } else {
        const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
        const tar_path = try gpa.print("{s}/config.tar", .{dir});
        const config_disk = try gpa.print("{s}-config", .{name});
        try writePrivate(io, gpa, tar_path, tar, why);
        var template: []const u8 = undefined;
        if (managed) {
            // As make lima boots one: on Lima's network, with its user,
            // from the image and the template make writes, so Lima manages
            // it, its ssh and its stop included.
            const made = try gpa.print("build/{s}/{s}/lima.yaml", .{ arch, ab.out });
            try run(io, why, &.{
                make_cmd,
                "--no-print-directory",
                try gpa.print("FORM={s}", .{o.form}),
                "DEV=",
                ab.app,
                "image",
                try gpa.print("build/{s}/disk.img", .{arch}),
                made,
            });
            const base = Dir.cwd().readFileAlloc(io, made, gpa, .limited(1 << 20)) catch |err|
                return why.refuse("{s}: {s}", .{ made, @errorName(err) });
            template = try lima.managedTemplate(gpa, base, o.form, config_disk);
        } else {
            var cwd_buf: [Dir.max_path_bytes]u8 = undefined;
            const cwd = cwd_buf[0..try std.process.currentPath(io, &cwd_buf)];
            const disk = try gpa.print("{s}/{s}/disk.img", .{ cwd, dir });
            try run(io, why, &.{
                make_cmd,
                "--no-print-directory",
                try gpa.print("FORM={s}", .{o.form}),
                "DEV=",
                ab.app,
                "disk",
                try gpa.print("DISK={s}", .{disk}),
                if (dhcp)
                    try gpa.print("DISK_ARGS=werewolf.mac={s} console=hvc0", .{m})
                else
                    "DISK_ARGS=console=hvc0",
            });
            template = try lima.template(
                gpa,
                o.form,
                arch,
                disk,
                if (dhcp) &m else null,
                config_disk,
            );
        }
        // A disk of that name left by a machine deleted with limactl alone.
        _ = std.process.run(
            gpa,
            io,
            .{ .argv = &.{ "limactl", "disk", "delete", config_disk } },
        ) catch {};
        try run(io, why, &.{ "limactl", "disk", "import", config_disk, tar_path });
        const yaml = try gpa.print("{s}/lima.yaml", .{dir});
        try writePrivate(io, gpa, yaml, template, why);
        try run(io, why, &.{ "limactl", "create", "--name", name, "--tty=false", yaml });
    }

    if (managed) {
        // Lima waits for its ssh and boot scripts, then for nothing else;
        // the machine is reached through Lima's ssh forward.
        try run(io, why, &.{ "limactl", "start", "--tty=false", name });
        const r = try std.process.run(gpa, io, .{
            .argv = &.{ "limactl", "list", name, "--format", "{{.SSHLocalPort}}" },
        });
        const port = std.mem.trim(u8, r.stdout, " \n");
        try w.print("{s}\t127.0.0.1:{s}\t{s}\n", .{ name, port, o.form });
        return;
    }

    // limactl start waits for ssh, which never answers; the lease says the
    // machine is up, or with no DHCP, its console, and the VM outlives the
    // start.
    const before = lima.previous(io, gpa, &m);
    const console_log = try gpa.print("{s}/serialv.log", .{
        try lima.dir(io, gpa, name) orelse return why.refuse("no machine {s}", .{name}),
    });
    const seen = if (Dir.cwd().statFile(io, console_log, .{})) |st| st.size else |_| 0;
    const log = try Dir.cwd().createFile(io, try gpa.print("{s}/start.log", .{dir}), .{});
    defer log.close(io);
    var starter = std.process.spawn(io, .{
        .argv = &.{ "limactl", "start", "--tty=false", name },
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    }) catch |err| return why.refuse("limactl start: {s}", .{@errorName(err)});
    if (!dhcp) {
        say(io, "{s}: waiting for it to boot", .{name});
        const up = try awaitUp(io, gpa, console_log, seen);
        starter.kill(io);
        if (!up) return why.refuse(
            "{s} is not up after 3 minutes: werewolf console {s}",
            .{ name, name },
        );
        say(
            io,
            "{s} is up on Lima's own network, which this Mac does not reach: {s} has no " ++
                "DHCP client for vzNAT. Its console: werewolf console {s}",
            .{ name, o.form, name },
        );
        try w.print("{s}\t-\t{s}\n", .{ name, o.form });
        return;
    }
    say(io, "{s}: waiting for its address", .{name});
    const ip = try lima.awaitAddress(io, gpa, &m, before);
    starter.kill(io);
    const addr = ip orelse
        return why.refuse(
            "{s} has no address after 3 minutes: werewolf console {s}",
            .{ name, name },
        );
    try w.print("{s}\t{s}\t{s}\n", .{ name, addr, o.form });
}

/// How long create waits for a machine here to say it is up, and how
/// often it looks: a machine is up about a second after it starts, so a
/// coarser look would make create the slower of the two.
const up_ms = 180_000;
const up_poll_ms = 50;

/// Wait for init's "werewolf: up in" on the console, past the first seen
/// bytes of its log: for a machine whose address says nothing, or that
/// has none this host reaches. Each look reads what follows seen into one
/// buffer, up to its size, so frequent looks cost no memory; a boot says
/// it is up well within its first MiB.
fn awaitUp(io: Io, gpa: Allocator, log: []const u8, seen: u64) !bool {
    const buf = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(buf);
    var waited: u32 = 0;
    while (waited < up_ms) : (waited += up_poll_ms) {
        if (Dir.cwd().openFile(io, log, .{})) |f| {
            defer f.close(io);
            // A log shorter than before was started again.
            const len = f.length(io) catch 0;
            const from = if (seen <= len) seen else 0;
            const n = f.readPositionalAll(io, buf, from) catch 0;
            if (std.mem.find(u8, buf[0..n], "werewolf: up in ") != null) return true;
        } else |_| {}
        try io.sleep(.fromMilliseconds(up_poll_ms), .awake);
    }
    return false;
}

/// create --on bhyve (bhyve.zig): the machine's disk, built for it, and
/// its config tar beside it, in its directory with its form's name; bhyve
/// under werewolf's supervisor, detached by daemon(8), as root, its
/// console on console.log there; then the console says it is up, and the
/// forwards say where it is reached. A machine that exists, of the same
/// form, takes a new config with a hard stop, since nothing asks a
/// werewolf machine to shut down; its boot disk and /data stay.
fn createBhyve(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    if (o.arch != null or o.size != null) return why.refuse(
        "--arch and --size are for --on gcp and aws: bhyve runs this machine's arch",
        .{},
    );
    if (!bhyve.installed(io))
        return why.refuse("--on bhyve: FreeBSD on x86_64, with vmm loaded (kldload vmm)", .{});
    Dir.cwd().access(io, bhyve.firmware, .{}) catch
        return why.refuse("no {s}: pkg install bhyve-firmware", .{bhyve.firmware});
    const root = bhyve.asRoot(io) catch
        return why.refuse("bhyve needs root, and there is no doas or sudo: pkg install doas", .{});
    const arch = hostArch();
    const dir = try machineDir(gpa, arch, name);
    try Dir.cwd().createDirPath(io, dir);
    var cwd_buf: [Dir.max_path_bytes]u8 = undefined;
    const cwd = cwd_buf[0..try std.process.currentPath(io, &cwd_buf)];
    const disk = try gpa.print("{s}/{s}/disk.img", .{ cwd, dir });
    const config = try gpa.print("{s}/{s}/config.tar", .{ cwd, dir });
    const log = try gpa.print("{s}/{s}/console.log", .{ cwd, dir });
    const form_file = try gpa.print("{s}/form", .{dir});
    const was = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, form_file, gpa, .limited(256)) catch "",
        " \n",
    );
    if (was.len > 0) try reconfigurable(o, name, was, "bhyve", why);
    if (try bhyve.exists(io, gpa, name)) {
        say(
            io,
            "{s}: replacing its config, with a hard stop: bhyve cannot ask it to shut down",
            .{name},
        );
        try run(
            io,
            why,
            try std.mem.concat(gpa, []const u8, &.{ root, try bhyve.destroy(gpa, name) }),
        );
    }
    if (was.len == 0) {
        const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
        try run(io, why, &.{
            make_cmd,
            "--no-print-directory",
            try gpa.print("FORM={s}", .{o.form}),
            "DEV=",
            ab.app,
            "disk",
            try gpa.print("DISK={s}", .{disk}),
            "DISK_ARGS=",
        });
        try writePrivate(io, gpa, form_file, o.form, why);
    }
    try writePrivate(io, gpa, config, tar, why);
    const fwds = try bhyve.forwards(gpa, name, try listens(io, gpa, o.form, why));
    // The log is made now, as this user, so daemon appends to it as root
    // and delete can still remove it.
    const f = Dir.cwd().createFile(
        io,
        log,
        .{ .truncate = false, .permissions = .fromMode(0o600) },
    ) catch |err| return why.refuse("{s}: {s}", .{ log, @errorName(err) });
    f.close(io);
    const seen = if (Dir.cwd().statFile(io, log, .{})) |st| st.size else |_| 0;
    var self_buf: [Dir.max_path_bytes]u8 = undefined;
    const self = self_buf[0..try std.process.executablePath(io, &self_buf)];
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, root);
    try argv.appendSlice(gpa, &.{ "daemon", "-f", "-o", log, self, "_bhyve", name, config });
    try argv.appendSlice(gpa, try bhyve.argv(gpa, name, disk, config, fwds));
    try run(io, why, argv.items);
    say(io, "{s}: waiting for it to boot", .{name});
    if (!try awaitUp(io, gpa, log, seen)) return why.refuse(
        "{s} is not up after 3 minutes: werewolf console {s} --on bhyve",
        .{ name, name },
    );
    for (fwds) |fw| say(
        io,
        "{s}: 127.0.0.1:{d} reaches its port {d}",
        .{ name, fw.host, fw.guest },
    );
    if (fwds.len == 0) say(
        io,
        "{s} listens on no port, so nothing reaches it; its console: werewolf console {s} --on " ++
            "bhyve",
        .{ name, name },
    );
    try w.print("{s}\t{s}\t{s}\n", .{
        name,
        if (fwds.len > 0) try gpa.print("127.0.0.1:{d}", .{fwds[0].host}) else "-",
        o.form,
    });
}

/// create --on firecracker (firecracker.zig): the form's image, built as
/// make run boots it; its data disk, config tar and Firecracker's
/// configuration in its directory; its network, as root; Firecracker
/// under werewolf's supervisor, detached by setsid, its console on
/// console.log there; then the console says it is up. A machine that
/// exists, of the same form, takes a new config with a hard stop, since
/// nothing asks a werewolf machine to shut down; its data disk stays, and
/// its configuration, so --dns is read at the first create alone.
fn createFirecracker(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    dns_given: ?[]const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    if (!firecracker.installed(io, gpa)) return why.refuse(
        "--on firecracker: Linux with /dev/kvm, and firecracker on the PATH (tools/install-deps)",
        .{},
    );
    if (o.arch != null or o.size != null) return why.refuse(
        "--arch and --size are for --on gcp and aws: Firecracker runs this machine's arch",
        .{},
    );
    const root = firecracker.asRoot(io) catch
        return why.refuse("the machine's tap device needs root, and there is no sudo or doas", .{});
    const user = environ.get("USER") orelse
        return why.refuse("no USER in the environment, whose tap device the machine's is", .{});
    const arch = hostArch();
    const dir = try machineDir(gpa, arch, name);
    try Dir.cwd().createDirPath(io, dir);
    var cwd_buf: [Dir.max_path_bytes]u8 = undefined;
    const cwd = cwd_buf[0..try std.process.currentPath(io, &cwd_buf)];
    const form_file = try gpa.print("{s}/form", .{dir});
    const was = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, form_file, gpa, .limited(256)) catch "",
        " \n",
    );
    if (was.len > 0) try reconfigurable(o, name, was, "firecracker", why);
    if (firecracker.running(io, gpa, dir)) |pid| {
        say(io, "{s}: replacing its config, with a hard stop", .{name});
        try firecracker.stop(io, gpa, dir, pid, why);
    }
    const n = try firecracker.net(gpa, name);
    if (was.len == 0) {
        const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
        try run(io, why, &.{
            make_cmd,
            "--no-print-directory",
            try gpa.print("FORM={s}", .{o.form}),
            "DEV=",
            ab.app,
            "slot",
            try firecracker.kernelPath(gpa, arch),
        });
        const dns = dns_given orelse firecracker.hostDns(io, gpa) orelse return why.refuse(
            "--dns ADDR: this host's resolvers are all on loopback, which the machine cannot reach",
            .{},
        );
        const image_args = std.mem.trim(u8, Dir.cwd().readFileAlloc(
            io,
            try gpa.print("build/{s}/{s}/meta/usr/share/werewolf/cmdline", .{ arch, ab.out }),
            gpa,
            .limited(4096),
        ) catch |err| return why.refuse(
            "{s}: no cmdline in its image: {s}",
            .{ o.form, @errorName(err) },
        ), " \n");
        const data = try gpa.print("{s}/{s}/data.img", .{ cwd, dir });
        try run(io, why, &.{ "truncate", "-s", "8192M", data });
        try writePrivate(io, gpa, try gpa.print("{s}/vm.json", .{dir}), try firecracker.config(
            gpa,
            try gpa.print("{s}/{s}", .{ cwd, try firecracker.kernelPath(gpa, arch) }),
            try gpa.print("{s}/build/{s}/{s}/slot/initramfs.zst", .{ cwd, arch, ab.out }),
            try firecracker.bootArgs(gpa, image_args, n, dns),
            data,
            try gpa.print("{s}/{s}/config.tar", .{ cwd, dir }),
            try gpa.print("{s}/build/{s}/{s}/slot/root.erofs", .{ cwd, arch, ab.out }),
            try gpa.print("{s}/{s}/firecracker.log", .{ cwd, dir }),
            n,
        ), why);
        try writePrivate(io, gpa, form_file, o.form, why);
    }
    try writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), tar, why);
    const log = try gpa.print("{s}/{s}/console.log", .{ cwd, dir });
    const seen = if (Dir.cwd().statFile(io, log, .{})) |st| st.size else |_| 0;
    try firecracker.networkUp(io, gpa, root, n, user, why);
    var self_buf: [Dir.max_path_bytes]u8 = undefined;
    const self = self_buf[0..try std.process.executablePath(io, &self_buf)];
    // The supervisor keeps the console itself; nothing of its own is said
    // anywhere else.
    var starter = std.process.spawn(io, .{
        .argv = &.{ "setsid", "-f", self, "_firecracker", try gpa.print("{s}/{s}", .{ cwd, dir }) },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch |err| return why.refuse("setsid: {s}", .{@errorName(err)});
    _ = starter.wait(io) catch {};
    say(io, "{s}: waiting for it to boot", .{name});
    if (!try awaitUp(io, gpa, log, seen)) return why.refuse(
        "{s} is not up after 3 minutes: werewolf console {s} --on firecracker",
        .{ name, name },
    );
    try w.print("{s}\t{s}\t{s}\n", .{ name, n.guest, o.form });
}

/// create --on proxmox (proxmox.zig): the release's disk on the node,
/// uploaded once; a VM of it with the config tar imported as its second
/// disk; or, for a VM that exists, the same form with a new config, after
/// a hard stop. The console, a file on the node, says when it is up, and
/// what address DHCP gave it.
fn createProxmox(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    const p = try proxmox.place(environ, why);
    const arch = o.arch orelse "x86_64";
    if (!std.mem.eql(u8, arch, "x86_64"))
        return why.refuse("--on proxmox: x86_64 machines only; its nodes are", .{});
    if (o.size != null) return why.refuse("--size is for --on gcp and aws", .{});
    const dir = try machineDir(gpa, arch, name);
    try Dir.cwd().createDirPath(io, dir);
    const tar_path = try gpa.print("{s}/config.tar", .{dir});
    try writePrivate(io, gpa, tar_path, tar, why);
    var vmid: []const u8 = undefined;
    if (proxmox.find(io, gpa, p, name)) |m| {
        try reconfigurable(o, name, m.form, "proxmox", why);
        say(io, "{s}: replacing the config of VM {s} on {s}, with a hard stop", .{
            name,
            m.vmid,
            p.host,
        });
        try proxmox.upload(io, gpa, p, tar_path, name, why);
        try proxmox.reconfigure(io, gpa, p, m, name, why);
        vmid = m.vmid;
    } else {
        const disk = try releaseDisk(io, gpa, o, arch, why);
        const image = try proxmox.ensureImage(io, gpa, p, o.form, arch, disk, why);
        vmid = proxmox.nextId(io, gpa, p) orelse
            return why.refuse("{s}: pvesh gave no next VMID", .{p.host});
        try proxmox.upload(io, gpa, p, tar_path, name, why);
        say(io, "{s}: making VM {s} on {s}", .{ name, vmid, p.host });
        try proxmox.create(io, gpa, p, vmid, name, o.form, image, why);
    }
    const seen = proxmox.logSize(io, gpa, p, name);
    try proxmox.start(io, gpa, p, vmid, why);
    say(io, "{s}: waiting for it to boot", .{name});
    switch (try proxmox.awaitUp(io, gpa, p, name, seen)) {
        .up => {},
        .panic => return why.refuse(
            "{s} panicked: werewolf console {s} --on proxmox",
            .{ name, name },
        ),
        .late => return why.refuse(
            "{s} not up after 3 minutes: werewolf console {s} --on proxmox",
            .{ name, name },
        ),
    }
    const addr = proxmox.address(proxmox.console(io, gpa, p, name, seen) orelse "") orelse "-";
    if (std.mem.eql(u8, addr, "-")) say(
        io,
        "{s}: its console reports no DHCP lease: its address is the static one in its tar, if any",
        .{name},
    );
    try w.print("{s}\t{s}\t{s}\n", .{ name, addr, o.form });
}

/// The TCP ports form listens on, as its chain's net declares them
/// (listen tcp/80 tcp/443), in order, once each.
fn listens(io: Io, gpa: Allocator, form: []const u8, why: *Why) ![]const u16 {
    var ports: std.ArrayList(u16) = .empty;
    for (try chain(io, gpa, form, why)) |f|
        for (try f.items(gpa, "net")) |line| try listenPorts(gpa, line, &ports);
    return ports.items;
}

/// Add the TCP ports a net line names, when it is a listen line, to
/// ports, once each.
fn listenPorts(gpa: Allocator, line: []const u8, ports: *std.ArrayList(u16)) !void {
    var words = std.mem.tokenizeAny(u8, line, " \t\r");
    if (!std.mem.eql(u8, words.next() orelse return, "listen")) return;
    while (words.next()) |word| {
        if (!std.mem.startsWith(u8, word, "tcp/")) continue;
        const p = std.fmt.parseInt(u16, word["tcp/".len..], 10) catch continue;
        if (std.mem.findScalar(u16, ports.items, p) == null) try ports.append(gpa, p);
    }
}

/// Whether form takes an address by DHCP: whether its chain runs
/// dhcp-client, as its form.yaml's programs say.
fn hasDhcp(io: Io, gpa: Allocator, form: []const u8, why: *Why) !bool {
    for (try chain(io, gpa, form, why)) |f|
        for (try f.items(gpa, "programs")) |p| if (std.mem.eql(u8, p, "dhcp-client")) return true;
    return false;
}

/// Whether Lima can manage a machine of form: one that answers Lima's ssh
/// as Lima's user and runs its readiness probes, which want sshd and bash.
/// Any other starts on vzNAT, unmanaged, and is stopped hard.
fn limaManages(io: Io, gpa: Allocator, form: []const u8, why: *Why) !bool {
    var sshd = false;
    var bash = false;
    for (try chain(io, gpa, form, why)) |f| {
        const text = try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/apko.yaml", .{f.dir}),
            gpa,
            .limited(256 << 10),
        );
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var words = std.mem.tokenizeAny(u8, line, " \t\r");
            if (!std.mem.eql(u8, words.next() orelse continue, "-")) continue;
            const pkg = words.next() orelse continue;
            if (std.mem.eql(u8, pkg, "openssh-server")) sshd = true;
            if (std.mem.eql(u8, pkg, "bash")) bash = true;
        }
    }
    return sshd and bash;
}

/// Another create of a machine that exists: the same form, a new config.
/// The config disk Lima attached is the tar's bytes, so they are replaced,
/// with the machine stopped; its boot disk and /data stay. Lima's stop
/// request reaches no werewolf machine yet, so the stop is a hard one.
fn reconfigure(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    form: []const u8,
    dir: []const u8,
    tar: []const u8,
    why: *Why,
) !bool {
    const d = try lima.dir(io, gpa, name) orelse return why.refuse("no machine {s}", .{name});
    const yaml = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/lima.yaml", .{d}),
        gpa,
        .limited(1 << 20),
    ) catch |err|
        return why.refuse("{s}/lima.yaml: {s}", .{ d, @errorName(err) });
    const managed = lima.isManaged(yaml);
    const was = lima.formOf(yaml) orelse
        return why.refuse("{s} was not made by werewolf create; it is Lima's alone", .{name});
    if (!std.mem.eql(u8, was, form)) return why.refuse(
        "{s} runs {s}, not {s}: another form is another disk; werewolf delete {s}, then create",
        .{ name, was, form, name },
    );
    if (!try lima.running(io, gpa, name)) {
        say(io, "{s}: replacing its config", .{name});
    } else if (managed) {
        say(io, "{s}: replacing its config; stopping it", .{name});
        try run(io, why, &.{ "limactl", "stop", name });
    } else {
        say(
            io,
            "{s}: replacing its config, with a hard stop: Lima cannot ask it to shut down",
            .{name},
        );
        try run(io, why, &.{ "limactl", "stop", "-f", name });
    }
    const parent = std.fs.path.dirname(d) orelse return why.refuse("{s}: no Lima home", .{d});
    try writePrivate(
        io,
        gpa,
        try gpa.print("{s}/_disks/{s}-config/datadisk", .{ parent, name }),
        tar,
        why,
    );
    try writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), tar, why);
    return managed;
}

/// A machine in a cloud: its architecture, --arch or this host's, where
/// create keeps its files, and its config tar in base64, as the clouds
/// take user data, kept private there.
const Cloud = struct { arch: []const u8, dir: []const u8, b64: []const u8 };

fn cloudMachine(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    why: *Why,
) !Cloud {
    const arch = o.arch orelse hostArch();
    if (!std.mem.eql(u8, arch, "aarch64") and !std.mem.eql(u8, arch, "x86_64"))
        return why.refuse("--arch {s}: aarch64 or x86_64", .{arch});
    const dir = try machineDir(gpa, arch, name);
    try Dir.cwd().createDirPath(io, dir);
    const b64 = try gpa.print("{s}/config.b64", .{dir});
    const encoded = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(tar.len));
    try writePrivate(io, gpa, b64, std.base64.standard.Encoder.encode(encoded, tar), why);
    return .{ .arch = arch, .dir = dir, .b64 = b64 };
}

/// Whether a machine that exists, made of the form was ("" if not made by
/// create), may take a new config: the same form, and no --app, since an
/// application is in the image.
fn reconfigurable(o: Options, name: []const u8, was: []const u8, on: []const u8, why: *Why) !void {
    if (o.app != null) return why.refuse(
        "{s} exists, and an application is in the image: werewolf delete {s} --on {s}, then create",
        .{ name, name, on },
    );
    if (was.len == 0) return why.refuse(
        "{s} was not made by werewolf create; it is {s}'s alone",
        .{ name, on },
    );
    if (!std.mem.eql(u8, was, o.form)) return why.refuse(
        "{s} runs {s}, not {s}: another form is another image; werewolf delete {s} --on {s}, " ++
            "then create",
        .{ name, was, o.form, name, on },
    );
}

/// The release's disk.qcow2 of the form, with --app's application, built
/// if stale.
fn releaseDisk(io: Io, gpa: Allocator, o: Options, arch: []const u8, why: *Why) ![]const u8 {
    const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
    const disk = try gpa.print("build/{s}/{s}/disk.qcow2", .{ arch, ab.out });
    try run(io, why, &.{
        make_cmd,
        "--no-print-directory",
        try gpa.print("FORM={s}", .{o.form}),
        try gpa.print("ARCH={s}", .{arch}),
        "DEV=",
        ab.app,
        disk,
    });
    return disk;
}

/// create --on gcp: the release's disk as an image, made once; a VM of
/// it with the config as user-data; or, for a VM that exists, the same
/// form with a new config, and a restart.
fn createGcp(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    const p = try gcp.place(io, gpa, why);
    const c = try cloudMachine(io, gpa, o, name, tar, why);
    if (gcp.formOf(io, gpa, p, name)) |was| {
        try reconfigurable(o, name, was, "gcp", why);
        say(
            io,
            "{s}: replacing its config, and restarting it; its address changes unless it is static",
            .{name},
        );
        try gcp.reconfigure(io, gpa, p, name, c.b64, why);
    } else {
        const disk = try releaseDisk(io, gpa, o, c.arch, why);
        const image = try gcp.ensureImage(io, gpa, p, o.form, c.arch, disk, c.dir, why);
        say(io, "{s}: starting it in {s}", .{ name, p.zone });
        try gcp.create(io, gpa, p, name, o.form, c.arch, o.size, image, c.b64, why);
    }
    switch (try gcp.awaitUp(io, gpa, p, name)) {
        .up => {},
        .panic => return why.refuse("{s} panicked: werewolf console {s} --on gcp", .{ name, name }),
        .late => return why.refuse(
            "{s} not up after 5 minutes: werewolf console {s} --on gcp",
            .{ name, name },
        ),
    }
    try w.print("{s}\t{s}\t{s}\n", .{ name, gcp.address(io, gpa, p, name) orelse "?", o.form });
}

/// create --on aws: the release's disk as an AMI, imported once; an
/// instance of it with the config as user data, in a security group of
/// its own that lets nothing in; or, for an instance that exists, the same
/// form with a new config, and a restart.
fn createAws(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    const p = try aws.place(io, gpa, why);
    const c = try cloudMachine(io, gpa, o, name, tar, why);
    var id: []const u8 = undefined;
    if (aws.find(io, gpa, p, name)) |i| {
        try reconfigurable(o, name, i.form, "aws", why);
        say(
            io,
            "{s}: replacing its config, and restarting it; its address changes unless it is " ++
                "elastic",
            .{name},
        );
        try aws.reconfigure(io, gpa, p, i.id, c.b64, why);
        id = i.id;
    } else {
        const disk = try releaseDisk(io, gpa, o, c.arch, why);
        const ami = try aws.ensureImage(io, gpa, p, o.form, c.arch, disk, c.dir, why);
        say(io, "{s}: starting it in {s}", .{ name, p.region });
        id = try aws.create(io, gpa, p, name, o.form, c.arch, o.size, ami, c.b64, why);
        say(
            io,
            "{s}: its security group, werewolf-{s}, lets nothing in: aws ec2 " ++
                "authorize-security-group-ingress --group-name werewolf-{s} --protocol tcp " ++
                "--port PORT --cidr ADDRESS/32",
            .{ name, name, name },
        );
    }
    switch (try aws.awaitUp(io, gpa, p, id)) {
        .up => {},
        .panic => return why.refuse("{s} panicked: werewolf console {s} --on aws", .{ name, name }),
        .late => return why.refuse(
            "{s} not up after 5 minutes: werewolf console {s} --on aws",
            .{ name, name },
        ),
    }
    try w.print("{s}\t{s}\t{s}\n", .{ name, aws.address(io, gpa, p, id) orelse "?", o.form });
}

/// create --on azure (azure.zig): the release's disk as a managed disk,
/// uploaded once; a specialized VM on a copy of it, with the config tar
/// as its userData; or, for a VM that exists, the same form with a new
/// config, and a restart.
fn createAzure(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    entries: []const Entry,
    tar: []const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    // az vm create reads user data as text (azure.carried), so a file it
    // would change is refused here, named, rather than changed there.
    for (entries) |e| if (!azure.carried(e.data)) return why.refuse(
        "{s}: Azure's CLI carries user data as text, and this file has a carriage return " ++
            "or a byte past ASCII, which it would change; give it as text (a key in hex)",
        .{e.path},
    );
    const p = try azure.place(io, gpa, why);
    const c = try cloudMachine(io, gpa, o, name, tar, why);
    // az reads the tar from a file and encodes it in base64 itself.
    const tar_path = try gpa.print("{s}/config.tar", .{c.dir});
    try writePrivate(io, gpa, tar_path, tar, why);
    if (azure.find(io, gpa, p, name)) |vm| {
        try reconfigurable(o, name, vm.form, "azure", why);
        say(io, "{s}: replacing its config, and restarting it", .{name});
        const before = if (azure.console(io, gpa, p, name)) |text| azure.mark(text) else "";
        try azure.reconfigure(io, gpa, p, name, tar, c.dir, why);
        return azureUp(io, gpa, p, name, o.form, before, w, why);
    }
    const disk = try releaseDisk(io, gpa, o, c.arch, why);
    const image = try azure.ensureImage(io, gpa, p, o.form, c.arch, disk, c.dir, why);
    say(io, "{s}: starting it in {s}, {s}", .{ name, p.group, p.location });
    try azure.create(io, gpa, p, name, o.form, c.arch, o.size, image, tar_path, why);
    say(
        io,
        "{s}: its security group, {s}NSG, lets nothing in: az network nsg rule create -g {s} " ++
            "--nsg-name {s}NSG -n ssh --priority 100 --destination-port-ranges 22 " ++
            "--source-address-prefixes ADDRESS/32",
        .{ name, name, p.group, name },
    );
    return azureUp(io, gpa, p, name, o.form, "", w, why);
}

/// Wait for an Azure machine's boot, in its console after before, its end
/// when the boot began, then print where it is.
fn azureUp(
    io: Io,
    gpa: Allocator,
    p: azure.Place,
    name: []const u8,
    form: []const u8,
    before: []const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    switch (try azure.awaitUp(io, gpa, p, name, before)) {
        .up => {},
        .panic => return why.refuse(
            "{s} panicked: werewolf console {s} --on azure",
            .{ name, name },
        ),
        .late => return why.refuse(
            "{s} not up after 5 minutes: werewolf console {s} --on azure",
            .{ name, name },
        ),
    }
    try w.print("{s}\t{s}\t{s}\n", .{ name, azure.address(io, gpa, p, name) orelse "?", form });
}

/// upload DISK --on gcp|aws|azure: a release's FORM-ARCH-disk.qcow2 made a
/// GCP image, an AMI or an Azure managed disk, as create makes one, for a
/// VM made some other way (Terraform, the console). Prints the image's
/// name, or the AMI's id. An Azure disk serves one VM, so make a copy of
/// it for each (az disk create --source).
fn upload(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const clouds = [_][]const u8{ "gcp", "aws", "azure" };
    const known = for (clouds) |c| {
        if (args.len == 3 and std.mem.eql(u8, args[2], c)) break true;
    } else false;
    if (!known or !std.mem.eql(u8, args[1], "--on"))
        return why.refuse("upload DISK --on gcp|aws|azure", .{});
    const disk = args[0];
    const base = std.fs.path.basename(disk);
    const stem = if (std.mem.endsWith(u8, base, "-disk.qcow2"))
        base[0 .. base.len - "-disk.qcow2".len]
    else
        return why.refuse(
            "{s}: a release's FORM-ARCH-disk.qcow2, as werewolf build makes one",
            .{disk},
        );
    const dash = std.mem.findScalarLast(
        u8,
        stem,
        '-',
    ) orelse return why.refuse("{s}: no FORM-ARCH", .{disk});
    const arch = stem[dash + 1 ..];
    if (!std.mem.eql(u8, arch, "aarch64") and !std.mem.eql(u8, arch, "x86_64"))
        return why.refuse("{s}: arch {s} is neither aarch64 nor x86_64", .{ disk, arch });
    const work = std.fs.path.dirname(disk) orelse ".";
    const image = if (std.mem.eql(u8, args[2], "azure"))
        try azure.ensureImage(
            io,
            gpa,
            try azure.place(io, gpa, why),
            stem[0..dash],
            arch,
            disk,
            work,
            why,
        )
    else if (std.mem.eql(u8, args[2], "aws"))
        try aws.ensureImage(
            io,
            gpa,
            try aws.place(io, gpa, why),
            stem[0..dash],
            arch,
            disk,
            work,
            why,
        )
    else
        try gcp.ensureImage(
            io,
            gpa,
            try gcp.place(io, gpa, why),
            stem[0..dash],
            arch,
            disk,
            work,
            why,
        );
    var out = Io.File.stdout().writerStreaming(io, &.{});
    try out.interface.print("{s}\n", .{image});
}

/// delete and console: NAME, and --on.
fn machineArgs(
    gpa: Allocator,
    io: Io,
    args: []const []const u8,
    why: *Why,
) !struct { []const u8, []const u8 } {
    var name: ?[]const u8 = null;
    var on: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--on") and i + 1 < args.len) {
            i += 1;
            on = args[i];
        } else if (args[i].len > 0 and args[i][0] != '-' and name == null) {
            name = args[i];
        } else return why.refuse(
            "{s}: NAME [--on lima|bhyve|firecracker|proxmox|gcp|aws|azure]",
            .{args[i]},
        );
    }
    const n = name orelse return why.refuse("name the machine\n{s}", .{usage});
    if (!isMachineName(n)) return why.refuse("{s}: not a machine's name", .{n});
    const p = platform(io, gpa, on);
    for ([_][]const u8{ "lima", "bhyve", "firecracker", "proxmox", "gcp", "aws", "azure" }) |keeper|
        if (std.mem.eql(u8, p, keeper)) return .{ n, p };
    return why.refuse("--on {s}: QEMU keeps no machine; it boots one in the foreground", .{p});
}

fn delete(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const name, const on = try machineArgs(gpa, io, args, why);
    if (std.mem.eql(u8, on, "gcp")) {
        // The machine and its disk, not the image, which others may share.
        const p = try gcp.place(io, gpa, why);
        if (gcp.formOf(io, gpa, p, name) != null) try gcp.delete(io, gpa, p, name, why);
    } else if (std.mem.eql(u8, on, "aws")) {
        // The instance, its volume and its security group, not the AMI.
        const p = try aws.place(io, gpa, why);
        try aws.delete(io, gpa, p, name, aws.find(io, gpa, p, name), why);
    } else if (std.mem.eql(u8, on, "azure")) {
        // The VM, its disk, NIC and network, not the image.
        try azure.delete(io, gpa, try azure.place(io, gpa, why), name, why);
    } else if (std.mem.eql(u8, on, "proxmox")) {
        // The VM and its disks, not the image, which others may share.
        const p = try proxmox.place(environ, why);
        if (proxmox.find(io, gpa, p, name)) |m| try proxmox.delete(io, gpa, p, m, name, why);
        Dir.cwd().deleteTree(io, try machineDir(gpa, "x86_64", name)) catch {};
    } else if (std.mem.eql(u8, on, "firecracker")) {
        // Its tar first, so the supervisor runs it no more; then its
        // Firecracker, killed; then its network, as root.
        const dir = try machineDir(gpa, hostArch(), name);
        Dir.cwd().deleteFile(io, try gpa.print("{s}/config.tar", .{dir})) catch {};
        if (firecracker.running(io, gpa, dir)) |pid| try firecracker.stop(io, gpa, dir, pid, why);
        if (firecracker.asRoot(io)) |root|
            firecracker.networkDown(io, gpa, root, try firecracker.net(gpa, name))
        else |_|
            say(io, "{s}: no sudo or doas, so its tap device and rules stay", .{name});
    } else if (std.mem.eql(u8, on, "bhyve")) {
        // Destroyed under its bhyve, which exits, and its supervisor with it.
        if (try bhyve.exists(io, gpa, name)) {
            const root = bhyve.asRoot(io) catch
                return why.refuse("bhyve needs root, and there is no doas or sudo", .{});
            try run(
                io,
                why,
                try std.mem.concat(gpa, []const u8, &.{ root, try bhyve.destroy(gpa, name) }),
            );
        }
    } else {
        if (try lima.exists(io, gpa, name)) try run(io, why, &.{ "limactl", "delete", "-f", name });
        _ = std.process.run(gpa, io, .{
            .argv = &.{ "limactl", "disk", "delete", try gpa.print("{s}-config", .{name}) },
        }) catch {};
    }
    // Its disk and its config tar, which holds secrets: here, under this
    // host's arch; for a cloud's, under either, as --arch chose, where its
    // config in base64 marks it a cloud's and not another machine's.
    Dir.cwd().deleteTree(io, try machineDir(gpa, hostArch(), name)) catch {};
    const cloud = std.mem.eql(u8, on, "gcp") or std.mem.eql(u8, on, "aws") or
        std.mem.eql(u8, on, "azure");
    if (cloud) for ([_][]const u8{ "aarch64", "x86_64" }) |arch| {
        const dir = try machineDir(gpa, arch, name);
        Dir.cwd().access(io, try gpa.print("{s}/config.b64", .{dir}), .{}) catch continue;
        Dir.cwd().deleteTree(io, dir) catch {};
    };
    say(io, "{s}: deleted, with its /data", .{name});
}

fn console(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const name, const on = try machineArgs(gpa, io, args, why);
    if (std.mem.eql(u8, on, "gcp")) {
        const p = try gcp.place(io, gpa, why);
        const text = gcp.console(
            io,
            gpa,
            p,
            name,
        ) orelse return why.refuse("no machine {s} in {s}", .{ name, p.zone });
        return Io.File.stdout().writeStreamingAll(io, text[text.len -| (64 << 10)..]);
    }
    if (std.mem.eql(u8, on, "aws")) {
        const p = try aws.place(io, gpa, why);
        const i = aws.find(io, gpa, p, name) orelse
            return why.refuse("no machine {s} in {s}", .{ name, p.region });
        const text = aws.console(io, gpa, p, i.id) orelse
            return why.refuse("{s}: no console yet; AWS keeps it from shortly after boot", .{name});
        return Io.File.stdout().writeStreamingAll(io, text);
    }
    if (std.mem.eql(u8, on, "azure")) {
        const p = try azure.place(io, gpa, why);
        const text = azure.console(io, gpa, p, name) orelse
            return why.refuse("no machine {s} in {s}, or no boot diagnostics", .{ name, p.group });
        return Io.File.stdout().writeStreamingAll(io, text[text.len -| (64 << 10)..]);
    }
    if (std.mem.eql(u8, on, "proxmox")) {
        const p = try proxmox.place(environ, why);
        const text = proxmox.console(io, gpa, p, name, 0) orelse
            return why.refuse("no console for {s} on {s}", .{ name, p.host });
        return Io.File.stdout().writeStreamingAll(io, text[text.len -| (64 << 10)..]);
    }
    const path = if (std.mem.eql(u8, on, "bhyve") or std.mem.eql(u8, on, "firecracker"))
        try gpa.print("{s}/console.log", .{try machineDir(gpa, hostArch(), name)})
    else
        try gpa.print("{s}/serialv.log", .{
            try lima.dir(io, gpa, name) orelse return why.refuse("no machine {s}", .{name}),
        });
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 20)) catch |err|
        return why.refuse("{s}: {s}", .{ path, @errorName(err) });
    // The last 64 KiB: the boot, and what followed.
    try Io.File.stdout().writeStreamingAll(io, text[text.len -| (64 << 10)..]);
}

fn isMachineName(s: []const u8) bool {
    if (s.len == 0 or s.len > 32 or !std.ascii.isLower(s[0])) return false;
    for (s) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

/// One line of -h: the flag, then where it goes, in a column.
fn row(w: *Io.Writer, flag: []const u8, what: []const u8) !void {
    try w.print("  {s}", .{flag});
    try w.splatByteAll(' ', @max(2, 30 -| flag.len));
    try w.print("{s}\n", .{what});
}

// --- names -------------------------------------------------------------------------------

/// Whether something on the machine reads path: werewolf's own files, or
/// a file or settings a service declares.
fn declared(iface: Interface, path: []const u8) bool {
    for (own_files) |p| if (std.mem.eql(u8, p, path)) return true;
    for (iface.files) |f| if (std.mem.eql(u8, f.path, path)) return true;
    for (iface.settings) |st| if (std.mem.eql(u8, st.path, path)) return true;
    return false;
}

/// A name every reader of a config tar takes: [A-Za-z0-9._-/], relative,
/// at most 100 bytes, with no empty, . or .. part.
fn isTarName(s: []const u8) bool {
    if (s.len == 0 or s.len > max_name) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._-/", c) == null)
        return false;
    var parts = std.mem.splitScalar(u8, s, '/');
    while (parts.next()) |p| {
        if (p.len == 0 or std.mem.eql(u8, p, ".") or std.mem.eql(u8, p, "..")) return false;
    }
    return true;
}

fn beneath(path: []const u8, parent: []const u8) bool {
    return path.len > parent.len and std.mem.startsWith(u8, path, parent) and
        path[parent.len] == '/';
}

// --- tests -------------------------------------------------------------------------------

const testing = std.testing;

test {
    _ = lima;
    _ = bhyve;
    _ = firecracker;
    _ = proxmox;
    _ = gcp;
    _ = aws;
    _ = azure;
    _ = app;
    _ = @import("image.zig");
    _ = @import("apk.zig");
}

const bastion =
    \\exec    /usr/bin/sshd -D -e -f /etc/ssh/sshd_config
    \\user    bastion
    \\pledge  stdio
    \\config  host-key /run/config/bastion/host_key
    \\config  authorized-keys /run/config/bastion/authorized_keys
    \\config  settings /run/config/bastion/settings.json   # may be missing
    \\setting destinations addrport... as PermitOpen
    \\render  conf destinations
;

test buildOptions {
    var why: Why = .{};
    const o = try buildOptions(&.{ "bastion", "--format", "vhd", "-o", "out" }, "aarch64", &why);
    try testing.expectEqualStrings("bastion", o.form);
    try testing.expectEqualStrings("out", o.dir);
    try testing.expectEqualStrings("aarch64", o.arch);
    try testing.expectEqual(DiskFormat.vhd, o.format);
    try testing.expectEqualStrings(
        "x86_64",
        (try buildOptions(&.{ "--arch", "x86_64", "prod" }, null, &why)).arch,
    );
    for ([_][]const []const u8{
        &.{},
        &.{ "a", "b" },
        &.{ "a", "--arch", "riscv64" },
        &.{ "a", "--format", "zip" },
        &.{ "a", "--on", "gcp" },
        &.{ "a", "-o" },
    }) |args| try testing.expectError(error.Refused, buildOptions(args, "aarch64", &why));
    try testing.expectError(error.Refused, buildOptions(&.{"a"}, null, &why));
}

test interface {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const i = try interface(gpa, &.{.{ .name = "sshd", .text = bastion }}, &why);
    try testing.expectEqual(@as(usize, 2), i.files.len);
    try testing.expectEqualStrings("bastion/authorized_keys", i.files[1].path);
    try testing.expectEqualStrings("bastion/settings.json", i.settings[0].path);
    try testing.expectEqualStrings("PermitOpen", i.settings[0].decl[0].key.?);

    const refused = [_][]const Service{
        // The same flag from two services: a form on prod-ssh with a bastion.
        &.{
            .{ .name = "a", .text = "config authorized-keys /run/config/a/k" },
            .{ .name = "b", .text = "config authorized-keys /run/config/b/k" },
        },
        &.{.{ .name = "a", .text = "config hostname /run/config/a/h" }},
        &.{.{ .name = "a", .text = "config key /run/config/hostname" }},
        &.{
            .{ .name = "a", .text = "config k1 /run/config/x" },
            .{ .name = "b", .text = "config k2 /run/config/x" },
        },
        &.{.{ .name = "a", .text = "config key /etc/shadow" }},
        &.{.{ .name = "a", .text = "setting a ip\nrender conf x" }},
        &.{.{
            .name = "a",
            .text = "setting a string\nrender conf x\nconfig settings /run/config/a/s.json",
        }},
    };
    for (refused) |svcs| try testing.expectError(error.Refused, interface(gpa, svcs, &why));
}

test options {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const o = try options(
        gpa,
        &.{ "-n", "--on", "aws", "--destinations=10.0.0.1:22", "bastion", "--host-key", "k" },
        &why,
    );
    try testing.expectEqualStrings("bastion", o.form);
    try testing.expect(o.check and o.on.? == .aws);
    try testing.expectEqualStrings("destinations", o.flags[0][0]);
    try testing.expectEqualStrings("k", o.flags[1][1]);
    try testing.expectEqual(
        Target.disk,
        (try options(gpa, &.{ "x", "--on", "proxmox" }, &why)).on.?,
    );
    for ([_][]const []const u8{
        &.{},
        &.{ "a", "b", "c" },
        &.{ "a", "--host-key" },
        &.{ "a", "--on", "mars" },
        &.{ "a", "-x", "1" },
        &.{ "a", "--config", "x", "--config", "y" },
    }) |args| try testing.expectError(error.Refused, options(gpa, args, &why));
}

test "a static network, checked as init checks it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const none: Interface = .{ .files = &.{}, .settings = &.{} };
    const o = try options(gpa, &.{ "x", "--ip", "10.0.0.5/24", "--gw=10.0.0.1" }, &why);
    const e = try gather(testing.io, gpa, none, o, &why);
    try testing.expectEqualStrings("network", e[0].path);
    try testing.expectEqualStrings("werewolf.ip=10.0.0.5/24 werewolf.gw=10.0.0.1\n", e[0].data);
    for ([_][]const []const u8{
        &.{ "x", "--gw", "10.0.0.1" },
        &.{ "x", "--ip", "10.0.0.5" },
        &.{ "x", "--ip", "10.0.0.5/24", "--dns", "224.0.0.1" },
    }) |args| try testing.expectError(
        error.Refused,
        gather(testing.io, gpa, none, try options(gpa, args, &why), &why),
    );
}

test "settings from flags, checked as the guest checks them" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const i = try interface(gpa, &.{.{ .name = "sshd", .text = bastion }}, &why);
    var obj: json.ObjectMap = .empty;
    const d = i.settings[0].decl[0];
    try setValue(gpa, &obj, d, "10.0.0.1:22,[fd00::1]:22", &why);
    try setValue(gpa, &obj, d, "10.0.0.2:22", &why);
    try testing.expectEqual(@as(usize, 3), obj.get("destinations").?.array.items.len);
    try testing.expectError(error.Refused, setValue(gpa, &obj, d, "host.example:22", &why));
    try testing.expectEqualStrings(
        "--destinations host.example:22: not a literal address and port",
        why.text,
    );

    var s: json.ObjectMap = .empty;
    const name: settings.Setting = .{ .name = "team", .type = .string };
    try setValue(gpa, &s, name, "red, blue", &why);
    try testing.expectError(error.Refused, setValue(gpa, &s, name, "green", &why));
}

test "the tar is ustar, sorted, and what std.tar reads back" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const entries = [_]Entry{
        .{ .path = "bastion/authorized_keys", .data = "ssh-ed25519 AAAA test\n", .from = "" },
        .{ .path = "hostname", .data = "edge\n", .from = "" },
    };
    const tar = try writeTar(gpa, &entries);
    try testing.expectEqual(@as(usize, 512 * 4 + 1024), tar.len);
    try testing.expectEqualStrings("ustar\x0000", tar[257..265]);

    var r: Io.Reader = .fixed(tar);
    var name_buf: [256]u8 = undefined;
    var link_buf: [256]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &r,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    for (entries) |want| {
        const e = (try it.next()).?;
        try testing.expectEqualStrings(want.path, e.name);
        try testing.expectEqual(want.data.len, e.size);
        try testing.expectEqual(@as(u32, 0o600), e.mode);
        var buf: [64]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        try it.streamRemaining(e, &w);
        try testing.expectEqualStrings(want.data, w.buffered());
    }
    try testing.expectEqual(null, try it.next());
}

test misfit {
    const small = [_]Entry{.{ .path = "a", .data = "x", .from = "" }};
    for ([_]Target{
        .disk,
        .gcp,
        .aws,
        .azure,
    }) |t| try testing.expectEqual(null, misfit(&small, 2048, t));
    const big = [_]Entry{.{ .path = "a", .data = &(@as([40 << 10]u8, @splat('x'))), .from = "" }};
    try testing.expectEqual(null, misfit(&big, 42 << 10, .disk));
    try testing.expect(misfit(&big, 42 << 10, .gcp) != null);
    try testing.expect(misfit(&small, 13 << 10, .aws) != null);
    try testing.expectEqual(null, misfit(&small, 13 << 10, .azure));
}

test awaitUp {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const old = "werewolf: up in 0.7s\n";
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "console.log", .data = old ++ "boot two\nwerewolf: up in 0.8s\n" },
    );
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const log = try tmp.dir.realPathFileAlloc(io, "console.log", arena.allocator());
    // Past the first boot's line, the second's.
    try testing.expect(try awaitUp(io, testing.allocator, log, old.len));
    // A log shorter than what was seen was started again: read from its start.
    try testing.expect(try awaitUp(io, testing.allocator, log, 1 << 30));
}

test listenPorts {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var ports: std.ArrayList(u16) = .empty;
    for ([_][]const u8{
        "listen tcp/80 tcp/443",
        "connect caddy tcp/443",
        "listen udp/53 tcp/80",
        "listen",
    }) |line|
        try listenPorts(arena.allocator(), line, &ports);
    try testing.expectEqualSlices(u16, &.{ 80, 443 }, ports.items);
}

test isTarName {
    try testing.expect(isTarName("bastion/host_key"));
    try testing.expect(isTarName("data.key"));
    for ([_][]const u8{ "", "/etc/x", "a/../b", "a//b", "a b", "a/", "./a", "é" }) |s|
        try testing.expect(!isTarName(s));
}
