//! howl: make what a werewolf machine needs, on the machine that makes
//! it, and run it (docs/design/cli.md). Built for this host, not the image.
//!
//!     howl build --with FORM [-o DIR] [--arch ARCH] [--format qcow2|raw|vhd|vmdk] [--app DIR]
//!     howl pack --with FORM [-o FILE] [-n] [--on TARGET] [CONFIG...]
//!     howl run [--with FORM,...] [--on TARGET] [--dev] [CONFIG...]
//!     howl create NAME --with FORM,... [--on TARGET] [--dev] [CONFIG...]
//!     howl ssh|console [NAME], howl delete NAME, howl stop
//!     howl build-apk RECIPE [--arch ARCH]
//!
//! build-apk builds a form's own package from a melange recipe (apk.zig).
//!
//! run is create, of the one machine it keeps, werewolf-run, on the engine
//! create picks: Lima on macOS, bhyve on FreeBSD, Firecracker on Linux
//! where its network needs no password, else QEMU (qemu.zig). ssh, console
//! and stop without a name are that machine's.
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
//!     config  authorized-keys /run/config/bastion/authorized_keys  --authorized-keys FILE
//!     setting destinations addrport... as PermitOpen               --destinations ADDR:PORT,...
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
const service = @import("service");
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
const adhoc = @import("adhoc.zig");
const oci = @import("oci.zig");
const progress = @import("progress.zig");
const qemu = @import("qemu.zig");
const booting = @import("boot.zig");
const forms = @import("form");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const json = std.json;

const usage =
    \\usage: howl build --with FORM,... [-o DIR] [--arch ARCH] [--format qcow2|raw|vhd|vmdk] [--app DIR]
    \\       howl pack --with FORM [-o FILE] [-n] [--on TARGET] [CONFIG...]
    \\       howl pack --with FORM -h   the flags FORM takes
    \\       howl run [--with FORM,...] [--on TARGET] [--dev] [--verbose] [CONFIG...]   create's machine werewolf-run, replaced each time; with no --with, lima on Lima, else prod-ssh
    \\       howl ssh [NAME] [-- COMMAND...]   ssh into it, or into NAME; howl stop ends it
    \\
++ "       howl create NAME --with FORM,... [--on " ++ Platform.list(.made, "|") ++
    "] [--dev] [--arch ARCH] [--size TYPE] [--allow-from me|CIDR] [CONFIG...]\n" ++
    "       howl delete NAME [--on " ++ Platform.list(.made, "|") ++ "]\n" ++
    "       howl console [NAME] [--on " ++ Platform.list(.made, "|") ++ "]\n" ++
    "       howl upload DISK --on " ++ Platform.list(.cloud, "|") ++ "\n" ++
    \\       howl build-apk RECIPE [--arch ARCH]   a form's own package, from a melange recipe
    \\       howl form --with FORM,... --package PKG,... --oci NAME=REF --KEY LINE --KEY.SUB VALUE -o DIR   a form from the line, kept;
    \\            build, run, create and pack take the same flags: one form alone is run as it is, more is generated (-n shows it)
    \\
;

/// What init extracts from a config disk, at most, per file.
const max_disk_file = 1 << 20;
/// What cloud-metadata accepts from user data (cmd/cloud-metadata).
const max_cloud_file = 32 << 10;
const max_cloud_total = 48 << 10;
const max_cloud_entries = 32;
const max_name = 100;

/// The environment: what names a Proxmox node (proxmox.zig), the user a
/// Firecracker machine's tap device is made for, and the terminal
/// (progress.zig).
pub var environ: *const std.process.Environ.Map = undefined;

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
            stop,
            ssh,
            upload,
            @"build-apk",
            form,
            _bhyve,
            _firecracker,
            _unpack,
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
        .stop => stopHere(io, gpa, args[2..], &why),
        .ssh => sshTo(io, gpa, args[2..], &why),
        .upload => upload(io, gpa, args[2..], &why),
        .@"build-apk" => apk.build(io, gpa, args[2..], &why),
        .form => adhoc.form(io, gpa, args[2..], &why),
        // create's supervisors on bhyve and Firecracker, not verbs for anyone.
        ._bhyve => if (args.len < 5)
            why.refuse("_bhyve NAME CONFIG BHYVE...", .{})
        else
            bhyve.keep(io, gpa, args[2], args[3], args[4..]),
        ._firecracker => if (args.len != 3)
            why.refuse("_firecracker DIR", .{})
        else
            firecracker.keep(io, gpa, args[2]),
        // form's unpacker for an image's tar, a child with nothing (oci.zig).
        ._unpack => oci.unpackMain(io, gpa, args[2..], &why),
    };
    done catch |err| switch (err) {
        // Said already, in full (progress).
        error.Refused => if (why.text.len == 0)
            std.process.exit(1)
        else
            fatal(io, "{s}", .{why.text}),
        else => fatal(io, "{s}", .{@errorName(err)}),
    };
}

fn fatal(io: Io, comptime fmt: []const u8, args: anytype) noreturn {
    say(io, fmt, args);
    std.process.exit(1);
}

pub fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    const line = std.mem.print(&buf, "howl: " ++ fmt ++ "\n", args) catch return;
    Io.File.stderr().writeStreamingAll(io, line) catch {};
}

/// Why a verb refused, for the one line that says so.
pub const Why = struct {
    /// Room for any refusal, the usage it may repeat included.
    buf: [4096]u8 = undefined,
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
    decl: []const settings.Setting,
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
/// by a flag of howl's: init's hostname, network, data.key and root's
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
    "allow-from",
};

/// A form's chain, base first, as the build lays it (lib/form.zig): the
/// form in ./forms, or in the directory form names.
pub fn chain(io: Io, gpa: Allocator, form: []const u8, why: *Why) ![]const forms.Form {
    Dir.cwd().access(io, "forms", .{}) catch
        return why.refuse("no ./forms: run howl in a werewolf checkout", .{});
    var f: forms.Failure = .{};
    return forms.chain(io, gpa, Dir.cwd(), form, &f) catch |err| switch (err) {
        error.Form => why.refuse("{s}", .{f.text}),
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// The flags the services declare: their `config` lines, and their
/// `setting` and `render` lines, each file read whole as leash reads it
/// (lib/service.zig), so what pack accepts, the guest does.
fn interface(gpa: Allocator, svcs: []const forms.Service, why: *Why) !Interface {
    var files: std.ArrayList(File) = .empty;
    var sets: std.ArrayList(Settings) = .empty;
    for (svcs) |svc| {
        var bad: service.Bad = .{};
        const s = service.parse(gpa, svc.text, &bad) catch |err| switch (err) {
            error.Invalid => return if (bad.line > 0)
                why.refuse("{s}, line {d}: {s}", .{ svc.name, bad.line, bad.why })
            else
                why.refuse("{s}: {s}", .{ svc.name, bad.why }),
            else => |e| return e,
        };
        var settings_path: ?[]const u8 = null;
        for (s.configs) |cfg| {
            const path = cfg.path["/run/config/".len..];
            if (!isTarName(path))
                return why.refuse("{s}: {s} cannot be in a config tar", .{ svc.name, cfg.path });
            if (std.mem.eql(u8, cfg.name, settings.input_file)) {
                settings_path = path;
            } else try files.append(
                gpa,
                .{ .flag = cfg.name, .path = path, .service = svc.name, .optional = cfg.optional },
            );
        }
        // leash refuses settings without render, or with no `config settings`.
        if (s.render != null)
            try sets.append(
                gpa,
                .{ .service = svc.name, .path = settings_path.?, .decl = s.settings },
            );
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

// --- the inputs -----------------------------------------------------------------------

/// What --on names: an engine on this machine, a hypervisor elsewhere, a
/// cloud, or, for pack, any hypervisor at all. A hypervisor reads the tar
/// from a disk; a cloud from user data, through cloud-metadata.
pub const Platform = enum {
    lima,
    bhyve,
    firecracker,
    qemu,
    proxmox,
    gcp,
    aws,
    azure,
    disk,

    /// Which platforms a list names: those create makes machines on, every
    /// one but disk; or the clouds, which take --arch and --size.
    const Kind = enum { made, cloud };

    fn is(p: Platform, kind: Kind) bool {
        return switch (kind) {
            .made => p != .disk,
            .cloud => p == .gcp or p == .aws or p == .azure,
        };
    }

    /// An engine on this machine, which runs this machine's arch.
    fn here(p: Platform) bool {
        return p == .lima or p == .bhyve or p == .firecracker or p == .qemu;
    }

    /// The platforms of a kind, as a usage or a refusal names them.
    fn list(comptime kind: Kind, comptime between: []const u8) []const u8 {
        const names = comptime names: {
            var out: []const u8 = "";
            for (std.enums.values(Platform)) |p| if (p.is(kind)) {
                out = out ++ (if (out.len > 0) between else "") ++ @tagName(p);
            };
            break :names out;
        };
        return names;
    }
};

/// What --arch and --size are refused with, where neither means anything.
const sized_only = "--arch and --size are for --on " ++ Platform.list(.cloud, ", ");

const Options = struct {
    form: []const u8 = "",
    /// create's machine's name, the word after FORM.
    name: ?[]const u8 = null,
    out: ?[]const u8 = null,
    check: bool = false,
    help: bool = false,
    on: ?Platform = null,
    config: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
    /// A static network: init's network file.
    ip: ?[]const u8 = null,
    gw: ?[]const u8 = null,
    dns: ?[]const u8 = null,
    data_key: ?[]const u8 = null,
    update_policy: ?[]const u8 = null,
    root_keys: ?[]const u8 = null,
    /// create --on a cloud's: the machine's architecture, and its type.
    arch: ?Arch = null,
    size: ?[]const u8 = null,
    /// build, run and create's: a directory, laid where the form keeps its
    /// application (app.zig).
    app: ?[]const u8 = null,
    /// create --on gcp, aws or azure's: who may reach the form's TCP ports,
    /// me or an IPv4 CIDR; without it, create says the commands instead.
    allow_from: ?[]const u8 = null,
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
        const name, const v = try flagValue(args, &i, why);
        if (!std.mem.startsWith(u8, name, "--") and !std.mem.eql(u8, name, "-o"))
            return why.refuse("{s}: flags are --NAME, or -o, -n, -h", .{a});
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
        else if (std.mem.eql(u8, flag, "size"))
            &o.size
        else if (std.mem.eql(u8, flag, "app"))
            &o.app
        else if (std.mem.eql(u8, flag, "allow-from"))
            &o.allow_from
        else
            null;
        if (slot) |s| {
            if (s.* != null) return why.refuse("--{s} given twice", .{flag});
            s.* = v;
        } else if (std.mem.eql(u8, flag, "on")) {
            if (o.on != null) return why.refuse("--on given twice", .{});
            o.on = std.meta.stringToEnum(Platform, v) orelse
                return why.refuse(
                    "--on {s}: {s}",
                    .{ v, comptime Platform.list(.made, " ") ++ " disk" },
                );
        } else if (std.mem.eql(u8, flag, "arch")) {
            if (o.arch != null) return why.refuse("--arch given twice", .{});
            o.arch = archName(v) orelse return why.refuse(arch_refusal, .{v});
        } else try flags.append(gpa, .{ flag, v });
    }
    if (o.form.len == 0) return why.refuse("no form\n{s}", .{usage});
    o.flags = flags.items;
    return o;
}

/// A flag and its value, `--NAME VALUE` or `--NAME=VALUE`, as every verb
/// takes them, from args[i.*], the flag; i is left on the last word read.
pub fn flagValue(
    args: []const []const u8,
    i: *usize,
    why: *Why,
) error{Refused}!struct { []const u8, []const u8 } {
    const a = args[i.*];
    if (std.mem.findScalar(u8, a, '=')) |eq| return .{ a[0..eq], a[eq + 1 ..] };
    i.* += 1;
    if (i.* == args.len) return why.refuse("{s} wants a value", .{a});
    return .{ a, args[i.*] };
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
    const values = try gpa.alloc(json.ObjectMap, iface.settings.len);
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
            "{s} takes no --{s}; howl pack {s} -h lists what it does",
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
    // The hostname, the network and the data key, as init reads them,
    // whether from a flag or from --config DIR.
    for (entries.items) |e| if (std.mem.eql(u8, e.path, "hostname")) {
        const line = e.data[0 .. std.mem.findScalar(u8, e.data, '\n') orelse e.data.len];
        const name = std.mem.trim(u8, line, " \t\r");
        if (!settings.isHostname(name)) return why.refuse(
            "hostname {s} (from {s}): a hostname of at most {d} bytes, which init takes",
            .{ name, e.from, settings.max_hostname },
        );
    };
    for (entries.items) |e| if (std.mem.eql(u8, e.path, "network")) {
        var reason: []const u8 = "";
        if (network.parse(e.data, &reason) == null) return why.refuse("network: {s}", .{reason});
    };
    for (entries.items) |e| if (std.mem.eql(u8, e.path, "data.key")) {
        if (e.data.len < settings.min_data_key) return why.refuse(
            "data.key (from {s}) is {d} bytes: init makes LUKS2 only with {d} or more " ++
                "random bytes (head -c 32 /dev/urandom)",
            .{ e.from, e.data.len, settings.min_data_key },
        );
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
/// by commas or by repeating the flag; a string or url list's only by
/// repeating, since either may hold a comma, as settings.declare holds
/// them out of env for.
fn setValue(
    gpa: Allocator,
    obj: *json.ObjectMap,
    d: settings.Setting,
    text: []const u8,
    why: *Why,
) !void {
    var items: std.ArrayList([]const u8) = .empty;
    if (d.list and d.type != .string and d.type != .url) {
        var parts = std.mem.splitScalar(u8, text, ',');
        while (parts.next()) |p| try items.append(gpa, p);
    } else try items.append(gpa, text);
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
fn misfit(entries: []const Entry, tar_len: usize, t: Platform) ?[]const u8 {
    if (!t.is(.cloud)) return null;
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
    arch: Arch,
    format: DiskFormat = .qcow2,
};

/// build's command line: FORM, and -o, --arch, --format, each with a value.
/// host is this machine's arch, if werewolf builds for it.
fn buildOptions(args: []const []const u8, host: ?Arch, why: *Why) !BuildOptions {
    var form: ?[]const u8 = null;
    var arch = host;
    var o: BuildOptions = .{ .form = "", .arch = undefined };
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (args[i].len == 0 or args[i][0] != '-') {
            if (form != null) return why.refuse("{s}: one form at a time", .{args[i]});
            form = args[i];
            continue;
        }
        const a, const v = try flagValue(args, &i, why);
        if (std.mem.eql(u8, a, "-o")) {
            o.dir = v;
        } else if (std.mem.eql(u8, a, "--arch")) {
            arch = archName(v) orelse return why.refuse(arch_refusal, .{v});
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
    o.arch = arch orelse return why.refuse("{s}: --arch", .{not_built_here});
    return o;
}

fn build(io: Io, gpa: Allocator, given: []const []const u8, why: *Why) !void {
    const all = (try adhoc.take(io, gpa, .build, given, why)) orelse return;
    const verbose, const args = try verboseFlag(gpa, all);
    const o = try buildOptions(args, hostArch(), why);
    // The form as make takes it, a name or a directory, and its name.
    const ref = o.form;
    const f = std.fs.path.basename(std.mem.trimEnd(u8, ref, "/"));
    const a = @tagName(o.arch);
    const dir = o.dir;
    const format = o.format;
    _ = try chain(io, gpa, ref, why);
    const ab = try appBuild(io, gpa, ref, o.arch, o.app, why);
    const command = try gpa.print("howl build {s}", .{std.mem.join(gpa, " ", args) catch ref});
    const log = try gpa.print("build/log/{s}-{s}-build.log", .{ f, a });

    // make keeps the build graph; this only names the target, as it ships.
    var done = try progress.run(io, gpa, why, &.{
        make_cmd,
        "--no-print-directory",
        try gpa.print("FORM={s}", .{ref}),
        try gpa.print("ARCH={s}", .{a}),
        "DEV=",
        ab.app,
        try gpa.print("DIST={s}", .{dir}),
        "_dist-form",
    }, .{ .verbose = verbose, .command = command, .log = log, .first = start_phase });

    const name = try gpa.print("{s}/{s}-{s}.json", .{ dir, f, a });
    const text = Dir.cwd().readFileAlloc(io, name, gpa, .limited(1 << 20)) catch |err|
        return why.refuse("{s}: {s}", .{ name, @errorName(err) });
    // As much of the manifest as is used here: the files it names. The
    // updater reads the rest (cmd/slot-update/release.zig).
    const m = json.parseFromSliceLeaky(
        struct { files: json.ArrayHashMap(struct { sha256: []const u8, size: u64 }) },
        gpa,
        text,
        .{ .ignore_unknown_fields = true },
    ) catch return why.refuse("{s}: not a manifest", .{name});
    const files = m.files.map;

    // What a machine boots from: the disk, or, for a form released for
    // direct boot, its initramfs, unless a format of its own was asked for.
    var boot = try gpa.print("{s}/{s}-{s}-{s}", .{
        dir, f, a, if (files.contains("disk.qcow2")) "disk.qcow2" else "initramfs.zst",
    });
    if (format != .qcow2) {
        if (!files.contains("disk.qcow2"))
            return why.refuse("{s} is released for direct boot, without a disk to convert", .{f});
        const dst = try gpa.print("{s}/{s}-{s}-disk.{t}", .{ dir, f, a, format });
        // VHD as Azure takes it: fixed, its size exactly the disk's.
        const convert: []const []const u8 = switch (format) {
            .raw => &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", boot, dst },
            .vhd => &.{
                "qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "vpc",
                "-o",
                "subformat=fixed,force_size=on",
                boot,
                dst,
            },
            .vmdk => &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "vmdk", boot, dst },
            .qcow2 => unreachable,
        };
        const c = try progress.run(io, gpa, why, convert, .{
            .verbose = verbose,
            .command = command,
            .log = log,
            .first = .{
                .name = try gpa.print("Converting the disk to {t}", .{format}),
                .short = "convert",
            },
            .make = false,
        });
        done.seconds += c.seconds;
        done.phases = try std.mem.concat(gpa, progress.Spent, &.{ done.phases, c.phases });
        boot = dst;
    }

    // What was made, where, and what to do with it: four lines.
    const look: progress.Look = .of(io, Io.File.stderr());
    var err_out: Io.Writer.Allocating = .init(gpa);
    const e = &err_out.writer;
    try e.print(
        "{s} Built {s} for {s} in {f}\n",
        .{ look.check(), f, a, progress.Clock{ .seconds = done.seconds } },
    );
    if (!verbose) try e.print("  {f}\n", .{look.dim(try gpa.print("{f}", .{done}))});
    Io.File.stderr().writeStreamingAll(io, err_out.written()) catch {};
    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    const size = if (Dir.cwd().statFile(io, boot, .{})) |st| st.size else |_| 0;
    try w.print(
        "  {s}  {f}\n",
        .{
            boot,
            look.dim(try gpa.print("{f}, every file in {s}", .{ Size{ .bytes = size }, name })),
        },
    );
    if (verbose) {
        for (files.keys()) |file| try w.print("  {s}/{s}-{s}-{s}\n", .{ dir, f, a, file });
    }
    err_out.clearRetainingCapacity();
    if (o.arch == hostArch()) {
        try e.print(
            "  Next: howl create NAME --with {s}   {f}\n",
            .{
                ref,
                look.dim(try gpa.print("a machine on {t}, kept", .{engine(io, gpa, null).on})),
            },
        );
        try e.print(
            "        howl run --with {s}           {f}\n",
            .{ ref, look.dim("boot it here, its console in this terminal") },
        );
    } else {
        try e.print("  Next: howl upload {s} --on {s}\n", .{ boot, Platform.list(.cloud, "|") });
    }
    Io.File.stderr().writeStreamingAll(io, err_out.written()) catch {};
}

/// The phase a build is in before make names one.
const start_phase: progress.Phase = .{ .name = "Starting the build", .short = "start" };

/// A file's size as people read one: 812 KiB, 44 MiB, 1.2 GiB.
const Size = struct {
    bytes: u64,

    pub fn format(s: Size, w: *Io.Writer) Io.Writer.Error!void {
        const k: u64 = 1 << 10;
        if (s.bytes < k << 10) return w.print("{d} KiB", .{(s.bytes + k - 1) / k});
        if (s.bytes < k << 20) return w.print("{d} MiB", .{(s.bytes + (k << 10) - 1) / (k << 10)});
        return w.print("{d}.{d} GiB", .{ s.bytes >> 30, ((s.bytes >> 20) & 1023) * 10 / 1024 });
    }
};

/// --verbose or -v, anywhere on a command line, and the rest of it.
fn verboseFlag(gpa: Allocator, args: []const []const u8) !struct { bool, []const []const u8 } {
    return takeFlag(gpa, args, &.{ "--verbose", "-v" });
}

/// Whether one of names, a flag without a value, is anywhere on a command
/// line, and the rest of it.
fn takeFlag(
    gpa: Allocator,
    args: []const []const u8,
    names: []const []const u8,
) !struct { bool, []const []const u8 } {
    var rest: std.ArrayList([]const u8) = .empty;
    var seen = false;
    for (args) |a| {
        for (names) |n| {
            if (std.mem.eql(u8, a, n)) {
                seen = true;
                break;
            }
        } else try rest.append(gpa, a);
    }
    return .{ seen, rest.items };
}

/// Run argv, its output the user's on standard error, so that standard
/// output is howl's result alone, and refuse if it fails.
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

fn pack(io: Io, gpa: Allocator, given: []const []const u8, why: *Why) !void {
    const args = (try adhoc.take(io, gpa, .pack, given, why)) orelse return;
    const o = try options(gpa, args, why);
    if (o.name) |n| return why.refuse("{s}: pack takes one form, and no name", .{n});
    if (o.arch != null or o.size != null) return why.refuse("{s}, create's", .{sized_only});
    if (o.allow_from != null) return why.refuse(
        "--allow-from is create's: it opens a machine's ports",
        .{},
    );
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
    for ([_]Platform{ .disk, .gcp, .azure, .aws }) |t| if (misfit(entries, tar.len, t) == null)
        try fits.print(gpa, " {t}", .{t});
    try w.print("{d} files, a {d}-byte tar, for:{s}\n", .{ entries.len, tar.len, fits.items });
    if (o.check) return;
    try writePrivate(io, gpa, o.out.?, tar, why);
    try w.print("wrote {s}\n", .{o.out.?});
}

/// The flags FORM takes, from its chain's files.
fn formInterface(io: Io, gpa: Allocator, form: []const u8, why: *Why) !Interface {
    const c = try chain(io, gpa, form, why);
    var failure: forms.Failure = .{};
    const svcs = forms.services(io, gpa, Dir.cwd(), c, &failure) catch |err| switch (err) {
        error.Form => return why.refuse("{s}", .{failure.text}),
        error.OutOfMemory => return error.OutOfMemory,
    };
    var iface = try interface(gpa, svcs, why);
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
    try w.print("{s}\nhowl {s} {s} takes:\n", .{ usage, verb, form });
    try row(w, "--config DIR", "files as they go in the tar");
    try row(w, "--hostname NAME", "hostname");
    try row(w, "--ip CIDR", "network: an address, where no DHCP gives one");
    try row(w, "--gw ADDR", "network: the default route");
    try row(w, "--dns ADDR", "network: the resolver");
    try row(w, "--data-key FILE", "data.key: /data in LUKS2");
    try row(w, "--root-keys FILE", "authorized_keys: root's, where the form runs sshd");
    try row(w, "--update-policy FILE", "update-policy.json: when updates install");
    if (std.mem.eql(u8, verb, "create"))
        try row(w, "--allow-from me|CIDR", "opens the form's TCP ports to it (gcp, aws, azure)");
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

/// run is create, of the one machine it keeps for trying a form: on the
/// engine create would pick, with create's flags, named werewolf-run,
/// and in place of the last one. howl ssh, console and stop, with no
/// name, are its.
fn runForm(io: Io, gpa: Allocator, given: []const []const u8, why: *Why) !void {
    // run's references and flags, the form first, as create takes them;
    // create's own taking is done here, once.
    const args = (try adhoc.take(io, gpa, .run, given, why)) orelse return;
    for (args) |a| if (std.mem.eql(u8, a, run_name))
        return why.refuse("{s} is the name run gives its machine: run [--with FORM] [flags]", .{a});
    const asking = for (args) |a| {
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) break true;
    } else false;
    // The last one, wherever it ran: it has the name, and maybe the ports.
    if (!asking) if (madeOn(
        io,
        gpa,
        run_name,
    )) |was| remove(io, gpa, run_name, was, why) catch |err| say(
        io,
        "{s}: the last one, on {t}, was not removed: {s}",
        .{ run_name, was, if (err == error.Refused) why.text else @errorName(err) },
    );
    var with: std.ArrayList([]const u8) = .empty;
    try with.appendSlice(gpa, args);
    try with.append(gpa, run_name);
    return createFrom(io, gpa, with.items, why);
}

/// How create tells what it does: everything, or one line and a summary;
/// the command, for a failure to repeat; when it began; and, when a
/// likelier engine was passed over, why.
const Tell = struct {
    verbose: bool,
    command: []const u8,
    began: Io.Timestamp,
    note: ?[]const u8 = null,
    dev: bool = false,

    fn step(t: Tell, gpa: Allocator, dir: []const u8) !progress.Options {
        return .{
            .verbose = t.verbose,
            .command = t.command,
            .log = try gpa.print("{s}/create.log", .{dir}),
            .first = start_phase,
        };
    }
};

/// create --on qemu (qemu.zig), and wherever no likelier engine is: the
/// form built, then booted in the background under QEMU with a data disk
/// and config tar of its own, ssh and its last port forwarded from free
/// ports on this host's loopback; a machine of the name stopped first, its
/// /data kept.
fn createQemu(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    tell: Tell,
    why: *Why,
) !void {
    const arch = try localArch(why);
    const dir = try machineDir(gpa, name);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const at = try gpa.print("{s}/{s}", .{ cwd, dir });
    const replaced = try qemu.stop(io, gpa, dir);
    const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
    const step = try tell.step(gpa, dir);
    const built = try progress.run(io, gpa, why, &.{
        make_cmd,
        "--no-print-directory",
        try gpa.print("FORM={s}", .{o.form}),
        if (tell.dev) "DEV=1" else "DEV=",
        ab.app,
        "image",
    }, step);
    try writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), tar, why);
    try qemu.disk(io, try gpa.print("{s}/data.img", .{dir}), 8 << 30);
    const ssh_port = try qemu.freePort(io, 2222);
    const web_port = try qemu.freePort(io, 8080);
    try writePrivate(io, gpa, try gpa.print("{s}/machine", .{dir}), try gpa.print(
        "form {s}\nssh {d}\nweb {d}\n",
        .{ o.form, ssh_port, web_port },
    ), why);
    var start_step = step;
    start_step.make = false;
    start_step.first = .{ .name = "Starting the VM under QEMU", .short = "start" };
    const launched = Io.Clock.awake.now(io);
    _ = try progress.run(io, gpa, why, &.{
        make_cmd,
        "--no-print-directory",
        "-s",
        try gpa.print("FORM={s}", .{o.form}),
        if (tell.dev) "DEV=1" else "DEV=",
        ab.app,
        try gpa.print(
            "QEMU_CONFIG=-drive file={s}/config.tar,format=raw,if=virtio,readonly=on",
            .{at},
        ),
        try gpa.print("RUN_DATA={s}/data.img", .{at}),
        try gpa.print("RUN_SSH_PORT={d}", .{ssh_port}),
        try gpa.print("RUN_WEB_PORT={d}", .{web_port}),
        try gpa.print("RUN_DIR={s}", .{at}),
        "run",
    }, start_step);
    var spin: progress.Spinner = .init(io);
    const watch = Io.Clock.awake.now(io);
    var boot = try booting.watch(
        io,
        gpa,
        try gpa.print("{s}/console.log", .{dir}),
        0,
        null,
        0,
        &spin,
    );
    spin.clear();
    // The VM's start is QEMU's, then until its console spoke.
    if (boot.power_ns) |ns| boot.power_ns = ns + launched.durationTo(watch).toNanoseconds();
    const look: progress.Look = .of(io, Io.File.stderr());
    if (!boot.up) {
        try Io.File.stderr().writeStreamingAll(io, try gpa.print(
            "{s} {s} did not say it was up within 3 minutes\n  {s} · {s}\n",
            .{ look.cross(), name, try consoleCommand(gpa, name), try stopCommand(gpa, name) },
        ));
        why.text = "";
        return error.Refused;
    }
    if (!(Io.File.stdout().isTty(io) catch false)) {
        var out = Io.File.stdout().writerStreaming(io, &.{});
        try out.interface.print("{s}\t127.0.0.1:{d}\t{s}\n", .{ name, ssh_port, o.form });
    }
    const ports = try listens(io, gpa, o.form, why);
    const ssh = std.mem.findScalar(u16, ports, 22) != null;
    const late = sshReady(io, ports, "127.0.0.1", ssh_port);
    return sayUp(io, gpa, tell.began, try gpa.print("{s} is up here, under QEMU{s}{s}", .{
        name,
        if (replaced) ", in place of the last" else "",
        late,
    }), built.seconds, boot, try gpa.print("{s}{s}{s}{s} · {s}", .{
        if (ssh) try sshCommand(gpa, name) else "",
        if (ssh) " · " else "",
        try reach(gpa, ports, web_port),
        try consoleCommand(gpa, name),
        try stopCommand(gpa, name),
    }), tell.note);
}

/// How to reach a machine, as a summary says it: the run machine's need no
/// name.
fn sshCommand(gpa: Allocator, name: []const u8) ![]const u8 {
    return if (std.mem.eql(u8, name, run_name))
        "howl ssh"
    else
        gpa.print("howl ssh {s}", .{name});
}

fn consoleCommand(gpa: Allocator, name: []const u8) ![]const u8 {
    return if (std.mem.eql(u8, name, run_name))
        "howl console"
    else
        gpa.print("howl console {s}", .{name});
}

fn stopCommand(gpa: Allocator, name: []const u8) ![]const u8 {
    return if (std.mem.eql(u8, name, run_name))
        "howl stop"
    else
        gpa.print("howl delete {s}", .{name});
}

/// howl ssh [NAME] [-- COMMAND...]: ssh as root into a machine here,
/// howl run's without a name: under QEMU on the port it forwarded,
/// under Firecracker at its tap's address, on Lima at its lease's address,
/// or through Lima's own ssh for one Lima manages. howl becomes ssh.
fn sshTo(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    var rest: []const []const u8 = args;
    var command: []const []const u8 = &.{};
    for (args, 0..) |a, i| if (std.mem.eql(u8, a, "--")) {
        rest = args[0..i];
        command = args[i + 1 ..];
        break;
    };
    const name, const on = try machineArgs(io, gpa, rest, why);
    const dir = try machineDir(gpa, name);
    // Its host key is its own, kept in /data: learned once, then held to,
    // beside its other files, not by an address another machine may get;
    // delete takes it with the machine.
    const pinned = [_][]const u8{
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", try gpa.print("UserKnownHostsFile={s}/known_hosts", .{dir}),
        "-o", try gpa.print("HostKeyAlias={s}", .{name}),
        "-o", "LogLevel=ERROR",
    };
    var argv: std.ArrayList([]const u8) = .empty;
    if (on == .qemu) {
        if (qemu.running(
            io,
            gpa,
            dir,
        ) == null) return why.refuse("no machine {s} running under QEMU", .{name});
        const port = qemu.record(
            io,
            gpa,
            dir,
            "ssh",
        ) orelse return why.refuse("{s}: no ssh port on record", .{name});
        try argv.appendSlice(gpa, &.{ "ssh", "-p", port });
        try argv.appendSlice(gpa, &pinned);
        try argv.append(gpa, "root@127.0.0.1");
    } else if (on == .firecracker) {
        try argv.append(gpa, "ssh");
        try argv.appendSlice(gpa, &pinned);
        try argv.append(gpa, try gpa.print("root@{s}", .{(try firecracker.net(gpa, name)).guest}));
    } else if (on == .lima) {
        if (!try lima.exists(io, gpa, name)) return why.refuse("no machine {s} on Lima", .{name});
        if (lima.addressOf(io, gpa, name)) |addr| {
            try argv.append(gpa, "ssh");
            try argv.appendSlice(gpa, &pinned);
            try argv.append(gpa, try gpa.print("root@{s}", .{addr}));
        } else try argv.appendSlice(gpa, &.{ "limactl", "shell", name });
    } else return why.refuse(
        "ssh reaches machines here (qemu, firecracker, lima); {t}'s address is in create's summary",
        .{on},
    );
    try argv.appendSlice(gpa, command);
    const err = std.process.replace(io, .{ .argv = argv.items });
    return why.refuse("{s}: {s}", .{ argv.items[0], @errorName(err) });
}

/// howl stop: end the machine howl run keeps, wherever it runs.
fn stopHere(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    if (args.len > 0) return why.refuse(
        "stop takes nothing: it ends howl run's machine; delete NAME ends another",
        .{},
    );
    const on = madeOn(
        io,
        gpa,
        run_name,
    ) orelse return why.refuse("no machine from howl run", .{});
    try remove(io, gpa, run_name, on, why);
    const look: progress.Look = .of(io, Io.File.stderr());
    try Io.File.stderr().writeStreamingAll(
        io,
        try gpa.print(
            "{s} Stopped {s}, the machine howl run kept\n",
            .{ look.check(), run_name },
        ),
    );
}

/// How this machine reaches one under QEMU: its last port but ssh on
/// web_port, as make run forwards it, a URL where the port speaks the web.
/// It ends " · ".
fn reach(gpa: Allocator, ports: []const u16, web_port: u16) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var web: ?u16 = null;
    for (ports) |p| if (p != 22) {
        web = p;
    };
    if (web) |p| {
        const scheme: ?[]const u8 = switch (p) {
            443, 8443 => "https://",
            80, 3000, 8000, 8080, 8081, 9000, 11434 => "http://",
            else => null,
        };
        if (scheme) |sc| {
            try out.print(gpa, "{s}127.0.0.1:{d} · ", .{ sc, web_port });
        } else try out.print(gpa, "127.0.0.1:{d} reaches its :{d} · ", .{ web_port, p });
    }
    return out.items;
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
    arch: Arch,
    src: ?[]const u8,
    why: *Why,
) !AppBuild {
    // Its outputs go by the form's name, as the Makefile's do: a form
    // outside the tree, ../myapp, builds into build/ARCH/myapp.
    const name = std.fs.path.basename(std.mem.trimEnd(u8, form, "/"));
    const dir = src orelse return .{ .app = "APP=", .out = name };
    // The last form's app, which lib/form.zig has checked is an absolute path.
    var at: ?[]const u8 = null;
    for (try chain(io, gpa, form, why)) |f| if (f.spec.get("app")) |a| {
        at = a.scalar.text;
    };
    const where = at orelse return why.refuse(
        "{s} keeps no application (no app in its forms' form.yaml): build on app, python, " ++
            "node, jre, nginx or php",
        .{form},
    );
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const root = try gpa.print("{s}/build/{t}/apps/{s}", .{ cwd, arch, name });
    const staged = try app.stage(io, gpa, dir, root, where, why);
    say(io, "app {s}: {d} files, {d} bytes, sha256 {s}, at {s}", .{
        dir,
        staged.files,
        staged.bytes,
        staged.digest,
        where,
    });
    return .{ .app = try gpa.print("APP={s}", .{root}), .out = try gpa.print("{s}-app", .{name}) };
}

/// Where create keeps what it made a machine of, on any platform: the
/// engine it is on, its disk, which names its MAC, and its config tar,
/// which holds secrets. delete removes it with the machine.
fn machineDir(gpa: Allocator, name: []const u8) ![]const u8 {
    return gpa.print("build/machines/{s}", .{name});
}

/// The GNU make the Makefile is written for: gmake on the BSDs, whose own
/// make is another program.
pub const make_cmd = switch (@import("builtin").os.tag) {
    .freebsd, .netbsd => "gmake",
    else => "make",
};

/// The architectures werewolf builds for, by its own names, which make,
/// the build's directories and a release's files use. Each cloud names
/// them as it does: GCP ARM64 and X86_64, AWS arm64 and x86_64, Azure
/// Arm64 and x64.
pub const Arch = enum { aarch64, x86_64 };

/// This machine's arch, which an engine here runs, if werewolf builds for it.
pub fn hostArch() ?Arch {
    return switch (@import("builtin").cpu.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
        else => null,
    };
}

pub const not_built_here = "this machine is neither aarch64 nor x86_64";

/// A machine an engine here or on Proxmox runs: two CPUs and 2 GiB, as
/// the clouds' smallest that werewolf runs well on (gcp.machine).
pub const local_cpus = 2;
pub const local_mib = 2048;

/// What marks a machine create made, on any platform, and names its form:
/// a cloud's label or tag, Proxmox's description, Lima's template.
pub const form_tag = "werewolf-form";

/// The arch an engine here runs: this machine's.
fn localArch(why: *Why) error{Refused}!Arch {
    return hostArch() orelse why.refuse("{s}, which werewolf builds for", .{not_built_here});
}

/// --arch's spellings, as each world writes them, made werewolf's own:
/// aarch64 (arm64) and x86_64 (x86-64, amd64).
pub fn archName(given: []const u8) ?Arch {
    const names = [_]struct { []const u8, Arch }{
        .{ "aarch64", .aarch64 }, .{ "arm64", .aarch64 },
        .{ "x86_64", .x86_64 },   .{ "x86-64", .x86_64 },
        .{ "amd64", .x86_64 },
    };
    for (names) |n| if (std.ascii.eqlIgnoreCase(given, n[0])) return n[1];
    return null;
}

/// Whether this runs as root, which bhyve and a Firecracker machine's
/// network need.
pub fn isRoot() bool {
    return switch (@import("builtin").os.tag) {
        .linux => std.os.linux.geteuid() == 0,
        else => std.c.geteuid() == 0,
    };
}

pub const arch_refusal = "--arch {s}: aarch64 (arm64), or x86_64 (x86-64, amd64)";

/// Where a machine runs when --on does not say: Lima on macOS, bhyve on
/// FreeBSD, Firecracker on Linux with KVM where its network can be set up
/// without a password, or QEMU; and, when a likelier one was passed over,
/// why, for the summary to say. run and create choose alike.
const Engine = struct { on: Platform, note: ?[]const u8 = null };

pub fn engine(io: Io, gpa: Allocator, given: ?Platform) Engine {
    if (given) |p| return .{ .on = p };
    if (lima.installed(io, gpa)) return .{ .on = .lima };
    if (bhyve.installed(io)) return .{ .on = .bhyve };
    if (firecracker.installed(io, gpa)) {
        if (firecracker.rootReady(io, gpa)) return .{ .on = .firecracker };
        return .{
            .on = .qemu,
            .note = "not Firecracker: its network needs root, and sudo asks a password (sudo " ++
                "-v, then again)",
        };
    }
    return .{ .on = .qemu };
}

/// The platform a machine was made on, as create recorded it.
fn madeOn(io: Io, gpa: Allocator, name: []const u8) ?Platform {
    const path = gpa.print("{s}/engine", .{machineDir(gpa, name) catch return null}) catch
        return null;
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64)) catch return null;
    return std.meta.stringToEnum(Platform, std.mem.trim(u8, text, " \n"));
}

/// The name run gives the one machine it keeps.
const run_name = "werewolf-run";

fn create(io: Io, gpa: Allocator, line: []const []const u8, why: *Why) !void {
    const all = (try adhoc.take(io, gpa, .create, line, why)) orelse return;
    return createFrom(io, gpa, all, why);
}

/// create, its line already taken: the form first, then the name and flags.
fn createFrom(io: Io, gpa: Allocator, all: []const []const u8, why: *Why) !void {
    const began = Io.Clock.awake.now(io);
    const verbose, const some = try verboseFlag(gpa, all);
    const dev, const args = try takeFlag(gpa, some, &.{"--dev"});
    var o = try options(gpa, args, why);
    if (o.out != null or o.check)
        return why.refuse("create takes no -o or -n: howl pack writes a tar", .{});
    const iface = try formInterface(io, gpa, o.form, why);
    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    if (o.help) return help(w, gpa, "create", o.form, iface);
    const name = o.name orelse return why.refuse(
        "create NAME --with FORM: name the machine\n{s}",
        .{usage},
    );
    if (!isMachineName(name)) return why.refuse(
        "{s}: a machine's name is [a-z][a-z0-9-]*, at most 32",
        .{name},
    );

    const eng = engine(io, gpa, o.on);
    const on = eng.on;
    const tell: Tell = .{
        .verbose = verbose,
        .command = try gpa.print("howl {s} {s}", .{
            if (std.mem.eql(u8, name, run_name)) "run" else "create",
            std.mem.join(
                gpa,
                " ",
                if (std.mem.eql(u8, name, run_name)) args[0 .. args.len - 1] else args,
            ) catch o.form,
        }),
        .began = began,
        .note = eng.note,
        .dev = dev,
    };
    if (on == .disk) return why.refuse(
        "--on disk is pack's: howl build and howl pack make a disk and its tar",
        .{},
    );
    if (dev and !on.here()) return why.refuse(
        "--dev is for machines here: a shell on {t} is a release's choice to make",
        .{on},
    );
    if (on.here() and (o.arch != null or o.size != null))
        return why.refuse("{s}: {t} runs this machine's arch", .{ sized_only, on });
    // A form with no DHCP client is given the hypervisor's own network in
    // its config tar, Lima's as make lima's template gives it on the
    // command line, or slirp's under bhyve, unless the flags or --config
    // DIR give one.
    const on_lima = on == .lima;
    // A Firecracker machine's address is its tap's, on the kernel command
    // line; --dns alone is taken there, not in the tar.
    var fc_dns: ?[]const u8 = null;
    if (on == .firecracker) {
        if (o.ip != null or o.gw != null) return why.refuse(
            "--ip and --gw: a Firecracker machine's address is its tap's, 172.16.0.0/16",
            .{},
        );
        fc_dns = o.dns;
        o.dns = null;
    }
    const dhcp = !(on_lima or on == .bhyve) or try hasDhcp(io, gpa, o.form, why);
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
    if (misfit(entries, tar.len, on)) |r| return why.refuse("not for {t}: {s}", .{ on, r });
    if (o.allow_from) |a| {
        if (!on.is(.cloud)) return why.refuse(
            "--allow-from is for --on {s}: {t}'s machines are reached as it says",
            .{ Platform.list(.cloud, ", "), on },
        );
        // Resolved, and checked, before anything is built or made.
        o.allow_from = try allowSource(io, gpa, a, why);
    }
    // What the machine is on, for the verbs that find it again.
    const dir = try machineDir(gpa, name);
    try Dir.cwd().createDirPath(io, dir);
    try writePrivate(io, gpa, try gpa.print("{s}/engine", .{dir}), @tagName(on), why);
    switch (on) {
        .qemu => return createQemu(io, gpa, o, name, tar, tell, why),
        .gcp => return createGcp(io, gpa, o, name, tar, w, why),
        .aws => return createAws(io, gpa, o, name, tar, w, why),
        .azure => return createAzure(io, gpa, o, name, entries, tar, w, why),
        .bhyve => return createBhyve(io, gpa, o, name, tar, tell.dev, w, why),
        .proxmox => return createProxmox(io, gpa, o, name, tar, w, why),
        .firecracker => return createFirecracker(io, gpa, o, name, tar, fc_dns, tell, why),
        .lima => {},
        .disk => unreachable,
    }
    if (!lima.installed(
        io,
        gpa,
    )) return why.refuse("--on lima: no limactl here, or not macOS (brew install lima)", .{});
    const arch = try localArch(why);
    const m = lima.mac(name);
    var managed = try limaManages(io, gpa, o.form, why);
    // Each step a line that says which it is in, and its output in a log.
    const step = try tell.step(gpa, dir);
    var built: ?i64 = null;
    if (try lima.exists(io, gpa, name)) {
        if (o.app != null) return why.refuse(
            "{s} exists, and an application is in the image: howl delete {s}, then create",
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
            const made = try gpa.print("build/{t}/{s}/lima.yaml", .{ arch, ab.out });
            built = (try progress.run(io, gpa, why, &.{
                make_cmd,
                "--no-print-directory",
                try gpa.print("FORM={s}", .{o.form}),
                if (tell.dev) "DEV=1" else "DEV=",
                ab.app,
                "image",
                try gpa.print("build/{t}/disk.img", .{arch}),
                made,
            }, step)).seconds;
            const base = Dir.cwd().readFileAlloc(io, made, gpa, .limited(1 << 20)) catch |err|
                return why.refuse("{s}: {s}", .{ made, @errorName(err) });
            template = try lima.managedTemplate(gpa, base, o.form, config_disk);
        } else {
            const cwd = try std.process.currentPathAlloc(io, gpa);
            const disk = try gpa.print("{s}/{s}/disk.img", .{ cwd, dir });
            built = (try progress.run(io, gpa, why, &.{
                make_cmd,
                "--no-print-directory",
                try gpa.print("FORM={s}", .{o.form}),
                if (tell.dev) "DEV=1" else "DEV=",
                ab.app,
                "disk",
                try gpa.print("DISK={s}", .{disk}),
                if (dhcp)
                    try gpa.print("DISK_ARGS=werewolf.mac={s} console=hvc0", .{m})
                else
                    "DISK_ARGS=console=hvc0",
            }, step)).seconds;
            template = try lima.template(
                gpa,
                o.form,
                @tagName(arch),
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
        var lima_step = step;
        lima_step.make = false;
        lima_step.first = .{ .name = "Creating the VM", .short = "create" };
        _ = try progress.run(
            io,
            gpa,
            why,
            &.{ "limactl", "disk", "import", config_disk, tar_path },
            lima_step,
        );
        const yaml = try gpa.print("{s}/lima.yaml", .{dir});
        try writePrivate(io, gpa, yaml, template, why);
        _ = try progress.run(
            io,
            gpa,
            why,
            &.{ "limactl", "create", "--name", name, "--tty=false", yaml },
            lima_step,
        );
    }
    const tty = Io.File.stdout().isTty(io) catch false;

    if (managed) {
        // Lima waits for its ssh and boot scripts, then for nothing else;
        // the machine is reached through Lima's ssh forward.
        var start_step = step;
        start_step.make = false;
        start_step.first = .{ .name = "Starting the VM, and Lima's ssh", .short = "start" };
        const started = try progress.run(
            io,
            gpa,
            why,
            &.{ "limactl", "start", "--tty=false", name },
            start_step,
        );
        const r = try std.process.run(gpa, io, .{
            .argv = &.{ "limactl", "list", name, "--format", "{{.SSHLocalPort}}" },
        });
        const port = std.mem.trim(u8, r.stdout, " \n");
        if (!tty) try w.print("{s}\t127.0.0.1:{s}\t{s}\n", .{ name, port, o.form });
        try sayUp(io, gpa, began, try gpa.print(
            "{s} is up on Lima, which manages it",
            .{name},
        ), built, .{
            .power_ns = @as(i96, started.seconds) * std.time.ns_per_s,
        }, try gpa.print(
            "{s} · {s}",
            .{ try sshCommand(gpa, name), try stopCommand(gpa, name) },
        ), tell.note);
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
    var spin: progress.Spinner = .init(io);
    const boot = try booting.watch(
        io,
        gpa,
        console_log,
        seen,
        if (dhcp) &m else null,
        before,
        &spin,
    );
    spin.clear();
    starter.kill(io);
    if (!dhcp) {
        if (!boot.up) return why.refuse(
            "{s} is not up after 3 minutes: howl console {s}",
            .{ name, name },
        );
        if (!tty) try w.print("{s}\t-\t{s}\n", .{ name, o.form });
        return sayUp(io, gpa, began, try gpa.print(
            "{s} is up on Lima, on its own network, which this Mac does not reach " ++
                "({s} has no DHCP client)",
            .{ name, o.form },
        ), built, boot, try gpa.print(
            "{s} · {s}",
            .{ try consoleCommand(gpa, name), try stopCommand(gpa, name) },
        ), tell.note);
    }
    const addr = boot.address orelse
        return why.refuse(
            "{s} has no address after 3 minutes: howl console {s}",
            .{ name, name },
        );
    if (!tty) try w.print("{s}\t{s}\t{s}\n", .{ name, addr, o.form });
    const ports = try listens(io, gpa, o.form, why);
    const late = sshReady(io, ports, addr, 22);
    try sayUp(io, gpa, began, try gpa.print(
        "{s} is up on Lima, at {s}{s}",
        .{ name, addr, late },
    ), built, boot, try gpa.print(
        "{s}{s} · {s}",
        .{
            try reachAt(gpa, addr, ports, name),
            try consoleCommand(gpa, name),
            try stopCommand(gpa, name),
        },
    ), tell.note);
}

/// For a form that serves ssh, ports holding 22, wait for its sshd at
/// host:port, so that "up" means reachable; what the line that says it is
/// up adds when it never answered.
fn sshReady(io: Io, ports: []const u16, host: []const u8, port: u16) []const u8 {
    if (std.mem.findScalar(u16, ports, 22) == null) return "";
    var spin: progress.Spinner = .init(io);
    defer spin.clear();
    return if (booting.awaitSsh(io, host, port, &spin)) "" else ", but its ssh does not answer yet";
}

/// That a machine is up, and how long each step took, as minikube says
/// it: the build, the VM's start, the kernel, userland and the address;
/// then how to reach it. Three lines.
fn sayUp(
    io: Io,
    gpa: Allocator,
    began: Io.Timestamp,
    what: []const u8,
    built: ?i64,
    boot: booting.Boot,
    next: []const u8,
    note: ?[]const u8,
) !void {
    const look: progress.Look = .of(io, Io.File.stderr());
    var steps: std.ArrayList(u8) = .empty;
    if (built) |b| try steps.print(gpa, "build {f}", .{progress.Clock{ .seconds = b }});
    if (boot.power_ns) |ns| try steps.print(
        gpa,
        "{s}VM start {f}",
        .{ sep(steps.items), Tenths{ .ns = ns } },
    );
    if (boot.kernel.len > 0)
        try steps.print(
            gpa,
            "{s}kernel {s} · userland {s}",
            .{ sep(steps.items), boot.kernel, boot.userland },
        );
    // An address that came with the boot is no step of its own.
    if (boot.address_ns) |ns| if (ns >= std.time.ns_per_s / 10) {
        try steps.print(gpa, "{s}address {f}", .{ sep(steps.items), Tenths{ .ns = ns } });
    };
    var out: Io.Writer.Allocating = .init(gpa);
    const ow = &out.writer;
    try ow.print(
        "{s} {s}, in {f}\n",
        .{
            look.check(),
            what,
            progress.Clock{ .seconds = began.untilNow(io, .awake).toSeconds() },
        },
    );
    if (steps.items.len > 0) try ow.print("  {f}\n", .{look.dim(steps.items)});
    if (note) |n| try ow.print("  {f}\n", .{look.dim(n)});
    try ow.print("  {s}\n", .{next});
    Io.File.stderr().writeStreamingAll(io, out.written()) catch {};
}

fn sep(so_far: []const u8) []const u8 {
    return if (so_far.len > 0) " · " else "";
}

/// A time to a tenth of a second: 2.1s.
const Tenths = struct {
    ns: i96,

    pub fn format(t: Tenths, w: *Io.Writer) Io.Writer.Error!void {
        const ns: u64 = @intCast(@max(t.ns, 0));
        // Under a second, in milliseconds: 42ms, not 0.0s.
        if (ns < std.time.ns_per_s) return w.print("{d}ms", .{ns / std.time.ns_per_ms});
        const d = ns / (std.time.ns_per_s / 10);
        try w.print("{d}.{d}s", .{ d / 10, d % 10 });
    }
};

/// How this machine reaches one at addr: ssh where it serves ssh, and its
/// last other port, as a URL where that port speaks the web. Each ends " · ".
fn reachAt(gpa: Allocator, addr: []const u8, ports: []const u16, name: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var web: ?u16 = null;
    var ssh = false;
    for (ports) |p| if (p == 22) {
        ssh = true;
    } else {
        web = p;
    };
    if (ssh) try out.print(gpa, "{s} · ", .{try sshCommand(gpa, name)});
    if (web) |p| switch (p) {
        80 => try out.print(gpa, "http://{s} · ", .{addr}),
        443 => try out.print(gpa, "https://{s} · ", .{addr}),
        3000,
        8000,
        8080,
        8081,
        9000,
        11434,
        => try out.print(gpa, "http://{s}:{d} · ", .{ addr, p }),
        else => try out.print(gpa, "{s}:{d} · ", .{ addr, p }),
    };
    return out.items;
}

/// How long create waits for a machine here to say it is up, and how
/// often it looks: a machine is up about a second after it starts, so a
/// coarser look would make create the slower of the two.
const up_ms = 180_000;
const up_poll_ms = 50;

/// Wait for init's up line, or a panic, on the console, past the first seen
/// bytes of its log: for a machine whose address says nothing, or that
/// has none this host reaches. Each look reads what follows seen into one
/// buffer, up to its size, so frequent looks cost no memory; a boot says
/// it is up well within its first MiB.
fn awaitUp(io: Io, gpa: Allocator, log: []const u8, seen: u64) !booting.Outcome {
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
            if (booting.outcome(buf[0..n])) |o| return o;
        } else |_| {}
        try io.sleep(.fromMilliseconds(up_poll_ms), .awake);
    }
    return .late;
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
    dev: bool,
    w: *Io.Writer,
    why: *Why,
) !void {
    if (!bhyve.installed(io))
        return why.refuse("--on bhyve: FreeBSD on x86_64, with vmm loaded (kldload vmm)", .{});
    Dir.cwd().access(io, bhyve.firmware, .{}) catch
        return why.refuse("no {s}: pkg install bhyve-firmware", .{bhyve.firmware});
    const root = bhyve.asRoot(io) catch
        return why.refuse("bhyve needs root, and there is no doas or sudo: pkg install doas", .{});
    const arch = try localArch(why);
    const dir = try machineDir(gpa, name);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const disk = try gpa.print("{s}/{s}/disk.img", .{ cwd, dir });
    const config = try gpa.print("{s}/{s}/config.tar", .{ cwd, dir });
    const log = try gpa.print("{s}/{s}/console.log", .{ cwd, dir });
    const form_file = try gpa.print("{s}/form", .{dir});
    const was = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, form_file, gpa, .limited(256)) catch "",
        " \n",
    );
    if (was.len > 0) try reconfigurable(o, name, was, .bhyve, why);
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
            if (dev) "DEV=1" else "DEV=",
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
    const self = try std.process.executablePathAlloc(io, gpa);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, root);
    try argv.appendSlice(gpa, &.{ "daemon", "-f", "-o", log, self, "_bhyve", name, config });
    try argv.appendSlice(gpa, try bhyve.argv(gpa, name, disk, config, fwds));
    try run(io, why, argv.items);
    say(io, "{s}: waiting for it to boot", .{name});
    switch (try awaitUp(io, gpa, log, seen)) {
        .up => {},
        .panic => return why.refuse("{s} panicked: howl console {s} --on bhyve", .{ name, name }),
        .late => return why.refuse(
            "{s} is not up after 3 minutes: howl console {s} --on bhyve",
            .{ name, name },
        ),
    }
    for (fwds) |fw| say(
        io,
        "{s}: 127.0.0.1:{d} reaches its port {d}",
        .{ name, fw.host, fw.guest },
    );
    if (fwds.len == 0) say(
        io,
        "{s} listens on no port, so nothing reaches it; its console: howl console {s} --on " ++
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
    tell: Tell,
    why: *Why,
) !void {
    if (!firecracker.installed(io, gpa)) return why.refuse(
        "--on firecracker: Linux with /dev/kvm, and firecracker on the PATH (tools/install-deps)",
        .{},
    );
    const root = firecracker.asRoot(io, gpa) catch
        return why.refuse("the machine's tap device needs root, and there is no sudo or doas", .{});
    const user = environ.get("USER") orelse
        return why.refuse("no USER in the environment, whose tap device the machine's is", .{});
    const arch = try localArch(why);
    const dir = try machineDir(gpa, name);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const form_file = try gpa.print("{s}/form", .{dir});
    const was = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, form_file, gpa, .limited(256)) catch "",
        " \n",
    );
    if (was.len > 0) try reconfigurable(o, name, was, .firecracker, why);
    if (firecracker.running(io, gpa, dir)) |pid| {
        say(io, "{s}: replacing its config, with a hard stop", .{name});
        try firecracker.stop(io, gpa, dir, pid, why);
    }
    const n = try firecracker.net(gpa, name);
    var built: ?i64 = null;
    if (was.len == 0) {
        const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
        built = (try progress.run(io, gpa, why, &.{
            make_cmd,
            "--no-print-directory",
            try gpa.print("FORM={s}", .{o.form}),
            if (tell.dev) "DEV=1" else "DEV=",
            ab.app,
            "slot",
            try firecracker.kernelPath(gpa, arch),
        }, try tell.step(gpa, dir))).seconds;
        const dns = dns_given orelse firecracker.hostDns(io, gpa) orelse return why.refuse(
            "--dns ADDR: this host's resolvers are all on loopback, which the machine cannot reach",
            .{},
        );
        const image_args = std.mem.trim(u8, Dir.cwd().readFileAlloc(
            io,
            try gpa.print("build/{t}/{s}/meta/usr/share/werewolf/cmdline", .{ arch, ab.out }),
            gpa,
            .limited(4096),
        ) catch |err| return why.refuse(
            "{s}: no cmdline in its image: {s}",
            .{ o.form, @errorName(err) },
        ), " \n");
        const data = try gpa.print("{s}/{s}/data.img", .{ cwd, dir });
        // The guest's /data, sparse, and this user's alone: it holds what
        // the machine keeps, secrets among it.
        const data_file = Dir.cwd().createFile(
            io,
            data,
            .{ .truncate = false, .permissions = .fromMode(0o600) },
        ) catch |err| return why.refuse("{s}: {s}", .{ data, @errorName(err) });
        defer data_file.close(io);
        data_file.setLength(io, 8192 << 20) catch |err|
            return why.refuse("{s}: {s}", .{ data, @errorName(err) });
        try writePrivate(io, gpa, try gpa.print("{s}/vm.json", .{dir}), try firecracker.config(
            gpa,
            try gpa.print("{s}/{s}", .{ cwd, try firecracker.kernelPath(gpa, arch) }),
            try gpa.print("{s}/build/{t}/{s}/slot/stage0.zst", .{ cwd, arch, ab.out }),
            try firecracker.bootArgs(gpa, image_args, n, dns),
            data,
            try gpa.print("{s}/{s}/config.tar", .{ cwd, dir }),
            try gpa.print("{s}/build/{t}/{s}/slot/root.erofs", .{ cwd, arch, ab.out }),
            try gpa.print("{s}/{s}/firecracker.log", .{ cwd, dir }),
            n,
        ), why);
        try writePrivate(io, gpa, form_file, o.form, why);
    }
    try writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), tar, why);
    const log = try gpa.print("{s}/{s}/console.log", .{ cwd, dir });
    const seen = if (Dir.cwd().statFile(io, log, .{})) |st| st.size else |_| 0;
    try firecracker.networkUp(io, gpa, root, n, user, why);
    const self = try std.process.executablePathAlloc(io, gpa);
    // The supervisor keeps the console itself; nothing of its own is said
    // anywhere else.
    const launched = Io.Clock.awake.now(io);
    var starter = std.process.spawn(io, .{
        .argv = &.{ "setsid", "-f", self, "_firecracker", try gpa.print("{s}/{s}", .{ cwd, dir }) },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch |err| return why.refuse("setsid: {s}", .{@errorName(err)});
    _ = starter.wait(io) catch {};
    var spin: progress.Spinner = .init(io);
    const watched = Io.Clock.awake.now(io);
    var boot = try booting.watch(io, gpa, log, seen, null, 0, &spin);
    spin.clear();
    // The VM's start: from Firecracker's launch until its console spoke.
    if (boot.power_ns) |ns| boot.power_ns = ns + launched.durationTo(watched).toNanoseconds();
    if (boot.ended) return why.refuse(
        "{s}: Firecracker exited before it was up: {s}",
        .{ name, try consoleCommand(gpa, name) },
    );
    if (!boot.up) return why.refuse(
        "{s} is not up after 3 minutes: {s}",
        .{ name, try consoleCommand(gpa, name) },
    );
    if (!(Io.File.stdout().isTty(io) catch false)) {
        var out = Io.File.stdout().writerStreaming(io, &.{});
        try out.interface.print("{s}\t{s}\t{s}\n", .{ name, n.guest, o.form });
    }
    const ports = try listens(io, gpa, o.form, why);
    const late = sshReady(io, ports, n.guest, 22);
    return sayUp(io, gpa, tell.began, try gpa.print(
        "{s} is up here, under Firecracker, at {s}{s}",
        .{ name, n.guest, late },
    ), built, boot, try gpa.print(
        "{s}{s} · {s}",
        .{
            try reachAt(gpa, n.guest, ports, name),
            try consoleCommand(gpa, name),
            try stopCommand(gpa, name),
        },
    ), tell.note);
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
    const arch = o.arch orelse .x86_64;
    if (arch != .x86_64)
        return why.refuse("--on proxmox: x86_64 machines only; its nodes are", .{});
    if (o.size != null) return why.refuse("--size is for --on {s}", .{Platform.list(.cloud, ", ")});
    const dir = try machineDir(gpa, name);
    const tar_path = try gpa.print("{s}/config.tar", .{dir});
    try writePrivate(io, gpa, tar_path, tar, why);
    var vmid: []const u8 = undefined;
    if (try proxmox.find(io, gpa, p, name, why)) |m| {
        try reconfigurable(o, name, m.form, .proxmox, why);
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
            "{s} panicked: howl console {s} --on proxmox",
            .{ name, name },
        ),
        .late => return why.refuse(
            "{s} not up after 3 minutes: howl console {s} --on proxmox",
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

/// The TCP ports form serves, as its chain's net declares them
/// (lib/form.zig): listen tcp/80 tcp/443, in order, once each.
fn listens(io: Io, gpa: Allocator, form: []const u8, why: *Why) ![]const u16 {
    const c = try chain(io, gpa, form, why);
    var f: forms.Failure = .{};
    return forms.listens(gpa, c, &f) catch |err| switch (err) {
        error.Form => why.refuse("{s}", .{f.text}),
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// Whether form takes an address by DHCP: whether its chain runs
/// dhcp-client, as its form.yaml's programs say.
fn hasDhcp(io: Io, gpa: Allocator, form: []const u8, why: *Why) !bool {
    for (try chain(io, gpa, form, why)) |f|
        for (try f.items(gpa, "programs")) |p| if (std.mem.eql(u8, p, "dhcp-client")) return true;
    return false;
}

/// Whether Lima can manage a machine of form: one that answers Lima's ssh
/// as Lima's user and runs its readiness probes, which want sshd and bash
/// among the packages its chain's apko configs install (lib/form.zig).
/// Any other starts on vzNAT, unmanaged, and is stopped hard.
fn limaManages(io: Io, gpa: Allocator, form: []const u8, why: *Why) !bool {
    const c = try chain(io, gpa, form, why);
    var f: forms.Failure = .{};
    const config = forms.apko(io, gpa, Dir.cwd(), c, &.{}, &f) catch |err| switch (err) {
        error.Form => return why.refuse("{s}", .{f.text}),
        error.OutOfMemory => return error.OutOfMemory,
    };
    var sshd = false;
    var bash = false;
    const packages = (config.get("contents") orelse return false).get("packages") orelse
        return false;
    if (packages != .list) return false;
    for (packages.list) |p| if (p == .scalar) {
        if (std.mem.eql(u8, p.scalar.text, "openssh-server")) sshd = true;
        if (std.mem.eql(u8, p.scalar.text, "bash")) bash = true;
    };
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
        return why.refuse("{s} was not made by howl create; it is Lima's alone", .{name});
    if (!std.mem.eql(u8, was, form)) return why.refuse(
        "{s} runs {s}, not {s}: another form is another disk; howl delete {s}, then create",
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

/// What a new cloud machine lets in: nothing, but what --allow-from
/// names, which create opens itself on the TCP ports the form listens on;
/// without it, create says the commands that would, to paste as they are,
/// for this host's address alone ($ME). delete removes what they make.
/// cloud is gcp, aws or azure, and p its place.
fn sayOpen(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    form: []const u8,
    comptime cloud: type,
    p: cloud.Place,
    allow_from: ?[]const u8,
    why: *Why,
) !void {
    const ports = try listens(io, gpa, form, why);
    if (ports.len == 0)
        return say(io, "{s}: {s} listens on no TCP port; nothing reaches it", .{ name, form });
    if (allow_from) |source| {
        for (try cloud.openArgs(gpa, p, name, ports, source)) |argv| try run(io, why, argv);
        return say(io, "{s}: open to {s} on {s}", .{ name, source, try portList(gpa, ports) });
    }
    var text: Io.Writer.Allocating = .init(gpa);
    try openText(
        &text.writer,
        name,
        try portList(gpa, ports),
        try cloud.openArgs(gpa, p, name, ports, "$ME/32"),
    );
    Io.File.stderr().writeStreamingAll(io, text.written()) catch {};
}

/// What create says for a machine nothing reaches: why, then commands,
/// one a line, ready to paste into sh, bash or zsh.
fn openText(
    w: *Io.Writer,
    name: []const u8,
    ports: []const u8,
    commands: []const []const []const u8,
) !void {
    try w.print(
        "howl: {s}: nothing reaches it yet; to let this host in on {s}, or --allow-from:\n" ++
            "ME=$(curl -fsS https://checkip.amazonaws.com)\n",
        .{ name, ports },
    );
    for (commands) |argv| {
        for (argv, 0..) |arg, i| {
            if (i > 0) try w.writeByte(' ');
            try shellWord(w, arg);
        }
        try w.writeByte('\n');
    }
}

/// A word as a shell reads it back: as it is, or in double quotes where it
/// holds more than letters, digits and . _ / : , = @ - (as "$ME/32" does,
/// which the shell then expands). Only werewolf's own words come here,
/// none with a quote or backslash.
fn shellWord(w: *Io.Writer, word: []const u8) !void {
    for (word) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and std.mem.findScalar(u8, "._/:,=@-", ch) == null) {
            return w.print("\"{s}\"", .{word});
        }
    } else if (word.len == 0) return w.writeAll("\"\"");
    try w.writeAll(word);
}

/// "port 22", "ports 22 8080".
fn portList(gpa: Allocator, ports: []const u16) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, if (ports.len == 1) "port" else "ports");
    for (ports) |port| try out.print(gpa, " {d}", .{port});
    return out.items;
}

/// --allow-from's source, checked: me, this host's public IPv4 address as
/// checkip.amazonaws.com sees it, or an IPv4 address and prefix.
fn allowSource(io: Io, gpa: Allocator, given: []const u8, why: *Why) ![]const u8 {
    if (!std.mem.eql(u8, given, "me")) {
        if (!isCidr(given)) return why.refuse(
            "--allow-from {s}: me, or an IPv4 address and prefix: 203.0.113.7/32, 0.0.0.0/0",
            .{given},
        );
        return given;
    }
    const r = std.process.run(gpa, io, .{
        .argv = &.{ "curl", "-fsS", "-m", "10", "https://checkip.amazonaws.com" },
    }) catch |err| return why.refuse("--allow-from me: curl: {s}", .{@errorName(err)});
    const me = try gpa.print("{s}/32", .{std.mem.trim(u8, r.stdout, " \r\n")});
    if (r.term != .exited or r.term.exited != 0 or !isCidr(me)) return why.refuse(
        "--allow-from me: checkip.amazonaws.com did not say this host's address; give it: " ++
            "--allow-from ADDRESS/32",
        .{},
    );
    return me;
}

/// An IPv4 address and a prefix of 0 to 32, in digits: 10.0.0.0/8.
fn isCidr(s: []const u8) bool {
    const slash = std.mem.findScalar(u8, s, '/') orelse return false;
    const bits = s[slash + 1 ..];
    if (bits.len == 0 or bits.len > 2) return false;
    for (bits) |c| if (!std.ascii.isDigit(c)) return false;
    if ((std.fmt.parseInt(u8, bits, 10) catch return false) > 32) return false;
    _ = std.Io.net.Ip4Address.parse(s[0..slash], 0) catch return false;
    return true;
}

/// A second create of a machine keeps its rules as its owner left them:
/// --allow-from opens a new machine's ports.
fn newOnly(o: Options, name: []const u8, on: Platform, why: *Why) error{Refused}!void {
    if (o.allow_from == null) return;
    return why.refuse(
        "{s} exists, and keeps its rules as they are: --allow-from opens a new machine's ports " ++
            "(howl delete {s} --on {t}, then create)",
        .{ name, name, on },
    );
}

/// A machine in a cloud: its architecture, --arch or this host's, where
/// create keeps its files, and its config tar in base64, as the clouds
/// take user data, kept private there.
const Cloud = struct { arch: Arch, dir: []const u8, b64: []const u8 };

fn cloudMachine(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    why: *Why,
) !Cloud {
    const arch = o.arch orelse hostArch() orelse
        return why.refuse("{s}: --arch", .{not_built_here});
    const dir = try machineDir(gpa, name);
    const b64 = try gpa.print("{s}/config.b64", .{dir});
    const encoded = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(tar.len));
    try writePrivate(io, gpa, b64, std.base64.standard.Encoder.encode(encoded, tar), why);
    return .{ .arch = arch, .dir = dir, .b64 = b64 };
}

/// Whether a machine that exists, made of the form was ("" if not made by
/// create), may take a new config: the same form, and no --app, since an
/// application is in the image.
fn notMade(name: []const u8, on: Platform, why: *Why) error{Refused} {
    return why.refuse("{s} was not made by howl create; it is {t}'s alone", .{ name, on });
}

fn reconfigurable(o: Options, name: []const u8, was: []const u8, on: Platform, why: *Why) !void {
    if (o.app != null) return why.refuse(
        "{s} exists, and an application is in the image: howl delete {s} --on {t}, then create",
        .{ name, name, on },
    );
    if (was.len == 0) return notMade(name, on, why);
    if (!std.mem.eql(u8, was, o.form)) return why.refuse(
        "{s} runs {s}, not {s}: another form is another image; howl delete {s} --on {t}, " ++
            "then create",
        .{ name, was, o.form, name, on },
    );
}

/// The release's disk.qcow2 of the form, with --app's application, built
/// if stale.
fn releaseDisk(io: Io, gpa: Allocator, o: Options, arch: Arch, why: *Why) ![]const u8 {
    const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
    const disk = try gpa.print("build/{t}/{s}/disk.qcow2", .{ arch, ab.out });
    try run(io, why, &.{
        make_cmd,
        "--no-print-directory",
        try gpa.print("FORM={s}", .{o.form}),
        try gpa.print("ARCH={t}", .{arch}),
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
    var made = false;
    if (try gcp.formOf(io, gpa, p, name, why)) |was| {
        try reconfigurable(o, name, was, .gcp, why);
        try newOnly(o, name, .gcp, why);
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
        made = true;
    }
    switch (try gcp.awaitUp(io, gpa, p, name)) {
        .up => {},
        .panic => return why.refuse("{s} panicked: howl console {s} --on gcp", .{ name, name }),
        .late => return why.refuse(
            "{s} not up after 5 minutes: howl console {s} --on gcp",
            .{ name, name },
        ),
    }
    try w.print("{s}\t{s}\t{s}\n", .{ name, gcp.address(io, gpa, p, name) orelse "?", o.form });
    if (made) try sayOpen(io, gpa, name, o.form, gcp, p, o.allow_from, why);
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
    var made = false;
    if (try aws.find(io, gpa, p, name, why)) |i| {
        try reconfigurable(o, name, i.form, .aws, why);
        try newOnly(o, name, .aws, why);
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
        made = true;
    }
    switch (try aws.awaitUp(io, gpa, p, id)) {
        .up => {},
        .panic => return why.refuse("{s} panicked: howl console {s} --on aws", .{ name, name }),
        .late => return why.refuse(
            "{s} not up after 5 minutes: howl console {s} --on aws",
            .{ name, name },
        ),
    }
    try w.print("{s}\t{s}\t{s}\n", .{ name, aws.address(io, gpa, p, id) orelse "?", o.form });
    if (made) try sayOpen(io, gpa, name, o.form, aws, p, o.allow_from, why);
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
    if (try azure.find(io, gpa, p, name, why)) |vm| {
        try reconfigurable(o, name, vm.form, .azure, why);
        try newOnly(o, name, .azure, why);
        say(io, "{s}: replacing its config, and restarting it", .{name});
        const before = if (azure.console(io, gpa, p, name)) |text| azure.mark(text) else "";
        try azure.reconfigure(io, gpa, p, name, tar, c.dir, why);
        return azureUp(io, gpa, p, name, o.form, before, w, why);
    }
    const disk = try releaseDisk(io, gpa, o, c.arch, why);
    const image = try azure.ensureImage(io, gpa, p, o.form, c.arch, disk, c.dir, why);
    say(io, "{s}: starting it in {s}, {s}", .{ name, p.group, p.location });
    try azure.create(io, gpa, p, name, o.form, c.arch, o.size, image, tar_path, why);
    try azureUp(io, gpa, p, name, o.form, "", w, why);
    try sayOpen(io, gpa, name, o.form, azure, p, o.allow_from, why);
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
            "{s} panicked: howl console {s} --on azure",
            .{ name, name },
        ),
        .late => return why.refuse(
            "{s} not up after 5 minutes: howl console {s} --on azure",
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
    const syntax = "upload DISK --on " ++ comptime Platform.list(.cloud, "|");
    if (args.len < 2) return why.refuse(syntax, .{});
    var i: usize = 1;
    const flag, const value = try flagValue(args, &i, why);
    const on = std.meta.stringToEnum(Platform, value) orelse .disk;
    if (i + 1 != args.len or !std.mem.eql(u8, flag, "--on") or !on.is(.cloud))
        return why.refuse(syntax, .{});
    const disk = args[0];
    const base = std.fs.path.basename(disk);
    const stem = if (std.mem.endsWith(u8, base, "-disk.qcow2"))
        base[0 .. base.len - "-disk.qcow2".len]
    else
        return why.refuse(
            "{s}: a release's FORM-ARCH-disk.qcow2, as howl build makes one",
            .{disk},
        );
    const dash = std.mem.findScalarLast(
        u8,
        stem,
        '-',
    ) orelse return why.refuse("{s}: no FORM-ARCH", .{disk});
    const arch = std.meta.stringToEnum(Arch, stem[dash + 1 ..]) orelse return why.refuse(
        "{s}: arch {s} is neither aarch64 nor x86_64",
        .{ disk, stem[dash + 1 ..] },
    );
    const form = stem[0..dash];
    // The upload's own directory beside the disk, for its raw copy and
    // the rest: two uploads at once, of one disk to two clouds, or of
    // both arches, never write each other's.
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const work = try gpa.print("{s}/upload-{x}", .{
        std.fs.path.dirname(disk) orelse ".",
        std.mem.readInt(u64, &nonce, .little),
    });
    try Dir.cwd().createDirPath(io, work);
    defer Dir.cwd().deleteTree(io, work) catch {};
    const image = switch (on) {
        .azure => try azure.ensureImage(
            io,
            gpa,
            try azure.place(io, gpa, why),
            form,
            arch,
            disk,
            work,
            why,
        ),
        .aws => try aws.ensureImage(
            io,
            gpa,
            try aws.place(io, gpa, why),
            form,
            arch,
            disk,
            work,
            why,
        ),
        .gcp => try gcp.ensureImage(
            io,
            gpa,
            try gcp.place(io, gpa, why),
            form,
            arch,
            disk,
            work,
            why,
        ),
        else => unreachable,
    };
    var out = Io.File.stdout().writerStreaming(io, &.{});
    try out.interface.print("{s}\n", .{image});
}

/// delete, console and ssh: NAME, and --on.
fn machineArgs(
    io: Io,
    gpa: Allocator,
    args: []const []const u8,
    why: *Why,
) !struct { []const u8, Platform } {
    const syntax = "[NAME] [--on " ++ comptime Platform.list(.made, "|") ++ "]";
    var name: ?[]const u8 = null;
    var on: ?Platform = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (args[i].len > 0 and args[i][0] == '-') {
            const flag, const value = try flagValue(args, &i, why);
            if (!std.mem.eql(u8, flag, "--on") or on != null)
                return why.refuse("{s}: {s}", .{ flag, syntax });
            const p = std.meta.stringToEnum(Platform, value) orelse .disk;
            if (!p.is(.made)) return why.refuse("--on {s}: {s}", .{ value, syntax });
            on = p;
        } else if (name == null) {
            name = args[i];
        } else return why.refuse("{s}: {s}", .{ args[i], syntax });
    }
    // No name: the machine howl run keeps.
    const n = name orelse run_name;
    if (!isMachineName(n)) return why.refuse("{s}: not a machine's name", .{n});
    // A machine create made, it recorded the platform of.
    return .{ n, on orelse madeOn(io, gpa, n) orelse engine(io, gpa, null).on };
}

fn delete(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const name, const on = try machineArgs(io, gpa, args, why);
    try remove(io, gpa, name, on, why);
    say(io, "{s}: deleted, with its /data", .{name});
}

/// name, on on, gone, with its disks and files here; said by the caller.
/// A machine of that name that howl create did not make, as its missing
/// form label or tag says, is refused, as create refuses it: it is its
/// owner's, not howl's to delete.
fn remove(io: Io, gpa: Allocator, name: []const u8, on: Platform, why: *Why) !void {
    const dir = try machineDir(gpa, name);
    switch (on) {
        .qemu => _ = try qemu.stop(io, gpa, dir),
        .gcp => {
            // The machine and its disk, not the image, which others may share.
            const p = try gcp.place(io, gpa, why);
            if (try gcp.formOf(io, gpa, p, name, why)) |was| {
                if (was.len == 0) return notMade(name, .gcp, why);
                try gcp.delete(io, gpa, p, name, why);
            }
        },
        .aws => {
            // The instance, its volume and its security group, not the AMI.
            const p = try aws.place(io, gpa, why);
            const i = try aws.find(io, gpa, p, name, why);
            if (i) |m| if (m.form.len == 0) return notMade(name, .aws, why);
            try aws.delete(io, gpa, p, name, i, why);
        },
        .azure => {
            // The VM, its disk, NIC and network, not the image.
            const p = try azure.place(io, gpa, why);
            const vm = try azure.find(io, gpa, p, name, why);
            if (vm) |v| if (v.form.len == 0) return notMade(name, .azure, why);
            try azure.delete(io, gpa, p, name, vm, why);
        },
        .proxmox => {
            // The VM and its disks, not the image, which others may share.
            const p = try proxmox.place(environ, why);
            const vm = try proxmox.find(io, gpa, p, name, why);
            if (vm) |m| try proxmox.delete(io, gpa, p, m, name, why);
        },
        .firecracker => {
            // Its tar first, so the supervisor runs it no more; then its
            // Firecracker, killed; then its network, as root.
            Dir.cwd().deleteFile(io, try gpa.print("{s}/config.tar", .{dir})) catch {};
            if (firecracker.running(
                io,
                gpa,
                dir,
            )) |pid| try firecracker.stop(io, gpa, dir, pid, why);
            if (firecracker.asRoot(io, gpa)) |root|
                firecracker.networkDown(io, gpa, root, try firecracker.net(gpa, name))
            else |_|
                say(io, "{s}: no sudo or doas, so its tap device and rules stay", .{name});
        },
        .bhyve => {
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
        },
        .lima => {
            if (try lima.exists(io, gpa, name)) {
                const d = try lima.dir(io, gpa, name) orelse
                    return why.refuse("no machine {s}", .{name});
                const yaml = Dir.cwd().readFileAlloc(
                    io,
                    try gpa.print("{s}/lima.yaml", .{d}),
                    gpa,
                    .limited(1 << 20),
                ) catch |err| return why.refuse("{s}/lima.yaml: {s}", .{ d, @errorName(err) });
                if (lima.formOf(yaml) == null) return notMade(name, .lima, why);
                // Quietly, unless it fails: then limactl's last words.
                const r = std.process.run(gpa, io, .{
                    .argv = &.{ "limactl", "delete", "-f", name },
                }) catch |err| return why.refuse("limactl: {s}", .{@errorName(err)});
                if (r.term != .exited or r.term.exited != 0) {
                    const said = std.mem.trim(
                        u8,
                        if (r.stderr.len > 0) r.stderr else r.stdout,
                        " \n",
                    );
                    return why.refuse("limactl failed: {s}", .{said[said.len -| 400..]});
                }
            }
            _ = std.process.run(gpa, io, .{
                .argv = &.{ "limactl", "disk", "delete", try gpa.print("{s}-config", .{name}) },
            }) catch {};
        },
        .disk => unreachable,
    }
    // What create kept of it: its disks, and its config tar, which holds
    // secrets.
    Dir.cwd().deleteTree(io, dir) catch {};
}

fn console(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const name, const on = try machineArgs(io, gpa, args, why);
    const d = try machineDir(gpa, name);
    if (on == .qemu) {
        if (qemu.running(io, gpa, d) == null) return why.refuse(
            "no machine {s} running under QEMU{s}",
            .{ name, if (std.mem.eql(u8, name, run_name)) ": howl run --with FORM" else "" },
        );
        return qemu.attach(io, gpa, d);
    }
    if (on == .gcp) {
        const p = try gcp.place(io, gpa, why);
        const text = gcp.console(
            io,
            gpa,
            p,
            name,
        ) orelse return why.refuse("no machine {s} in {s}", .{ name, p.zone });
        return show(io, gpa, text[text.len -| (64 << 10)..]);
    }
    if (on == .aws) {
        const p = try aws.place(io, gpa, why);
        const i = try aws.find(io, gpa, p, name, why) orelse
            return why.refuse("no machine {s} in {s}", .{ name, p.region });
        const text = aws.console(io, gpa, p, i.id) orelse
            return why.refuse("{s}: no console yet; AWS keeps it from shortly after boot", .{name});
        return show(io, gpa, text);
    }
    if (on == .azure) {
        const p = try azure.place(io, gpa, why);
        const text = azure.console(io, gpa, p, name) orelse
            return why.refuse("no machine {s} in {s}, or no boot diagnostics", .{ name, p.group });
        return show(io, gpa, text[text.len -| (64 << 10)..]);
    }
    if (on == .proxmox) {
        const p = try proxmox.place(environ, why);
        const text = proxmox.console(io, gpa, p, name, 0) orelse
            return why.refuse("no console for {s} on {s}", .{ name, p.host });
        return show(io, gpa, text[text.len -| (64 << 10)..]);
    }
    const path = if (on == .bhyve or on == .firecracker)
        try gpa.print("{s}/console.log", .{d})
    else
        try gpa.print("{s}/serialv.log", .{
            try lima.dir(io, gpa, name) orelse return why.refuse("no machine {s}", .{name}),
        });
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 20)) catch |err|
        return why.refuse("{s}: {s}", .{ path, @errorName(err) });
    // The last 64 KiB: the boot, and what followed.
    try show(io, gpa, text[text.len -| (64 << 10)..]);
}

/// A guest's console text on stdout: to a terminal, without what would
/// drive it (escapes, control characters, C1 codes), since the guest, not
/// howl, wrote it; to a pipe or file, as it is.
fn show(io: Io, gpa: Allocator, text: []const u8) !void {
    const out = Io.File.stdout();
    try out.writeStreamingAll(io, if (out.isTty(io) catch false) try inert(gpa, text) else text);
}

/// text with only newlines, tabs and printable characters left: every
/// other C0 byte, DEL, and C1 control, raw or as UTF-8, dropped.
fn inert(gpa: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = try .initCapacity(gpa, text.len);
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == 0xc2 and i + 1 < text.len and text[i + 1] >= 0x80 and text[i + 1] <= 0x9f) {
            i += 1;
            continue;
        }
        if ((c < 0x20 and c != '\n' and c != '\t') or c == 0x7f) continue;
        out.appendAssumeCapacity(c);
    }
    return out.toOwnedSlice(gpa);
}

test inert {
    const a = testing.allocator;
    const got = try inert(a, "ok\x1b]0;title\x07 \x1b[2Jdone\r\n\xc2\x9b31m\xc3\xa9\ttab\x7f");
    defer a.free(got);
    try testing.expectEqualStrings("ok]0;title [2Jdone\n31m\xc3\xa9\ttab", got);
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
/// A name a config tar may hold, plain as every reader of one takes it
/// (settings.entryName), and short enough for ustar's name field.
fn isTarName(s: []const u8) bool {
    const n = settings.entryName(s) orelse return false;
    return n.len > 0 and n.len <= max_name and n.len == s.len;
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
    _ = adhoc;
    _ = oci;
    _ = @import("progress.zig");
    _ = @import("qemu.zig");
    _ = @import("boot.zig");
}

const bastion =
    \\exec    /usr/bin/sshd -D -e -f /etc/ssh/sshd_config
    \\user    bastion
    \\pledge  stdio
    \\config  authorized-keys /run/config/bastion/authorized_keys
    \\config  settings /run/config/bastion/settings.json   # may be missing
    \\setting destinations addrport... as PermitOpen
    \\render  conf destinations
;

test archName {
    for ([_]struct { []const u8, Arch }{
        .{ "aarch64", .aarch64 }, .{ "arm64", .aarch64 }, .{ "ARM64", .aarch64 },
        .{ "x86_64", .x86_64 },   .{ "x86-64", .x86_64 }, .{ "amd64", .x86_64 },
        .{ "AMD64", .x86_64 },
    }) |c| try testing.expectEqual(c[1], archName(c[0]).?);
    for ([_][]const u8{ "", "x86", "i386", "arm", "riscv64", "x64", "aarch64 " }) |bad|
        try testing.expectEqual(null, archName(bad));
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: Why = .{};
    const o = try options(arena.allocator(), &.{ "prod", "web", "--arch", "amd64" }, &why);
    try testing.expectEqual(.x86_64, o.arch.?);
    try testing.expectError(
        error.Refused,
        options(arena.allocator(), &.{ "prod", "--arch", "i386" }, &why),
    );
    try testing.expectEqual(
        .aarch64,
        (try buildOptions(&.{ "--arch=arm64", "prod" }, null, &why)).arch,
    );
}

test buildOptions {
    var why: Why = .{};
    const o = try buildOptions(&.{ "bastion", "--format", "vhd", "-o", "out" }, .aarch64, &why);
    try testing.expectEqualStrings("bastion", o.form);
    try testing.expectEqualStrings("out", o.dir);
    try testing.expectEqual(.aarch64, o.arch);
    try testing.expectEqual(DiskFormat.vhd, o.format);
    try testing.expectEqual(
        .x86_64,
        (try buildOptions(&.{ "--arch", "x86_64", "prod" }, null, &why)).arch,
    );
    for ([_][]const []const u8{
        &.{},
        &.{ "a", "b" },
        &.{ "a", "--arch", "riscv64" },
        &.{ "a", "--format", "zip" },
        &.{ "a", "--on", "gcp" },
        &.{ "a", "-o" },
    }) |args| try testing.expectError(error.Refused, buildOptions(args, .aarch64, &why));
    try testing.expectError(error.Refused, buildOptions(&.{"a"}, null, &why));
}

test flagValue {
    var why: Why = .{};
    const args = [_][]const u8{ "--on", "gcp", "--arch=arm64", "--size" };
    var i: usize = 0;
    const a = try flagValue(&args, &i, &why);
    try testing.expectEqualStrings("--on", a[0]);
    try testing.expectEqualStrings("gcp", a[1]);
    try testing.expectEqual(1, i);
    i = 2;
    const b = try flagValue(&args, &i, &why);
    try testing.expectEqualStrings("--arch", b[0]);
    try testing.expectEqualStrings("arm64", b[1]);
    try testing.expectEqual(2, i);
    i = 3;
    try testing.expectError(error.Refused, flagValue(&args, &i, &why));
}

test "Platform: lists and kinds" {
    try testing.expectEqualStrings(
        "lima|bhyve|firecracker|qemu|proxmox|gcp|aws|azure",
        Platform.list(.made, "|"),
    );
    try testing.expectEqualStrings("gcp, aws, azure", Platform.list(.cloud, ", "));
    try testing.expect(Platform.qemu.here() and !Platform.proxmox.here());
    try testing.expect(!Platform.disk.is(.made));
}

test interface {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const i = try interface(gpa, &.{.{ .name = "sshd", .path = "", .text = bastion }}, &why);
    try testing.expectEqual(@as(usize, 1), i.files.len);
    try testing.expectEqualStrings("bastion/authorized_keys", i.files[0].path);
    try testing.expectEqualStrings("bastion/settings.json", i.settings[0].path);
    try testing.expectEqualStrings("PermitOpen", i.settings[0].decl[0].key.?);

    // Each a service file leash takes, but for what follows its first lines.
    const head = "exec /a\nuser x\npledge stdio\n";
    const refused = [_][]const [2][]const u8{
        // The same flag from two services: a form on prod-ssh with a bastion.
        &.{
            .{ "a", head ++ "config authorized-keys /run/config/a/k" },
            .{ "b", head ++ "config authorized-keys /run/config/b/k" },
        },
        &.{.{ "a", head ++ "config hostname /run/config/a/h" }},
        &.{.{ "a", head ++ "config key /run/config/hostname" }},
        &.{
            .{ "a", head ++ "config k1 /run/config/x" },
            .{ "b", head ++ "config k2 /run/config/x" },
        },
        &.{.{ "a", head ++ "config key /etc/shadow" }},
        &.{.{ "a", head ++ "setting a ip\nrender conf x" }},
        &.{.{
            "a",
            head ++ "setting a string\nrender conf x\nconfig settings /run/config/a/s.json",
        }},
        // What leash refuses, pack does: render twice, an optional settings.
        &.{.{
            "a",
            head ++ "config settings /run/config/a/s.json\nsetting a ip\nrender conf x\n" ++
                "render conf y",
        }},
        &.{.{ "a", head ++ "config settings /run/config/a/s.json optional" }},
        &.{.{ "a", head ++ "config ../k /run/config/a/k" }},
        &.{.{ "a", "config k /run/config/a/k" }},
    };
    for (refused) |texts| {
        var svcs: [2]forms.Service = undefined;
        for (texts, svcs[0..texts.len]) |t, *s| s.* = .{ .name = t[0], .path = "", .text = t[1] };
        try testing.expectError(error.Refused, interface(gpa, svcs[0..texts.len], &why));
    }
}

test options {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const o = try options(
        gpa,
        &.{
            "-n",      "--on",              "aws", "--destinations=10.0.0.1:22",
            "bastion", "--authorized-keys", "k",
        },
        &why,
    );
    try testing.expectEqualStrings("bastion", o.form);
    try testing.expect(o.check and o.on.? == .aws);
    try testing.expectEqualStrings("destinations", o.flags[0][0]);
    try testing.expectEqualStrings("k", o.flags[1][1]);
    try testing.expectEqual(
        Platform.proxmox,
        (try options(gpa, &.{ "x", "--on", "proxmox" }, &why)).on.?,
    );
    for ([_][]const []const u8{
        &.{},
        &.{ "a", "b", "c" },
        &.{ "a", "--authorized-keys" },
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
    const i = try interface(gpa, &.{.{ .name = "sshd", .path = "", .text = bastion }}, &why);
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

    // A url may hold a comma, so a list of them is given by repeating.
    var u: json.ObjectMap = .empty;
    const hooks: settings.Setting = .{ .name = "hooks", .type = .url, .list = true };
    try setValue(gpa, &u, hooks, "https://a.example/?x=1,2", &why);
    try setValue(gpa, &u, hooks, "https://b.example/", &why);
    try testing.expectEqual(@as(usize, 2), u.get("hooks").?.array.items.len);
}

test "the hostname and data key, checked as init checks them" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const none: Interface = .{ .files = &.{}, .settings = &.{} };
    const e = try gather(
        testing.io,
        gpa,
        none,
        try options(gpa, &.{ "x", "--hostname", "edge" }, &why),
        &why,
    );
    try testing.expectEqualStrings("edge\n", e[0].data);
    const long: [65]u8 = @splat('a');
    try testing.expectError(error.Refused, gather(
        testing.io,
        gpa,
        none,
        try options(gpa, &.{ "x", "--hostname", &long }, &why),
        &why,
    ));
    try testing.expectError(error.Refused, gather(
        testing.io,
        gpa,
        none,
        try options(gpa, &.{ "x", "--hostname", "a_b" }, &why),
        &why,
    ));
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
    for ([_]Platform{
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
    try testing.expectEqual(.up, try awaitUp(io, testing.allocator, log, old.len));
    // A log shorter than what was seen was started again: read from its start.
    try testing.expectEqual(.up, try awaitUp(io, testing.allocator, log, 1 << 30));
}

test isCidr {
    for ([_][]const u8{ "10.0.0.0/8", "203.0.113.7/32", "0.0.0.0/0" }) |good|
        try testing.expect(isCidr(good));
    for ([_][]const u8{
        "me",           "10.0.0.0",     "10.0.0.0/",   "10.0.0.0/33",
        "10.0.0.0/+8",  "10.0.0.0/008", "10.0.0/8",    "fd00::/8",
        "10.0.0.0/8 x", "$(id)/32",     "10.0.0.0/8;", "",
    }) |bad| try testing.expect(!isCidr(bad));
}

test openText {
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try openText(&w, "web", "ports 22 8080", &.{
        &.{
            "gcloud",
            "compute",
            "firewall-rules",
            "create",
            "web-allow",
            "--source-ranges",
            "$ME/32",
        },
        &.{ "az", "--x", "" },
    });
    try testing.expectEqualStrings(
        "howl: web: nothing reaches it yet; to let this host in on ports 22 8080, or " ++
            "--allow-from:\nME=$(curl -fsS https://checkip.amazonaws.com)\n" ++
            "gcloud compute firewall-rules create web-allow --source-ranges \"$ME/32\"\n" ++
            "az --x \"\"\n",
        w.buffered(),
    );
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("port 22", try portList(arena.allocator(), &.{22}));
}

test "--allow-from is create's, for the clouds alone" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const o = try options(gpa, &.{ "prod", "web", "--allow-from", "10.0.0.0/8" }, &why);
    try testing.expectEqualStrings("10.0.0.0/8", o.allow_from.?);
    try testing.expectError(
        error.Refused,
        options(gpa, &.{ "prod", "--allow-from", "me", "--allow-from", "me" }, &why),
    );
    try testing.expectError(error.Refused, newOnly(o, "web", .aws, &why));
    try testing.expect(std.mem.find(u8, why.text, "web exists") != null);
    try newOnly(.{ .form = "prod" }, "web", .aws, &why);
    try testing.expectError(error.Refused, allowSource(testing.io, gpa, "0.0.0.0", &why));
    try testing.expectEqualStrings(
        "0.0.0.0/0",
        try allowSource(testing.io, gpa, "0.0.0.0/0", &why),
    );
}

test isTarName {
    try testing.expect(isTarName("bastion/settings.json"));
    try testing.expect(isTarName("data.key"));
    for ([_][]const u8{ "", "/etc/x", "a/../b", "a//b", "a b", "a/", "./a", "é" }) |s|
        try testing.expect(!isTarName(s));
}
