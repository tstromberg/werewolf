//! howl is werewolf's command-line tool. It builds forms, packs config tars,
//! and creates, reaches and deletes machines, here or in a cloud. It runs on
//! the build host, not in the image. See README.md and docs/design/implemented/cli.md.

const std = @import("std");
const settings = @import("settings");
const service = @import("service");
const update_policy = @import("update-policy");
const network = @import("network");
const cmdline = @import("cmdline");
const lima = @import("lima.zig");
const bhyve = @import("bhyve.zig");
const firecracker = @import("firecracker.zig");
const proxmox = @import("proxmox.zig");
const gcp = @import("gcp.zig");
const aws = @import("aws.zig");
const azure = @import("azure.zig");
const app = @import("app.zig");
const apk = @import("apk.zig");
const published = @import("published.zig");
const keys = @import("keys.zig");
const adhoc = @import("adhoc.zig");
const oci = @import("oci.zig");
const progress = @import("progress.zig");
const local = @import("local.zig");
const cloud = @import("cloud.zig");
const verbs = @import("verbs.zig");
const native = @import("build.zig");
const forms = @import("form");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const json = std.json;

pub const usage =
    \\usage: howl forms [FORM|SEARCH] [--arch ARCH] [--build|--published] [--json]   browse forms; an exact name shows setup and commands
    \\       howl versions [--with FORM] [--on qemu|lima|bhyve] [--arch ARCH] [--json]   available base image releases
    \\       howl build --with FORM,... [--build] [--disable=secureboot,tpm,ipe] [-o DIR] [--arch ARCH] [--format qcow2|raw|vhd|vmdk] [--app DIR]
    \\       howl test --with FORM [--arch ARCH] [--iterate [--driver NAME] [--phase seed|verify]]   run the release gate or reuse a local test VM
    \\       howl pack --with FORM [--build] [-o FILE] [-n] [--on TARGET] [CONFIG...]
    \\       howl pack --with FORM -h   the flags FORM takes
    \\       howl run [--with FORM,...] [--on TARGET] [--add-current-user auto|yes|no] [--version TAG] [--disable=secureboot,tpm,ipe] [--dev=ssh] [--build] [--yes] [--verbose] [CONFIG...]   protected by default; replaces werewolf-run; default form playground
    \\       howl ssh [[USER@]NAME] [--identity KEY | --no-agent] [-- COMMAND...]
    \\       howl owner [NAME] status|pause|resume|check|outcome|try [HASH]   operate an enrolled QEMU VM without guest SSH
    \\       howl stop [NAME] [--on qemu]   stop a local VM and keep its disk
    \\       howl start NAME                                  start an enrolled stopped VM
    \\       howl export NAME [--service NAME] [--output FILE] [--disk RAW]   export a consistent data archive
    \\       howl import NAME ARCHIVE [--service NAME] [--on TARGET] [--config DIR] [--disk RAW]   restore data; leave applications stopped
    \\
++ "       howl create NAME --with FORM,... [--on " ++ Platform.list(.made, "|") ++
    "] [--version TAG] [--disable=secureboot,tpm,ipe] [--dev=ssh] [--build] [--yes] [--arch " ++
    "ARCH] " ++
    "[--size TYPE] " ++
    "[--allow-from me|CIDR] [--add-current-user auto|yes|no] " ++
    "[--network tap|slirp] [--bridge NAME] " ++
    "[CONFIG...]\n" ++
    "       howl delete NAME [--on " ++ Platform.list(.made, "|") ++ "]\n" ++
    "       howl console [NAME] [--on " ++ Platform.list(.made, "|") ++ "]\n" ++
    "       howl upload DISK --on " ++ Platform.list(.cloud, "|") ++ "\n" ++
    \\       --variant NAME[,NAME...] and --ssh select image variants for build, pack, test, run and create
    \\       howl build-apk RECIPE [--arch ARCH] [--verbose]   a form's own package, from a melange recipe
    \\       howl apply FILE [--name NAME] [--app DIR] [--to ssh://HOST/PATH] [-n]   publish an enrolled machine's declaration
    \\       howl form [-f FILE] --with FORM,... --packages PKG,... --KEY LINE --KEY.SUB VALUE --services.NAME.KEY LINE -o DIR   a form from a manifest and the line, kept;
    \\            build, run, create and pack take the same flags, form.yaml's keys: one form alone is run as it is, more is generated (-n shows it)
    \\
;

/// max_disk_file is the largest file init extracts from a config disk.
const max_disk_file = 1 << 20;
/// These are the limits cloud-metadata puts on user data (cmd/cloud-metadata).
const max_cloud_file = 32 << 10;
const max_cloud_total = 48 << 10;
const max_cloud_entries = 32;
const max_name = 100;

/// environ is the process environment. It names the Proxmox node
/// (proxmox.zig), the user who owns a Firecracker tap device, and the
/// terminal (progress.zig).
pub var environ: *const std.process.Environ.Map = undefined;

/// The canonical variant selection for this command.
pub var variants: []const []const u8 = &.{};

pub fn variantArgs(
    gpa: Allocator,
    args: []const []const u8,
    why: *Why,
) !struct { names: []const []const u8, args: []const []const u8 } {
    var names: std.ArrayList([]const u8) = .empty;
    var rest: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--ssh")) {
            try names.append(gpa, "ssh");
        } else if (std.mem.eql(u8, arg, "--variant") or std.mem.startsWith(u8, arg, "--variant=")) {
            _, const value = try flagValue(args, &i, why);
            try names.append(gpa, value);
        } else {
            try rest.append(gpa, arg);
            if (std.mem.eql(u8, arg, "--")) {
                try rest.appendSlice(gpa, args[i + 1 ..]);
                break;
            }
        }
    }
    var failure: forms.Failure = .{};
    return .{ .names = forms.variantNames(gpa, names.items, &failure) catch
        return why.refuse("{s}", .{failure.text}), .args = rest.items };
}

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    environ = init.environ_map;
    var args: []const []const u8 = init.minimal.args.toSlice(gpa) catch fatal(
        io,
        "out of memory",
        .{},
    );
    if (args.len < 2) fatal(io, "{s}", .{usage});
    const verb = std.meta.stringToEnum(
        enum {
            build,
            @"test",
            pack,
            run,
            create,
            import,
            @"export",
            sync,
            apply,
            delete,
            console,
            stop,
            start,
            ssh,
            @"_ssh-agent",
            owner,
            upload,
            @"build-apk",
            form,
            forms,
            versions,
            _build,
            _bhyve,
            @"_bhyve-secure",
            _firecracker,
            _unpack,
            @"_boot-image",
            _tpm,
            @"_build-helper",
            @"_native-firmware",
        },
        args[1],
    ) orelse
        fatal(io, "no verb {s}\n{s}", .{ args[1], usage });
    var why: Why = .{};
    switch (verb) {
        .build,
        .@"test",
        .pack,
        .run,
        .create,
        .form,
        .forms,
        .versions,
        ._build,
        .@"_boot-image",
        => {
            const selected = variantArgs(gpa, args[2..], &why) catch fatal(io, "{s}", .{why.text});
            variants = selected.names;
            args = std.mem.concat(
                gpa,
                []const u8,
                &.{ args[0..2], selected.args },
            ) catch fatal(io, "out of memory", .{});
        },
        else => {},
    }
    published.choose(args[1], args[2..]);
    const done = switch (verb) {
        .build => native.build(io, gpa, args[2..], &why),
        .@"test" => @import("test.zig").command(io, gpa, args[2..], &why),
        .pack => pack(io, gpa, args[2..], &why),
        .run => runForm(io, gpa, args[2..], &why),
        .create => create(io, gpa, args[2..], &why),
        .import => @import("data.zig").command(io, gpa, .import, args[2..], &why),
        .@"export" => @import("data.zig").command(io, gpa, .@"export", args[2..], &why),
        .sync => why.refuse(
            "sync was replaced by howl import NAME ARCHIVE; restore into empty data",
            .{},
        ),
        .apply => @import("apply.zig").apply(io, gpa, args[2..], &why),
        .delete => verbs.delete(io, gpa, args[2..], &why),
        .console => verbs.console(io, gpa, args[2..], &why),
        .start => @import("local-secure.zig").start(io, gpa, args[2..], &why),
        .stop => verbs.stopHere(io, gpa, args[2..], &why),
        .ssh => verbs.sshTo(io, gpa, args[2..], &why),
        .@"_ssh-agent" => @import("ssh-agent.zig").command(io, gpa, args[2..], &why),
        .owner => @import("owner.zig").command(io, gpa, args[2..], &why),
        .upload => cloud.upload(io, gpa, args[2..], &why),
        .@"build-apk" => apk.build(io, gpa, args[2..], &why),
        .form => adhoc.form(io, gpa, args[2..], &why),
        .forms => @import("discovery.zig").command(io, gpa, args[2..], &why),
        .versions => @import("download.zig").versions(io, gpa, args[2..], &why),
        // Internal: the Makefile's image targets (build.zig).
        ._build => native.buildTargets(io, gpa, args[2..], &why),
        .@"_boot-image" => @import("boot-image.zig").command(io, gpa, args[2..], &why),
        // Internal: create runs howl again as the bhyve or Firecracker supervisor.
        ._bhyve => if (args.len < 5)
            why.refuse("_bhyve NAME CONFIG BHYVE...", .{})
        else
            bhyve.keep(io, gpa, args[2], args[3], args[4..]),
        .@"_bhyve-secure" => if (args.len < 5)
            why.refuse("_bhyve-secure NAME DIR BHYVE...", .{})
        else
            bhyve.keepProtected(io, gpa, args[2], args[3], args[4..]),
        ._firecracker => firecracker.command(io, gpa, args[2..], &why),
        // Internal: a protected machine's TPM supervisor, and what
        // tools/enroll-boot asks howl for.
        ._tpm => @import("swtpm.zig").command(io, gpa, args[2..], &why),
        .@"_build-helper" => @import("prerequisites.zig").helper(io, gpa, args[2..], &why),
        .@"_native-firmware" => @import("firmware.zig").command(io, gpa, args[2..], &why),
        // Internal: form unpacks an OCI image's tar in a child with no
        // environment (oci.zig).
        ._unpack => oci.unpackMain(io, args[2..], &why),
    };
    done catch |err| switch (err) {
        // An empty why means progress has already printed the failure.
        error.Refused => if (why.text.len == 0)
            std.process.exit(1)
        else
            fatal(io, "{s}", .{why.text}),
        error.VariantChangeRequiresNewMachine => fatal(io, "variants cannot change on an " ++
            "enrolled machine; keep its selection or create a new " ++
            "machine", .{}),
        else => fatal(io, "{s}", .{@errorName(err)}),
    };
}

fn fatal(io: Io, comptime fmt: []const u8, args: anytype) noreturn {
    say(io, fmt, args);
    std.process.exit(1);
}

pub fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    var out = Io.File.stderr().writerStreaming(io, &buf);
    out.interface.print("howl: " ++ fmt ++ "\n", args) catch return;
    out.interface.flush() catch {};
}

/// Why holds the reason a verb refused, which main prints as one line.
pub const Why = struct {
    /// buf has room for any refusal, including the usage it may repeat.
    buf: [4096]u8 = undefined,
    text: []const u8 = "",

    pub fn refuse(w: *Why, comptime fmt: []const u8, args: anytype) error{Refused} {
        // A refusal may quote a registry, a server or a guest.
        const said = std.mem.print(&w.buf, fmt, args) catch {
            w.text = "(too long to say)";
            return error.Refused;
        };
        w.text = inert(said);
        return error.Refused;
    }
};

/// inert drops from text, in place, what could drive a terminal: C0
/// controls but newline and tab, DEL, C1 controls, and bytes that are not
/// valid UTF-8 (a lone 0x9b is CSI to a terminal that reads 8-bit
/// controls). A guest, a registry or a server may have written text.
pub fn inert(text: []u8) []u8 {
    var i: usize = 0;
    var j: usize = 0;
    while (i < text.len) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch {
            i += 1;
            continue;
        };
        if (n > text.len - i) break;
        const seq = text[i..][0..n];
        if (!std.unicode.utf8ValidateSlice(seq)) {
            i += 1;
            continue;
        }
        // C1 controls, U+0080 to U+009F, are 0xc2 0x80 to 0xc2 0x9f.
        const control = switch (n) {
            1 => (seq[0] < 0x20 and seq[0] != '\n' and seq[0] != '\t') or seq[0] == 0x7f,
            2 => seq[0] == 0xc2 and seq[1] <= 0x9f,
            else => false,
        };
        if (!control) {
            @memmove(text[j..][0..n], seq);
            j += n;
        }
        i += n;
    }
    return text[0..j];
}

test "a refusal quoting a registry cannot drive the terminal" {
    var why: Why = .{};
    const err = why.refuse("crane: {s}", .{"no\x1b]52;c;cGF5bG9hZA==\x07 such\x9b2J image\n"});
    try std.testing.expectEqual(error.Refused, err);
    try std.testing.expectEqualStrings("crane: no]52;c;cGF5bG9hZA== such2J image\n", why.text);
}

// --- the form's interface ----------------------------------------------------------

/// File is a file a service declares with a config line. --FLAG FILE puts
/// it at path in the tar. The service runs without an optional one.
const File = struct {
    flag: []const u8,
    path: []const u8,
    service: []const u8,
    optional: bool = false,
};

/// Settings is a service with settings. Its settings.json goes at path.
const Settings = struct {
    service: []const u8,
    path: []const u8,
    decl: []const settings.Setting,
};

/// Interface is the set of flags a form takes, and where each lands.
pub const Interface = struct {
    files: []const File,
    settings: []const Settings,
    /// policy is the form's etc/werewolf/update-policy.json, if any. An
    /// operator's update-policy.json is applied over it.
    policy: ?[]const u8 = null,
    /// people is the manifest's users as the config tar's `users` file
    /// (lib/form.zig peopleFile); empty when it names no one.
    people: []const u8 = "",
    /// Distinguish an explicit empty users map from an absent one.
    people_defined: bool = false,
};

/// own_files are the tar files werewolf's programs read, each set by a howl
/// flag. init reads hostname, network, data.key, dev and root's authorized_keys;
/// slot-update reads update-policy.json.
const own_files = [_][]const u8{
    "hostname",
    "network",
    "data.key",
    "authorized_keys",
    "dev",
    "users",
    "update-policy.json",
};

/// reserved lists howl's own flags, which no service may declare.
const reserved = [_][]const u8{
    "config",
    "hostname",
    "ip",
    "gw",
    "dns",
    "data-key",
    "root-keys",
    "add-current-user",
    "dev",
    "update-policy",
    "on",
    "arch",
    "size",
    "app",
    "allow-from",
    "disable",
    "network",
    "bridge",
};

/// chain returns form's chain, base first, as the build lays it out
/// (lib/form.zig). form is a directory, or a name: a published form, or
/// with --build one in ./forms (published.zig).
pub fn chain(io: Io, gpa: Allocator, form: []const u8, why: *Why) ![]const forms.Form {
    const names = try published.names(io, gpa, published.arch, form, &.{}, why);
    if (std.mem.eql(u8, names, "forms")) Dir.cwd().access(io, "forms", .{}) catch
        return why.refuse("no ./forms: --build builds from a werewolf checkout", .{});
    var f: forms.Failure = .{};
    return forms.chainSelectedIn(
        io,
        gpa,
        Dir.cwd(),
        names,
        form,
        variants,
        &f,
    ) catch |err| switch (err) {
        error.Form => why.refuse("{s}", .{f.text}),
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// devChain adds local developer SSH to a form while keeping that form last
/// in the chain, so its name and service declarations remain authoritative.
pub fn devChain(io: Io, gpa: Allocator, form: []const u8, why: *Why) ![]const forms.Form {
    const original = try chain(io, gpa, form, why);
    return addDevSsh(io, gpa, original, why);
}

/// addDevSsh layers local developer SSH into an already-resolved form chain.
pub fn addDevSsh(
    io: Io,
    gpa: Allocator,
    original: []const forms.Form,
    why: *Why,
) ![]const forms.Form {
    var policy: forms.Failure = .{};
    const ports = try forms.listens(gpa, original, &policy);
    if (std.mem.findScalar(u16, ports, dev_ssh_port) != null)
        return why.refuse("--dev=ssh reserves TCP port {d} for developer SSH", .{dev_ssh_port});
    return @import("compose").withDevSsh(gpa, original, try devSshForm(io, gpa, why));
}

pub const dev_ssh_port: u16 = 2222;

/// devSshForm stages the embedded developer listener without altering a
/// form's own SSH service or requiring a checkout beside the howl binary.
pub fn devSshForm(io: Io, gpa: Allocator, why: *Why) ![]const forms.Form {
    const embedded = @import("files");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(embedded.dev_ssh_form);
    hash.update(embedded.dev_ssh_config);
    const dir = try gpa.print("build/dev-ssh/{x}/howl-dev", .{hash.finalResult()});
    const guard_path = try gpa.print("{s}.lock", .{dir});
    try Dir.cwd().createDirPath(io, std.fs.path.dirname(dir).?);
    const guard = try Dir.cwd().createFile(io, guard_path, .{ .truncate = false });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    for ([_]struct { []const u8, []const u8 }{
        .{ "form.yaml", embedded.dev_ssh_form },
        .{ "rootfs/etc/ssh/howl-dev.conf", embedded.dev_ssh_config },
    }) |file| {
        const path = try gpa.print("{s}/{s}", .{ dir, file[0] });
        const previous = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 10)) catch "";
        if (std.mem.eql(u8, previous, file[1])) continue;
        try Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?);
        try writePrivate(io, gpa, path, file[1], why);
    }
    var failure: forms.Failure = .{};
    return forms.chain(io, gpa, Dir.cwd(), dir, &failure) catch |err| switch (err) {
        error.Form => why.refuse("{s}", .{failure.text}),
        error.OutOfMemory => error.OutOfMemory,
    };
}

test "developer SSH preserves the form's SSH service and settings" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var failure: forms.Failure = .{};
    var why: Why = .{};
    const original = try forms.chain(io, gpa, Dir.cwd(), "bastion", &failure);
    const dev = try addDevSsh(io, gpa, original, &why);
    const before = try forms.services(io, gpa, Dir.cwd(), original, &failure);
    const after = try forms.services(io, gpa, Dir.cwd(), dev, &failure);
    for (before) |old| {
        const found = for (after) |current| {
            if (std.mem.eql(u8, old.name, current.name)) break current.text;
        } else return error.MissingProductionService;
        try testing.expectEqualStrings(old.text, found);
    }
    try testing.expectEqualStrings("bastion", dev[dev.len - 1].name);
    try testing.expectEqualStrings(
        try forms.sshdConfig(gpa, original, &failure),
        try forms.sshdConfig(gpa, dev, &failure),
    );
    const ports = try forms.listens(gpa, dev, &failure);
    try testing.expect(std.mem.findScalar(u16, ports, 22) != null);
    try testing.expect(std.mem.findScalar(u16, ports, dev_ssh_port) != null);
    const config = try @import("compose").apko(io, gpa, Dir.cwd(), dev, &.{}, &failure);
    for ([_][]const u8{ "sshd", "_dhcp" }) |name| {
        var count: usize = 0;
        for (config.get("accounts").?.get("users").?.list) |user| {
            if (std.mem.eql(u8, user.get("username").?.scalar.text, name)) count += 1;
        }
        try testing.expectEqual(1, count);
    }
}

test "developer access leaves minimal storage unchanged" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var failure: forms.Failure = .{};
    var why: Why = .{};
    const original = try forms.chain(testing.io, gpa, Dir.cwd(), "minimal", &failure);
    const dev = try addDevSsh(testing.io, gpa, original, &why);
    const config = try @import("compose").apko(testing.io, gpa, Dir.cwd(), dev, &.{}, &failure);
    for (config.get("contents").?.get("packages").?.list) |pkg| {
        try testing.expect(!std.mem.eql(u8, pkg.scalar.text, "cryptsetup"));
        try testing.expect(!std.mem.eql(u8, pkg.scalar.text, "e2fsprogs"));
    }
}

/// interface returns the flags svcs declare in their `config`, `setting`
/// and `render` lines. It parses each file with leash's parser
/// (lib/service.zig), so pack accepts exactly what the guest accepts.
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
        // A secret is a file flag too, named for its variable:
        // SMTP_PASSWORD is --smtp-password.
        for (s.secrets) |sec| {
            const path = sec.path["/run/config/".len..];
            if (!isTarName(path))
                return why.refuse("{s}: {s} cannot be in a config tar", .{ svc.name, sec.path });
            const flag = try gpa.dupe(u8, sec.name);
            for (flag) |*c| c.* = if (c.* == '_') '-' else std.ascii.toLower(c.*);
            try files.append(
                gpa,
                .{ .flag = flag, .path = path, .service = svc.name, .optional = sec.optional },
            );
        }
        // service.parse refuses render without `config settings`, so
        // settings_path is set here.
        if (s.render != null)
            try sets.append(
                gpa,
                .{ .service = svc.name, .path = settings_path.?, .decl = s.settings },
            );
    }

    // Every flag means one thing, and every path in the tar has one source.
    // A setting several services declare alike, of one type, is one flag,
    // its value given to each: a site's domain, to its web server and its
    // application. A file they declare alike, the same path and the same
    // optional bit, is one flag too: one secret, read by each service.
    const Flag = struct { name: []const u8, service: []const u8, setting: ?settings.Setting };
    var flags: std.ArrayList(Flag) = .empty;
    for (files.items) |f|
        try flags.append(gpa, .{ .name = f.flag, .service = f.service, .setting = null });
    for (sets.items) |s| for (s.decl) |d|
        try flags.append(gpa, .{ .name = d.name, .service = s.service, .setting = d });
    for (flags.items, 0..) |a, i| {
        for (reserved) |r| if (std.mem.eql(u8, a.name, r))
            return why.refuse(
                "{s} declares --{s}, which is werewolf's own",
                .{ a.service, a.name },
            );
        for (flags.items[0..i]) |b| if (std.mem.eql(u8, a.name, b.name)) {
            if (a.setting == null and b.setting == null) {
                const fa = fileNamed(files.items, a.service, a.name).?;
                const fb = fileNamed(files.items, b.service, b.name).?;
                if (std.mem.eql(u8, fa.path, fb.path) and fa.optional == fb.optional) continue;
                return unalike(why, a, b);
            }
            const x = a.setting orelse return unalike(why, a, b);
            const y = b.setting orelse return unalike(why, a, b);
            if (x.type != y.type or x.list != y.list) return unalike(why, a, b);
        };
    }
    var paths: std.ArrayList([]const u8) = .empty;
    for (files.items) |f| try paths.append(gpa, f.path);
    for (sets.items) |s| try paths.append(gpa, s.path);
    for (paths.items, 0..) |a, i| {
        for (own_files) |own| if (std.mem.eql(u8, a, own))
            return why.refuse("a service declares {s}, which is werewolf's own", .{a});
        for (paths.items[0..i]) |b| if (std.mem.eql(u8, a, b)) {
            if (identicalFiles(files.items, a)) continue;
            return why.refuse("two declarations put files at {s}", .{a});
        };
    }
    return .{ .files = files.items, .settings = sets.items };
}

// --- the inputs -----------------------------------------------------------------------

/// Platform is what --on names: an engine on this machine, a hypervisor
/// elsewhere, a cloud, or disk (pack only: any hypervisor). A hypervisor
/// reads the tar from a disk; a cloud from user data, via cloud-metadata.
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

    /// Kind selects platforms: made is every one create makes machines on
    /// (all but disk); cloud is the clouds, which take --arch and --size.
    const Kind = enum { made, cloud };

    pub fn is(p: Platform, kind: Kind) bool {
        return switch (kind) {
            .made => p != .disk,
            .cloud => p == .gcp or p == .aws or p == .azure,
        };
    }

    /// here reports whether p is an engine on this machine. It runs this
    /// machine's arch.
    fn here(p: Platform) bool {
        return p == .lima or p == .bhyve or p == .firecracker or p == .qemu;
    }

    /// list joins the names of kind's platforms with between, for usage and
    /// refusals.
    pub fn list(comptime kind: Kind, comptime between: []const u8) []const u8 {
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

/// sized_only is the error for --arch or --size where they mean nothing.
const sized_only = "--arch and --size are for --on " ++ Platform.list(.cloud, ", ");

pub const Options = struct {
    form: []const u8 = "",
    /// name is create's machine name, the word after FORM.
    name: ?[]const u8 = null,
    out: ?[]const u8 = null,
    check: bool = false,
    help: bool = false,
    on: ?Platform = null,
    config: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
    /// ip, gw and dns give a static network, written to init's network file.
    ip: ?[]const u8 = null,
    gw: ?[]const u8 = null,
    dns: ?[]const u8 = null,
    /// bhyve defaults to TAP for built images; published images need SLIRP.
    network: ?bhyve.Mode = null,
    bridge: ?[]const u8 = null,
    data_key: ?[]const u8 = null,
    update_policy: ?[]const u8 = null,
    root_keys: ?[]const u8 = null,
    add_current_user: enum { auto, yes, no } = .auto,
    /// own_keys are the keys from ~/.ssh create copies to root (keys.zig),
    /// where no --root-keys or --config gives root any.
    own_keys: ?[]const u8 = null,
    /// arch and size are the machine's architecture and type, for create on
    /// a cloud.
    arch: ?Arch = null,
    size: ?[]const u8 = null,
    /// app is a directory to lay where the form keeps its application
    /// (app.zig). build, run and create take it.
    app: ?[]const u8 = null,
    /// local takes werewolf's programs from this checkout (--build), not
    /// from its repository, so the machine does not update them.
    local: bool = false,
    /// disabled is what --disable gave up of werewolf's protections; with
    /// nothing given up, the machine is protected.
    disabled: cmdline.Protections = .empty,
    boot_image: ?@import("boot-image.zig").Request = null,
    /// built is the protected image howl made here for the machine (--build).
    built: ?@import("local-secure.zig").Built = null,
    production_download: bool = false,
    /// dev is the local --dev launch path; init uses its config marker only
    /// to admit key-only root SSH for this machine.
    dev: bool = false,
    /// allow_from is who may reach the form's TCP ports on gcp, aws or
    /// azure: me or an IPv4 CIDR. Without it, create prints the commands.
    allow_from: ?[]const u8 = null,
    /// flags are the --FLAG VALUE pairs the form declares, in order.
    flags: []const [2][]const u8 = &.{},

    pub fn protected(o: Options) bool {
        return o.disabled.count() == 0;
    }
};

/// options parses a command line without its verb. The first word that is
/// not a flag or a flag's value is FORM; a second is the machine's name.
pub fn options(gpa: Allocator, args: []const []const u8, why: *Why) !Options {
    var o: Options = .{};
    var current_user_given = false;
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
        else if (std.mem.eql(u8, flag, "bridge"))
            &o.bridge
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
        if (std.mem.eql(
            u8,
            flag,
            "import",
        )) return why.refuse("--import was replaced by howl import NAME ARCHIVE", .{});
        if (slot) |s| {
            if (s.* != null) return why.refuse("--{s} given twice", .{flag});
            s.* = v;
        } else if (std.mem.eql(u8, flag, "add-current-user")) {
            if (current_user_given) return why.refuse("--add-current-user given twice", .{});
            current_user_given = true;
            o.add_current_user = std.meta.stringToEnum(@TypeOf(o.add_current_user), v) orelse
                return why.refuse("--add-current-user {s}: auto, yes or no", .{v});
        } else if (std.mem.eql(u8, flag, "network")) {
            if (o.network != null) return why.refuse("--network given twice", .{});
            o.network = std.meta.stringToEnum(bhyve.Mode, v) orelse
                return why.refuse("--network {s}: tap or slirp, for --on bhyve", .{v});
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

/// flagValue splits the flag at args[i.*], `--NAME VALUE` or
/// `--NAME=VALUE`, into name and value. It leaves i on the last word read.
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

/// Entry is one file in the tar, and the flag it came from.
pub const Entry = struct { path: []const u8, data: []const u8, from: []const u8 };

/// fileNamed returns the file flag service declares, if it does.
fn fileNamed(files: []const File, svc: []const u8, flag: []const u8) ?File {
    for (files) |f| if (std.mem.eql(u8, f.service, svc) and std.mem.eql(u8, f.flag, flag))
        return f;
    return null;
}

/// identicalFiles reports whether every file at path is one declaration:
/// the same flag and the same optional bit, declared more than once.
fn identicalFiles(files: []const File, path: []const u8) bool {
    var flag: ?[]const u8 = null;
    var optional: ?bool = null;
    var n: usize = 0;
    for (files) |f| if (std.mem.eql(u8, f.path, path)) {
        n += 1;
        if (flag) |g| {
            if (!std.mem.eql(u8, g, f.flag) or optional.? != f.optional) return false;
        } else {
            flag = f.flag;
            optional = f.optional;
        }
    };
    return n >= 2;
}

/// unalike refuses a flag two services declare differently.
fn unalike(why: *Why, a: anytype, b: anytype) error{Refused} {
    return why.refuse(
        "--{s} is declared by {s} and by {s}, not as one setting of one type: rename one",
        .{ a.name, b.service, a.service },
    );
}

/// gather reads what the flags name, checks it against the form, and
/// returns the tar's entries sorted by path. It writes nothing.
pub fn gather(io: Io, gpa: Allocator, iface: Interface, o: Options, why: *Why) ![]const Entry {
    var entries: std.ArrayList(Entry) = .empty;
    var stdin_used: ?[]const u8 = null;

    if (o.config) |dir| try readConfigDir(io, gpa, dir, &entries, why);
    // The manifest's people, as init makes their accounts and keys files
    // (lib/form.zig peopleFile): the machine's own, never a taken form's.
    if (iface.people_defined or iface.people.len > 0) try add(
        gpa,
        &entries,
        .{ .path = "users", .data = iface.people, .from = "form.yaml's users" },
        why,
    );
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
    }, why) else if (o.own_keys) |k| try add(gpa, &entries, .{
        .path = "authorized_keys",
        .data = k,
        .from = "~/.ssh",
    }, why);
    if (o.dev and o.own_keys != null and o.root_keys == null) try add(gpa, &entries, .{
        .path = "dev",
        .data = "yes\n",
        .from = "--dev=ssh",
    }, why);
    if (o.update_policy) |f| try add(gpa, &entries, .{
        .path = "update-policy.json",
        .data = try readInput(io, gpa, f, "--update-policy", &stdin_used, why),
        .from = "--update-policy",
    }, why);

    // Settings flags are collected per service; file flags go straight in.
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
        // A setting several services declare goes to each.
        var set = false;
        for (iface.settings, values) |s, *obj| for (s.decl) |d| if (std.mem.eql(u8, d.name, flag)) {
            try setValue(gpa, obj, d, value, why);
            set = true;
        };
        if (set) continue :flag;
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

    // Refuse here what the machine would refuse: each service's settings,
    // as service-config checks them, and any missing required file.
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
    // Check the hostname, network and data key as init does, whether they
    // came from a flag or from --config DIR.
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
    // Check the update policy as slot-update applies it: werewolf's
    // limits, then the form's file, then the operator's.
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

/// setValue adds one command-line value of setting d to obj. A list takes
/// commas or a repeated flag; a string or url list takes only a repeated
/// flag, since its values may hold commas.
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

/// readInput reads the file a FILE flag names, or standard input for -.
/// Only one flag may read standard input.
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

/// readConfigDir adds the regular files under --config DIR at their paths
/// in it. It skips Finder's .DS_Store and AppleDouble ._ files and refuses
/// anything else that is not a regular file or a directory.
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

/// writeTar returns entries as a POSIX ustar archive, as cloud-metadata
/// writes one: owned by root, mode 0600, dated 1970. It has no directory
/// entries; init makes the parents.
pub fn writeTar(gpa: Allocator, entries: []const Entry) ![]const u8 {
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

/// misfit returns why the tar does not fit t, or null if it does. AWS caps
/// user data at 16 KiB and Azure at 64 KiB, both after base64; GCP's
/// 256 KiB is more than cloud-metadata takes.
pub fn misfit(entries: []const Entry, tar_len: usize, t: Platform) ?[]const u8 {
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

/// start_phase is the phase a build is in before a step names one.
pub const start_phase: progress.Phase = .{ .name = "Starting the build", .short = "start" };

/// verboseFlag reports whether --verbose or -v is anywhere in args, and
/// returns the other args.
pub fn verboseFlag(gpa: Allocator, args: []const []const u8) !struct { bool, []const []const u8 } {
    return takeFlag(gpa, args, &.{ "--verbose", "-v" });
}

/// takeFlag reports whether any of names, flags without values, is
/// anywhere in args, and returns the other args.
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

/// run runs argv with its output on standard error, so standard output
/// holds only howl's result. It refuses if argv fails.
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
    const taken = (try adhoc.take(io, gpa, .pack, given, why)) orelse return;
    // --build, which reads forms from this checkout, main has taken.
    _, const args = try takeFlag(gpa, taken, &.{"--build"});
    const o = try options(gpa, args, why);
    if (o.network != null or
        o.bridge != null) return why.refuse("--network and --bridge are run's and create's", .{});
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

    const entries = try keys.addCurrentUser(
        io,
        gpa,
        iface,
        o,
        try gather(io, gpa, iface, o, why),
        why,
    );
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

/// formInterface returns the flags form takes, from its chain's files.
pub fn formInterface(io: Io, gpa: Allocator, form: []const u8, why: *Why) !Interface {
    if (@import("boot-config.zig").forForm(form)) |definition| return definition.interface;
    const c = try chain(io, gpa, form, why);
    var failure: forms.Failure = .{};
    const svcs = forms.services(io, gpa, Dir.cwd(), c, &failure) catch |err| switch (err) {
        error.Form => return why.refuse("{s}", .{failure.text}),
        error.OutOfMemory => return error.OutOfMemory,
    };
    var iface = try interface(gpa, svcs, why);
    iface.people = forms.peopleFile(gpa, c, &failure) catch |err| switch (err) {
        error.Form => return why.refuse("{s}", .{failure.text}),
        error.OutOfMemory => return error.OutOfMemory,
    };
    iface.people_defined = c[c.len - 1].spec.get("users") != null;
    // The image lays the forms over each other, so the last one's wins.
    for (c) |f| {
        const path = try gpa.print("{s}/rootfs/etc/werewolf/update-policy.json", .{f.dir});
        if (Dir.cwd().readFileAlloc(io, path, gpa, .limited(update_policy.max_input + 1))) |text| {
            iface.policy = text;
        } else |_| {}
    }
    if (forms.updates(c).policy) |text| iface.policy = text;
    if (iface.policy) |text| {
        var policy: update_policy.Settings = .{};
        if (try update_policy.apply(gpa, &policy, .form, text)) |r|
            return why.refuse("{s}: updates.policy: {s}: {s}", .{ form, r.key, r.why });
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
    try row(w, "--network tap|slirp", "bhyve: TAP for built images; signed downloads use SLIRP");
    try row(
        w,
        "--bridge NAME",
        "bhyve TAP: existing bridge; auto-detected when there is exactly one",
    );
    try row(w, "--data-key FILE", "data.key: /data in LUKS2");
    try row(w, "--root-keys FILE", "authorized_keys: root's, where the form runs sshd");
    try row(
        w,
        "--add-current-user auto|yes|no",
        "add your local SSH account; auto when users is absent, except Lima",
    );
    try row(
        w,
        "--users.NAME.keys LINE",
        "users: NAME's security key (repeat); --users.NAME.admin makes it root's too",
    );
    try row(w, "--update-policy FILE", "update-policy.json: when updates install");
    if (std.mem.eql(u8, verb, "create")) {
        try row(
            w,
            "--version TAG",
            "install a protected GitHub release; updates follow the latest channel",
        );
        try row(w, "--allow-from me|CIDR", "opens the form's TCP ports to it (gcp, aws, azure)");
    }
    for (iface.files) |f| try row(
        w,
        try gpa.print("--{s} FILE", .{f.flag}),
        try gpa.print("{s}{s}", .{ f.path, if (f.optional) "" else ", required" }),
    );
    // A setting several services declare is one row: each file it goes
    // to, and required if any requires it.
    var listed: std.array_hash_map.String(void) = .empty;
    for (iface.settings) |st| for (st.decl) |d| {
        if ((try listed.getOrPut(gpa, d.name)).found_existing) continue;
        var paths: std.ArrayList(u8) = .empty;
        var required = false;
        for (iface.settings) |other| for (other.decl) |e| if (std.mem.eql(u8, e.name, d.name)) {
            if (paths.items.len > 0) try paths.appendSlice(gpa, ", ");
            try paths.appendSlice(gpa, other.path);
            required = required or e.required;
        };
        try row(
            w,
            try gpa.print("--{s} {t}{s}", .{ d.name, d.type, if (d.list) "..." else "" }),
            try gpa.print("{s}{s}", .{ paths.items, if (required) ", required" else "" }),
        );
    };
}

/// writePrivate writes data to path with mode 0600. It writes a file
/// beside path and renames it over path, so path is never half written.
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

/// runForm creates werewolf-run, the one machine run keeps for trying a
/// form, in place of the last one. It takes create's flags and picks the
/// engine create would. howl ssh, console and stop with no name act on it.
fn runForm(io: Io, gpa: Allocator, given: []const []const u8, why: *Why) !void {
    // Expand the line here, once; createFrom takes it as it is.
    const args = (try adhoc.take(io, gpa, .run, given, why)) orelse return;
    for (args) |a| if (std.mem.eql(u8, a, run_name))
        return why.refuse("{s} is the name run gives its machine: run [--with FORM] [flags]", .{a});
    const asking = for (args) |a| {
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) break true;
    } else false;
    // Refuse an unsupported protection mode before removing the previous VM.
    if (!asking) {
        const launch = try launchFlags(gpa, args, why);
        const o = try options(gpa, launch.args, why);
        try requireProtection(engineFor(io, gpa, o.on, launch.protected()).on, launch, why);
    }
    var with: std.ArrayList([]const u8) = .empty;
    try with.appendSlice(gpa, args);
    try with.append(gpa, run_name);
    return createFrom(io, gpa, with.items, true, why);
}

/// Tell is how create reports: every line, or one line per step and a
/// summary. It holds the command for a failure to repeat, the start time,
/// and why a likelier engine was passed over, if one was.
pub const Tell = struct {
    verbose: bool,
    command: []const u8,
    began: Io.Timestamp,
    note: ?[]const u8 = null,
    dev: bool = false,

    milestones: ?*progress.Milestones = null,

    pub fn step(t: Tell, gpa: Allocator, dir: []const u8) !progress.Options {
        return .{
            .verbose = t.verbose,
            .command = t.command,
            .log = try gpa.print("{s}/create.log", .{dir}),
            .first = if (t.milestones) |m|
                m.phase orelse .{
                    .name = "Preparing VM boot image and enrollment",
                    .short = "prepare",
                }
            else
                .{ .name = "Preparing VM boot image and enrollment", .short = "prepare" },
            .milestones = t.milestones,
        };
    }
};

// --- create, delete, console -----------------------------------------------------------

/// AppBuild is where an application is staged, if there is one: the
/// image's root it lays over the form's. Its build is FORM-app, so the
/// form's own build is untouched.
const AppBuild = struct { root: ?[]const u8 = null };

pub fn appBuild(
    io: Io,
    gpa: Allocator,
    form: []const u8,
    arch: Arch,
    src: ?[]const u8,
    why: *Why,
) !AppBuild {
    // Outputs are named by the form's base name: a form outside the tree,
    // ../myapp, builds into build/ARCH/myapp.
    const name = std.fs.path.basename(std.mem.trimEnd(u8, form, "/"));
    const dir = src orelse return .{};
    // The last form's app wins; lib/form.zig has checked it is absolute.
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
    return .{ .root = root };
}

/// buildHere builds goals of s for a machine, reporting through steps, and
/// returns where it wrote. Every package is pinned by the input-bound lock.
pub fn buildHere(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    s: native.Spec,
    goals: native.Goals,
) !native.Paths {
    try native.make(io, gpa, steps, s, goals);
    return native.paths(gpa, s);
}

/// machineDir returns where create keeps a machine's files on any
/// platform: its engine, disks and config tar, which holds secrets.
/// delete removes it with the machine.
pub fn machineDir(gpa: Allocator, name: []const u8) ![]const u8 {
    return gpa.print("build/machines/{s}", .{name});
}

/// dataDir returns where howl keeps what no clean build may take: signing
/// keys, without which no machine made with them takes another update, and
/// local package repositories. It is $XDG_DATA_HOME/howl, or
/// ~/.local/share/howl, the user's alone. ~/.howl, an older home, moves there.
pub fn dataDir(io: Io, gpa: Allocator) ![]const u8 {
    const home = environ.get("HOME") orelse return error.NoHome;
    const xdg = environ.get("XDG_DATA_HOME") orelse "";
    // The XDG spec ignores a relative path.
    const dir = if (std.fs.path.isAbsolute(xdg))
        try gpa.print("{s}/howl", .{xdg})
    else
        try gpa.print("{s}/.local/share/howl", .{home});
    try Dir.cwd().createDirPath(io, std.fs.path.dirname(dir).?);
    try moveOnce(io, try gpa.print("{s}/.howl", .{home}), dir);
    const made = if (Dir.cwd().access(io, dir, .{})) |_| false else |_| true;
    try Dir.cwd().createDirPath(io, dir);
    try Dir.cwd().setFilePermissions(io, dir, .fromMode(0o700), .{});
    if (made) say(io, "keeping signing keys in {s}: back it up, since machines made with " ++
        "them take updates only signed by them", .{dir});
    return dir;
}

/// keysDir returns dataDir's keys/sub, the user's alone, first moving there
/// what an older howl kept at legacy in build/, which make clean removes.
pub fn keysDir(io: Io, gpa: Allocator, sub: []const u8, legacy: []const u8) ![]const u8 {
    const all = try gpa.print("{s}/keys", .{try dataDir(io, gpa)});
    try Dir.cwd().createDirPath(io, all);
    try Dir.cwd().setFilePermissions(io, all, .fromMode(0o700), .{});
    const dir = try gpa.print("{s}/{s}", .{ all, sub });
    try Dir.cwd().createDirPath(io, std.fs.path.dirname(dir).?);
    try moveOnce(io, legacy, dir);
    try Dir.cwd().createDirPath(io, dir);
    try Dir.cwd().setFilePermissions(io, dir, .fromMode(0o700), .{});
    return dir;
}

/// moveOnce renames from to to when from exists and to does not.
fn moveOnce(io: Io, from: []const u8, to: []const u8) !void {
    if (Dir.cwd().access(io, to, .{})) |_| return else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    if (Dir.cwd().access(io, from, .{})) |_| {} else |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    }
    Dir.rename(Dir.cwd(), from, Dir.cwd(), to, io) catch |err| {
        say(io, "cannot move {s} to {s} ({t}): move it there yourself", .{ from, to, err });
        return err;
    };
    say(io, "moved {s} to {s}", .{ from, to });
}

test keysDir {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const saved = environ;
    defer environ = saved;
    var env: std.process.Environ.Map = .init(gpa);
    try env.put("HOME", try gpa.print("{s}/home", .{root}));
    try env.put("XDG_DATA_HOME", try gpa.print("{s}/data", .{root}));
    environ = &env;
    // An older howl's key in build/ moves; a second call finds it moved.
    try tmp.dir.createDirPath(io, "build/boot/aarch64");
    try tmp.dir.writeFile(io, .{ .sub_path = "build/boot/aarch64/boot.key", .data = "k" });
    const legacy = try gpa.print("{s}/build/boot/aarch64", .{root});
    const dir = try keysDir(io, gpa, "boot/aarch64", legacy);
    try testing.expectEqualStrings(try gpa.print("{s}/data/howl/keys/boot/aarch64", .{root}), dir);
    try testing.expectEqualStrings("k", try tmp.dir.readFileAlloc(
        io,
        "data/howl/keys/boot/aarch64/boot.key",
        gpa,
        .limited(8),
    ));
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "build/boot/aarch64", .{}));
    try testing.expectEqualStrings(dir, try keysDir(io, gpa, "boot/aarch64", legacy));
    for ([_][]const u8{ "data/howl", "data/howl/keys", "data/howl/keys/boot/aarch64" }) |d| {
        const st = try tmp.dir.statFile(io, d, .{});
        try testing.expectEqual(0o700, st.permissions.toMode() & 0o777);
    }
}

/// make_cmd is the GNU make the Makefile needs: gmake on the BSDs, whose
/// make is a different program.
pub const make_cmd = switch (@import("builtin").os.tag) {
    .freebsd, .netbsd => "gmake",
    else => "make",
};

/// Arch is an architecture werewolf builds for, by the names make, build
/// directories and release files use. Clouds spell them differently: GCP
/// ARM64 and X86_64, AWS arm64 and x86_64, Azure Arm64 and x64.
pub const Arch = enum { aarch64, x86_64 };

/// hostArch returns this machine's arch, or null if werewolf does not
/// build for it. Engines here run this arch.
pub fn hostArch() ?Arch {
    return switch (@import("builtin").cpu.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
        else => null,
    };
}

pub const not_built_here = "this machine is neither aarch64 nor x86_64";

/// local_cpus and local_mib size a machine here or on Proxmox: two CPUs
/// and 4 GiB, like the default cloud types (gcp.machine), enough for an
/// application with its database, Mastodon's among them. A guest takes the
/// host's memory only as it uses it.
pub const local_cpus = 2;
pub const local_mib = 4096;

/// form_tag marks a machine create made and names its form: in a cloud's
/// label or tag, a Proxmox description, or a Lima template.
pub const form_tag = "werewolf-form";

/// localArch returns the arch an engine here runs: this machine's.
pub fn localArch(why: *Why) error{Refused}!Arch {
    return hostArch() orelse why.refuse("{s}, which werewolf builds for", .{not_built_here});
}

/// archName maps an --arch spelling, in any case, to Arch: aarch64
/// (arm64) or x86_64 (x86-64, amd64).
pub fn archName(given: []const u8) ?Arch {
    const names = [_]struct { []const u8, Arch }{
        .{ "aarch64", .aarch64 }, .{ "arm64", .aarch64 },
        .{ "x86_64", .x86_64 },   .{ "x86-64", .x86_64 },
        .{ "amd64", .x86_64 },
    };
    for (names) |n| if (std.ascii.eqlIgnoreCase(given, n[0])) return n[1];
    return null;
}

/// isRoot reports whether howl runs as root, which bhyve and a
/// Firecracker machine's network need.
pub fn isRoot() bool {
    return switch (@import("builtin").os.tag) {
        .linux => std.os.linux.geteuid() == 0,
        else => std.c.geteuid() == 0,
    };
}

pub const arch_refusal = "--arch {s}: aarch64 (arm64), or x86_64 (x86-64, amd64)";

/// Secure deployments choose Lima on macOS, QEMU on Linux and bhyve on FreeBSD. Missing
/// prerequisites never change the protection mode or select another backend.
const Engine = struct { on: Platform, note: ?[]const u8 = null };

pub fn engine(io: Io, gpa: Allocator, given: ?Platform) Engine {
    return engineFor(io, gpa, given, true);
}

fn protectedEngine(host: std.Target.Os.Tag, given: ?Platform) Platform {
    return given orelse switch (host) {
        .macos => .lima,
        .freebsd => .bhyve,
        else => .qemu,
    };
}

fn engineFor(io: Io, gpa: Allocator, given: ?Platform, secure: bool) Engine {
    if (secure) return .{ .on = protectedEngine(@import("builtin").os.tag, given) };
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

const Launch = struct {
    disabled: cmdline.Protections,
    dev: bool,
    local: bool,
    yes: bool,
    version: ?[]const u8 = null,
    args: []const []const u8,

    pub fn protected(l: Launch) bool {
        return l.disabled.count() == 0;
    }
};

pub fn launchFlags(gpa: Allocator, line: []const []const u8, why: *Why) !Launch {
    _, const plain = try verboseFlag(gpa, line);
    const dev, const rest = try takeFlag(gpa, plain, &.{"--dev=ssh"});
    const from_tree, const more = try takeFlag(gpa, rest, &.{"--build"});
    const yes, const before_disable = try takeFlag(gpa, more, &.{"--yes"});
    var args: std.ArrayList([]const u8) = .empty;
    var given: ?[]const u8 = null;
    var version: ?[]const u8 = null;
    var i: usize = 0;
    while (i < before_disable.len) : (i += 1) {
        const a = before_disable[i];
        if (std.mem.eql(u8, a, "--version") or std.mem.startsWith(u8, a, "--version=")) {
            if (version != null) return why.refuse("--version given twice", .{});
            _, version = try flagValue(before_disable, &i, why);
            if (!@import("boot-download").validVersion(version.?)) return why.refuse(
                "--version takes a timestamp or base-images-SERIAL release tag; use howl versions",
                .{},
            );
            continue;
        }
        if (!std.mem.eql(u8, a, "--disable") and !std.mem.startsWith(u8, a, "--disable=")) {
            try args.append(gpa, a);
            continue;
        }
        if (given != null) return why.refuse("--disable twice: give one list", .{});
        _, given = try flagValue(before_disable, &i, why);
    }
    const disabled: cmdline.Protections = if (given) |v| try disableValue(v, why) else .empty;
    if (!disabled.eql(.empty) and !disabled.eql(.full) and
        !disabled.eql(firecracker.unavailable)) return why.refuse(
        "--disable={s}: use secureboot,tpm for Firecracker with IPE, or " ++ every_protection,
        .{given.?},
    );
    if (version != null and (from_tree or !disabled.eql(.empty))) return why.refuse(
        "--version requires a protected image download; omit --build and --disable",
        .{},
    );
    return .{
        .disabled = disabled,
        .dev = dev,
        .local = from_tree,
        .yes = yes,
        .version = version,
        .args = args.items,
    };
}

test "SSH iteration alone gives developer access" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: Why = .{};
    try testing.expect((try launchFlags(arena.allocator(), &.{"--dev=ssh"}, &why)).dev);
    // The developer shell is retired: --dev is no flag of launch's.
    const bare = try launchFlags(arena.allocator(), &.{"--dev"}, &why);
    try testing.expect(!bare.dev and bare.args.len == 1);
}

/// every_protection is the one --disable run and create take for now: one
/// protected profile provides Secure Boot, the TPM and IPE.
pub const every_protection = "secureboot,tpm,ipe";

/// disableValue parses --disable's list (cmdline.Protection). Secure Boot
/// goes only with the TPM, whose record unsigned boot code could ignore.
pub fn disableValue(v: []const u8, why: *Why) !cmdline.Protections {
    const set = cmdline.protections(v) orelse return why.refuse(
        "--disable={s}: it names secureboot, tpm or ipe, comma-separated, each once",
        .{v},
    );
    if (set.contains(.secureboot) and !set.contains(.tpm)) return why.refuse(
        "--disable={s}: unsigned boot code could ignore the TPM, so secureboot goes with tpm",
        .{v},
    );
    return set;
}

/// securedHere reports whether on runs protected machines on this host
/// (local-secure.zig), rather than in a cloud.
fn securedHere(on: Platform) bool {
    return on == .lima or on == .qemu or on == .bhyve;
}

fn requireProtection(on: Platform, launch: Launch, why: *Why) !void {
    if (launch.dev and !launch.disabled.eql(.full)) return why.refuse(
        "developer access requires an unprotected local machine: " ++
            "--dev=ssh --disable=" ++ every_protection,
        .{},
    );
    if (on == .firecracker) {
        if (launch.version != null) return why.refuse(
            "Firecracker cannot boot a protected UEFI download; omit --version to build " ++
                "an IPE image with host-pinned boot files",
            .{},
        );
        return;
    }
    if (!launch.disabled.eql(.empty) and !launch.disabled.eql(.full)) return why.refuse(
        "--disable=secureboot,tpm is supported by Firecracker only; this provider requires " ++
            "all protections or --disable=" ++ every_protection,
        .{},
    );
    if (!launch.protected()) return;
    if (securedHere(on)) return;
    // A cloud's firmware enrolls the image's own boot key; its first boot
    // takes the TPM (docs/design/implemented/independent-updates.md).
    if (on.is(.cloud)) {
        if (launch.local) return;
        return why.refuse(
            "{t}: werewolf publishes no {t} image yet; build one with your own keys: --build",
            .{ on, on },
        );
    }
    return why.refuse(
        "{t}: protected deployment is not ready; use Lima on macOS, QEMU on Linux or a cloud, " ++
            "or give up what {t} cannot provide yet: --disable=" ++ every_protection,
        .{ on, on },
    );
}

test "deployment defaults protect Lima, QEMU and bhyve without backend fallback" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: Why = .{};
    const launch = try launchFlags(arena.allocator(), &.{ "playground", "--build" }, &why);
    try testing.expect(launch.protected() and launch.local);
    try testing.expect((Options{}).protected());
    try testing.expectEqual(Platform.lima, protectedEngine(.macos, null));
    try testing.expectEqual(Platform.qemu, protectedEngine(.linux, null));
    try requireProtection(.lima, launch, &why);
    try requireProtection(.qemu, launch, &why);
    const downloaded = try launchFlags(arena.allocator(), &.{"playground"}, &why);
    try testing.expect(downloaded.protected() and !downloaded.local);
    try requireProtection(.lima, downloaded, &why);
    try requireProtection(.qemu, downloaded, &why);
    try requireProtection(.bhyve, downloaded, &why);
    try requireProtection(.bhyve, launch, &why);
    try requireProtection(.firecracker, launch, &why);
    try testing.expectError(error.Refused, requireProtection(.proxmox, launch, &why));
    // Clouds take a protected image built here; werewolf publishes none for them.
    for ([_]Platform{ .aws, .gcp, .azure }) |on| {
        try requireProtection(on, launch, &why);
        try testing.expectError(error.Refused, requireProtection(on, downloaded, &why));
    }
    const dev = try launchFlags(arena.allocator(), &.{ "playground", "--dev=ssh" }, &why);
    try testing.expectError(error.Refused, requireProtection(.lima, dev, &why));
    const unprotected = try launchFlags(
        arena.allocator(),
        &.{ "--disable=secureboot,tpm,ipe", "playground", "--dev=ssh" },
        &why,
    );
    try testing.expect(unprotected.disabled.eql(.full) and unprotected.dev);
    try testing.expectEqualSlices([]const u8, &.{"playground"}, unprotected.args);
    try requireProtection(.firecracker, unprotected, &why);
    const spaced = try launchFlags(
        arena.allocator(),
        &.{ "--disable", "ipe,tpm,secureboot" },
        &why,
    );
    try testing.expect(spaced.disabled.eql(.full) and spaced.args.len == 0);
    for ([_][]const []const u8{
        &.{ "playground", "--disable=tpm" },
        &.{ "playground", "--disable=landlock" },
        &.{ "playground", "--disable" },
        &.{ "--disable=secureboot,tpm,ipe", "--disable=secureboot,tpm,ipe" },
    }) |line| try testing.expectError(error.Refused, launchFlags(arena.allocator(), line, &why));
}

test "versioned installs retain the download profile and reject conflicting modes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: Why = .{};
    const launch = try launchFlags(
        arena.allocator(),
        &.{ "playground", "--version=20261014T232908Z", "--on", "qemu" },
        &why,
    );
    try testing.expectEqualStrings("20261014T232908Z", launch.version.?);
    try testing.expect(launch.protected() and !launch.local);
    try testing.expectEqualSlices([]const u8, &.{ "playground", "--on", "qemu" }, launch.args);
    for ([_][]const []const u8{
        &.{ "--version", "20261014T232908Z", "--build" },
        &.{ "--version", "20261014T232908Z", "--disable=secureboot,tpm,ipe" },
        &.{ "--version", "20261014T232908Z", "--version", "20261014T232908Z" },
        &.{ "--version", "../image" },
        &.{"--version"},
    }) |line| try testing.expectError(error.Refused, launchFlags(arena.allocator(), line, &why));
}

test "Firecracker retains IPE and refuses developer and download downgrades" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: Why = .{};
    const gpa = arena.allocator();
    const partial = try launchFlags(gpa, &.{"--disable=secureboot,tpm"}, &why);
    try requireProtection(.firecracker, partial, &why);
    try testing.expect(!partial.disabled.contains(.ipe));
    try testing.expectError(error.Refused, requireProtection(.qemu, partial, &why));
    const dev = try launchFlags(gpa, &.{ "--disable=secureboot,tpm", "--dev=ssh" }, &why);
    try testing.expectError(error.Refused, requireProtection(.firecracker, dev, &why));
    const download = try launchFlags(gpa, &.{ "--version", "20261014T232908Z" }, &why);
    try testing.expectError(error.Refused, requireProtection(.firecracker, download, &why));
}

/// madeOn returns the platform create recorded for name, or null.
pub fn madeOn(io: Io, gpa: Allocator, name: []const u8) ?Platform {
    const path = gpa.print("{s}/engine", .{machineDir(gpa, name) catch return null}) catch
        return null;
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64)) catch return null;
    return std.meta.stringToEnum(Platform, std.mem.trim(u8, text, " \n"));
}

/// run_name is the name of the one machine run keeps.
pub const run_name = "werewolf-run";

fn create(io: Io, gpa: Allocator, line: []const []const u8, why: *Why) !void {
    const all = (try adhoc.take(io, gpa, .create, line, why)) orelse return;
    return createFrom(io, gpa, all, false, why);
}

/// createFrom is create after adhoc.take has expanded the line: the form
/// first, then the name and flags.
fn createFrom(io: Io, gpa: Allocator, all: []const []const u8, replacing: bool, why: *Why) !void {
    const began = Io.Clock.awake.now(io);
    const verbose, const some = try verboseFlag(gpa, all);
    var milestones: progress.Milestones = .init(io, !verbose);
    defer milestones.finish();
    const launch = try launchFlags(gpa, some, why);
    const args = launch.args;
    const dev = launch.dev;
    const yes = launch.yes;
    var o = try options(gpa, args, why);
    o.local = launch.local;
    o.dev = dev;
    o.disabled = launch.disabled;
    if (o.out != null or o.check)
        return why.refuse("create takes no -o or -n: howl pack writes a tar", .{});
    const eng = engineFor(io, gpa, o.on, o.protected());
    const on = eng.on;
    try bhyveNetworkOptions(o, on, why);
    if (!o.help) {
        try requireProtection(on, launch, why);
        // Refuse an unavailable host before downloads or replacement of run's
        // previous machine. Later checks still guard each actual launch.
        if (o.protected() and securedHere(on) and on != .lima)
            _ = try @import("local-secure.zig").admit(io, gpa, on, dev, why);
    }
    if (on == .firecracker) {
        if (o.disabled.eql(.empty)) o.disabled = firecracker.unavailable;
        if (!o.help) {
            say(io, "warning: {s}", .{firecracker.warning});
            if (!firecracker.installed(io, gpa)) return why.refuse(
                "--on firecracker: Linux with /dev/kvm, and Firecracker 1.17+ on the PATH " ++
                    "(tools/install-deps)",
                .{},
            );
        }
    }
    o.on = on;
    milestones.enabled = !o.help and !verbose;
    milestones.enter(.{
        .name = try gpa.print("Resolving {s} deployment for {t}", .{ o.form, on }),
        .short = "resolve",
    });
    if (o.protected() and !o.local) {
        o.production_download = true;
        if (o.app != null or !forms.isName(o.form)) return why.refuse(
            "custom code requires --build; signed downloads deploy a published form",
            .{},
        );
        o.boot_image = try @import("download.zig").selected(
            io,
            gpa,
            o.form,
            on,
            try localArch(why),
            launch.version,
            why,
        );
        const descriptor = try @import("boot-image.zig").admitHead(
            io,
            gpa,
            o.boot_image.?,
            try localArch(why),
        );
        @import(
            "boot-config.zig",
        ).current = descriptor.configuration orelse return error.MissingDeploymentDefinition;
    }
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

    if (on == .lima) {
        try @import("local-secure.zig").reconcileLima(io, gpa, name, why);
        if (o.protected()) _ = try @import("local-secure.zig").admit(io, gpa, on, dev, why);
    }
    if (on == .bhyve) try @import("local-secure.zig").restoreBhyveNetwork(io, gpa, &o, name);
    // `howl run` owns one disposable machine. Older howl releases made it
    // without the protected enrollment profile, so replace that legacy VM
    // before a source build instead of building for an instance we cannot
    // resume and refusing it only at launch time.
    if (replacing and o.protected() and std.mem.eql(u8, name, run_name)) {
        if (madeOn(io, gpa, name)) |previous| {
            const profile = try gpa.print(
                "{s}/authority/profile.json",
                .{try machineDir(gpa, name)},
            );
            const enrolled = if (Dir.cwd().access(io, profile, .{}))
                true
            else |err| switch (err) {
                error.FileNotFound => false,
                else => return err,
            };
            if (!enrolled) {
                milestones.enter(.{
                    .name = "Replacing the previous unenrolled run VM",
                    .short = "replace",
                });
                try verbs.remove(io, gpa, name, previous, why);
            }
        }
    }
    if (o.boot_image != null) try @import("local-secure.zig").resumeDownload(
        io,
        gpa,
        &o,
        name,
        why,
    );
    if (on == .bhyve and o.boot_image != null) try bhyveDownloadNetwork(&o, why);
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
        .milestones = &milestones,
    };
    if (on == .disk) return why.refuse(
        "--on disk is pack's: howl build and howl pack make a disk and its tar",
        .{},
    );
    if (dev and !on.here()) return why.refuse(
        "--dev=ssh is for machines here, not {t}: developer SSH is never released",
        .{on},
    );
    if (on.here() and ((o.arch != null and o.arch != hostArch()) or o.size != null))
        return why.refuse("{s}: {t} runs this machine's arch", .{ sized_only, on });
    // On Lima or explicitly selected SLIRP, a form with no DHCP client gets the hypervisor's
    // user network in its tar (Lima's, as a Lima-managed machine's command
    // line sets it, or bhyve's slirp), unless the flags or --config DIR
    // give one.
    const on_lima = on == .lima;
    // A Firecracker machine's address is its tap's, on the kernel command
    // line. Only --dns is allowed, and it goes there, not in the tar.
    var fc_dns: ?[]const u8 = null;
    if (on == .firecracker) {
        if (o.ip != null or o.gw != null) return why.refuse(
            "--ip and --gw: a Firecracker machine's address is its tap's, 172.16.0.0/16",
            .{},
        );
        fc_dns = o.dns;
        o.dns = null;
    }
    const on_slirp = on == .bhyve and o.network == .slirp;
    const dhcp = dev or !(on_lima or on_slirp) or try hasDhcp(io, gpa, o.form, why);
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
    // Root's keys, where none are given: the person's own, at once for a
    // machine here, theirs already; elsewhere if they agree.
    const given_keys = o.root_keys != null or if (o.config) |d|
        if (Dir.cwd().access(io, try std.fs.path.join(gpa, &.{ d, "authorized_keys" }), .{}))
            true
        else |_|
            false
    else
        false;
    if (!given_keys) {
        if (dev) {
            o.own_keys = try keys.devPublic(io, gpa);
        } else if (@import("boot-config.zig").forForm(o.form)) |definition| {
            if (definition.ssh != .disabled) o.own_keys = try keys.offerFor(
                io,
                gpa,
                definition.ssh == .files,
                name,
                yes or on.here(),
                verbose,
            );
        } else o.own_keys = try keys.offer(
            io,
            gpa,
            try chain(io, gpa, o.form, why),
            name,
            yes or on.here(),
            verbose,
        );
    }
    const entries = try keys.addCurrentUser(
        io,
        gpa,
        iface,
        o,
        try gather(io, gpa, iface, o, why),
        why,
    );
    const tar = try writeTar(gpa, entries);
    if (misfit(entries, tar.len, on)) |r| return why.refuse("not for {t}: {s}", .{ on, r });
    if (replacing) {
        var keep = false;
        if (o.protected() and securedHere(on)) {
            const cached = try @import("local-secure.zig").reuse(io, gpa, o, name, tar);
            if (cached == .running) {
                milestones.done(.{
                    .name = try gpa.print("{s} running, inputs unchanged; total", .{name}),
                    .short = "ready",
                });
                try local.protectedReady(io, gpa, name, o.form, on, true, w, why);
                return;
            }
            keep = cached == .configure;
        }
        if (o.protected() and madeOn(io, gpa, name) != null) keep = true;
        if (!keep) if (madeOn(
            io,
            gpa,
            name,
        )) |was| verbs.remove(io, gpa, name, was, why) catch |err| say(
            io,
            "{s}: the last one, on {t}, was not removed: {s}",
            .{ name, was, if (err == error.Refused) why.text else @errorName(err) },
        );
    }
    if (o.allow_from) |a| {
        if (!on.is(.cloud)) return why.refuse(
            "--allow-from is for --on {s}: {t}'s machines are reached as it says",
            .{ Platform.list(.cloud, ", "), on },
        );
        // Resolve and check it before anything is built or made.
        o.allow_from = try cloud.allowSource(io, gpa, a, why);
    }
    // A protected --build machine here boots an image built with the user's
    // own keys; a cloud's is built as its release disk (cloud.zig).
    if (o.protected() and o.local and securedHere(on) and o.built == null)
        try @import("local-secure.zig").resumeLocal(io, gpa, &o, name, tell, why);
    // Record the platform, so delete, console and ssh find the machine.
    const dir = try machineDir(gpa, name);
    try Dir.cwd().createDirPath(io, dir);
    try writePrivate(io, gpa, try gpa.print("{s}/engine", .{dir}), @tagName(on), why);
    const dev_key_marker = try gpa.print("{s}/dev", .{dir});
    if (dev) {
        try writePrivate(io, gpa, dev_key_marker, if (given_keys) "custom\n" else "managed\n", why);
    } else Dir.cwd().deleteFile(io, dev_key_marker) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return why.refuse("{s}: {s}", .{ dev_key_marker, @errorName(err) }),
    };
    switch (on) {
        .qemu => try local.createQemu(io, gpa, o, name, tar, tell, why),
        .gcp => try cloud.createGcp(io, gpa, o, name, tar, w, why),
        .aws => try cloud.createAws(io, gpa, o, name, tar, w, why),
        .azure => try cloud.createAzure(io, gpa, o, name, entries, tar, w, why),
        .bhyve => try local.createBhyve(io, gpa, o, name, tar, tell, w, why),
        .proxmox => try local.createProxmox(io, gpa, o, name, tar, w, why),
        .firecracker => try local.createFirecracker(io, gpa, o, name, tar, fc_dns, tell, why),
        .lima => try local.createLima(io, gpa, o, name, tar, dhcp, tell, w, why),
        .disk => unreachable,
    }
    try @import("apply.zig").enroll(io, gpa, name, o, on, why);
}

fn bhyveDownloadNetwork(o: *Options, why: *Why) !void {
    // Published x86 QEMU UKIs sign their SLIRP network into the command line.
    // A config disk cannot override it; never rewrite signed boot material.
    if (o.network == .tap or o.bridge != null) return why.refuse(
        "the published x86 image signs in its SLIRP network; TAP requires an image built " ++
            "for TAP with --build. Omit --bridge/--network tap for the published image",
        .{},
    );
    if (o.ip != null or o.gw != null or o.dns != null) return why.refuse(
        "the published bhyve image fixes its SLIRP address, gateway and DNS; omit --ip, --gw " ++
            "and --dns",
        .{},
    );
    o.network = .slirp;
}

test "published bhyve selects compatible SLIRP and refuses ignored TAP or static flags" {
    var why: Why = .{};
    var o: Options = .{};
    try bhyveDownloadNetwork(&o, &why);
    try testing.expectEqual(bhyve.Mode.slirp, o.network.?);
    for ([_]Options{
        .{ .network = .tap },
        .{ .bridge = "bridge0" },
        .{ .ip = "10.1.2.3/24" },
        .{ .dns = "1.1.1.1" },
    }) |given| {
        var bad = given;
        try testing.expectError(error.Refused, bhyveDownloadNetwork(&bad, &why));
    }
}

fn bhyveNetworkOptions(o: Options, on: Platform, why: *Why) !void {
    if ((o.network != null or o.bridge != null) and on != .bhyve)
        return why.refuse("--network and --bridge are for --on bhyve", .{});
    if (o.network == .slirp and o.bridge != null)
        return why.refuse("--bridge goes with TAP, not --network slirp", .{});
}

test "bhyve network selection defaults to TAP and retains explicit SLIRP" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const tap = try options(
        gpa,
        &.{ "playground", "--on", "bhyve", "--bridge", "re0bridge" },
        &why,
    );
    try testing.expectEqual(bhyve.Mode.tap, tap.network orelse .tap);
    try bhyveNetworkOptions(tap, .bhyve, &why);
    const slirp = try options(gpa, &.{ "playground", "--network=slirp" }, &why);
    try testing.expectEqual(bhyve.Mode.slirp, slirp.network.?);
    try testing.expectError(error.Refused, bhyveNetworkOptions(slirp, .qemu, &why));
    var bad = slirp;
    bad.bridge = "re0bridge";
    try testing.expectError(error.Refused, bhyveNetworkOptions(bad, .bhyve, &why));
    try testing.expectError(
        error.Refused,
        options(gpa, &.{ "playground", "--network=other" }, &why),
    );
    try testing.expectError(
        error.Refused,
        options(gpa, &.{ "playground", "--network=tap", "--network=slirp" }, &why),
    );
}

/// listens returns the TCP ports form serves, as its chain's net lines
/// declare them (lib/form.zig): listen tcp/80 tcp/443, in order, once each.
pub fn listens(io: Io, gpa: Allocator, form: []const u8, why: *Why) ![]const u16 {
    if (@import("boot-config.zig").forForm(form)) |definition| return definition.ports;
    const c = try chain(io, gpa, form, why);
    var f: forms.Failure = .{};
    return forms.listens(gpa, c, &f) catch |err| switch (err) {
        error.Form => why.refuse("{s}", .{f.text}),
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// listensDev reports the ports of a local developer VM, including its
/// automatically added SSH service.
pub fn listensDev(io: Io, gpa: Allocator, form: []const u8, dev: bool, why: *Why) ![]const u16 {
    if (!dev) return listens(io, gpa, form, why);
    const c = try devChain(io, gpa, form, why);
    var f: forms.Failure = .{};
    return forms.listens(gpa, c, &f) catch |err| switch (err) {
        error.Form => why.refuse("{s}", .{f.text}),
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// hasDhcp reports whether form's chain runs dhcp-client, as its form.yaml
/// programs say.
pub fn hasDhcp(io: Io, gpa: Allocator, form: []const u8, why: *Why) !bool {
    if (@import("boot-config.zig").forForm(form)) |definition| return definition.dhcp;
    for (try chain(io, gpa, form, why)) |f|
        for (try f.items(gpa, "programs")) |p| if (std.mem.eql(u8, p, "dhcp-client")) return true;
    return false;
}

/// notMade refuses a machine that howl create did not make.
pub fn notMade(name: []const u8, on: Platform, why: *Why) error{Refused} {
    return why.refuse("{s} was not made by howl create; it is {t}'s alone", .{ name, on });
}

/// reconfigurable refuses a new config for an existing machine made of the
/// form was ("" if create did not make it) unless the form is the same and
/// there is no --app, since an application is in the image.
/// only while the data is first made, so an existing machine refuses it too.
pub fn reconfigurable(
    o: Options,
    name: []const u8,
    was: []const u8,
    on: Platform,
    why: *Why,
) !void {
    if (o.app != null) return why.refuse(
        "{s} exists, and an application is in the image: howl delete {s} --on {t}, then create",
        .{ name, name, on },
    );
    if (was.len == 0) return notMade(name, on, why);
    if (!std.mem.eql(
        u8,
        std.fs.path.basename(std.mem.trimEnd(u8, was, "/")),
        std.fs.path.basename(std.mem.trimEnd(u8, o.form, "/")),
    )) return why.refuse(
        "{s} runs {s}, not {s}: another form is another image; howl delete {s} --on {t}, " ++
            "then create",
        .{ name, was, o.form, name, on },
    );
}

test "reconfigure accepts a cloud form label for a local manifest path" {
    var why: Why = .{};
    const o: Options = .{ .form = "build/adhoc/web/" };
    try reconfigurable(o, "web-vm", "web", .gcp, &why);
    try testing.expectError(error.Refused, reconfigurable(o, "web-vm", "other", .gcp, &why));
    try testing.expectError(error.Refused, reconfigurable(o, "web-vm", "", .gcp, &why));
}

/// releaseDisk returns the form's release disk.qcow2, with --app's
/// application, and builds it if it is stale, as howl build would.
pub fn releaseDisk(io: Io, gpa: Allocator, o: Options, arch: Arch, why: *Why) ![]const u8 {
    return releaseDiskAt(io, gpa, o, arch, o.on orelse .qemu, null, why);
}

pub fn releaseDiskAt(
    io: Io,
    gpa: Allocator,
    o: Options,
    arch: Arch,
    provider: Platform,
    target: ?[]const u8,
    why: *Why,
) ![]const u8 {
    const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
    const name = std.fs.path.basename(std.mem.trimEnd(u8, o.form, "/"));
    var steps: progress.Steps = try .init(io, gpa, why, .{
        .command = try gpa.print("howl build --with {s} --arch {t}{s}{s}", .{
            o.form,
            arch,
            if (o.app != null) " --app " else "",
            o.app orelse "",
        }),
        .log = try gpa.print("build/log/{s}-{t}-build.log", .{ name, arch }),
        .first = start_phase,
    });
    const configured_key = environ.get("WEREWOLF_BOOT_KEY");
    const boot_signer: ?@import(
        "secureboot.zig",
    ).Keys = if (target == null) null else if (configured_key) |key|
        .{ .key = key, .cert = environ.get("WEREWOLF_BOOT_CRT") orelse "release/boot.crt" }
    else
        try @import("secureboot.zig").signer(
            io,
            gpa,
            &steps,
            try keysDir(
                io,
                gpa,
                try gpa.print("boot/{t}", .{arch}),
                try gpa.print("build/boot/{t}", .{arch}),
            ),
            false,
        );
    const ipe_inputs: ?@import(
        "prerequisites.zig",
    ).Inputs = if (o.protected() and target != null and
        environ.get("WEREWOLF_IPE_KERNEL") == null)
        try @import("prerequisites.zig").resolve(io, gpa, &steps, arch, why)
    else
        null;
    const kernel = if (target != null)
        environ.get("WEREWOLF_IPE_KERNEL") orelse if (ipe_inputs) |inp| inp.kernel else null
    else
        null;
    // A kernel with IPE, given here, keeps IPE whatever --disable gave up.
    var disabled = o.disabled;
    if (kernel != null) disabled.remove(.ipe);
    // WEREWOLF_DISK_ARGS adds kernel arguments to a cloud disk's signed command
    // line, for diagnosis: earlycon, ignore_loglevel. The build signs them.
    var words: std.ArrayList([]const u8) = .empty;
    if (environ.get("WEREWOLF_DISK_ARGS")) |extra| {
        var it = std.mem.tokenizeAny(u8, extra, " \t");
        while (it.next()) |w| try words.append(gpa, w);
    }
    const spec: native.Spec = .{
        .form = o.form,
        .variants = variants,
        .arch = arch,
        .disabled = disabled,
        .disk = .{ .args = words.items },
        .app = ab.root,
        .published = !o.local,
        .boot_key = if (boot_signer) |k| k.key else null,
        .boot_cert = if (boot_signer) |k| k.cert else null,
        .boot_native = target != null,
        .qcow2_path = target,
        .ipe_kernel = kernel,
        .ipe_key = if (kernel != null)
            environ.get("WEREWOLF_IPE_KEY") orelse if (ipe_inputs) |inp| inp.key else null
        else
            null,
        .ipe_cert = if (kernel != null)
            environ.get("WEREWOLF_IPE_CRT") orelse if (ipe_inputs) |inp| inp.cert else null
        else
            null,
        .ipe_updates = if (kernel != null) environ.get("IPE_UPDATES") else null,
        .image_serial = if (kernel != null) environ.get("IMAGE_SERIAL") else null,
        // A cloud's protected image holds its release to the TPM floor.
        .tpm = target != null and kernel != null and !o.disabled.contains(.tpm),
        .image_index = if (environ.get("IMAGE_INDEX")) |text|
            cmdline.releaseIndex(text) orelse return why.refuse(
                "IMAGE_INDEX={s}: a release index, 1 or more",
                .{text},
            )
        else
            1,
    };
    const p = try buildHere(
        io,
        gpa,
        &steps,
        spec,
        .{ .qcow2 = true, .private_machine = target != null },
    );
    if (target) |disk| {
        const secure = @import("local-secure.zig");
        const images = @import("data-image.zig");
        const local_spec = secure.scrubLocalSpec(spec);
        var recorded = local_spec;
        recorded.disk_path = disk;
        const definition = try @import("boot-config.zig").derive(io, gpa, o.form, name, why);
        const approved = try images.approve(io, gpa, secure.Profile{
            .spec = recorded,
            .local = local_spec,
            .provider = provider,
            .managed = false,
            .configuration = definition,
        }, true, why);
        var profile = approved.profile;
        profile.provider = provider;
        profile.spec.disk_path = disk;
        profile.configuration = definition;
        profile.local = local_spec;
        const authority = try gpa.print("{s}/authority", .{std.fs.path.dirname(disk).?});
        try Dir.cwd().createDirPath(io, authority);
        try Dir.cwd().setFilePermissions(io, authority, .fromMode(0o700), .{});
        try images.replaceRecord(
            io,
            gpa,
            try gpa.print("{s}/profile.json", .{authority}),
            try std.json.Stringify.valueAlloc(gpa, profile, .{}),
        );
    }
    _ = try steps.finish();
    return target orelse gpa.print("{s}/disk.qcow2", .{p.out});
}

pub fn isMachineName(s: []const u8) bool {
    if (s.len == 0 or s.len > 32 or !std.ascii.isLower(s[0])) return false;
    for (s) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

/// isIp4 reports whether s is a dotted-quad IPv4 address: what a guest's
/// lease or console says is accepted as an address only in this form.
pub fn isIp4(s: []const u8) bool {
    var octets = std.mem.splitScalar(u8, s, '.');
    var n: usize = 0;
    while (octets.next()) |o| : (n += 1) {
        if (o.len == 0 or o.len > 3) return false;
        for (o) |c| if (!std.ascii.isDigit(c)) return false;
        if ((std.fmt.parseInt(u16, o, 10) catch return false) > 255) return false;
    }
    return n == 4;
}

test isIp4 {
    try std.testing.expect(isIp4("192.168.1.40"));
    try std.testing.expect(!isIp4("192.168.1"));
    try std.testing.expect(!isIp4("192.168.1.256"));
    try std.testing.expect(!isIp4("1.2.3.4.5"));
    try std.testing.expect(!isIp4("1.2.3.\x1b[2J"));
}

/// row writes one line of -h: the flag, then, in a column, where it goes.
fn row(w: *Io.Writer, flag: []const u8, what: []const u8) !void {
    try w.print("  {s}", .{flag});
    try w.splatByteAll(' ', @max(2, 30 -| flag.len));
    try w.print("{s}\n", .{what});
}

// --- names -------------------------------------------------------------------------------

/// declared reports whether something on the machine reads path: one of
/// werewolf's own files, or a file or settings a service declares.
fn declared(iface: Interface, path: []const u8) bool {
    for (own_files) |p| if (std.mem.eql(u8, p, path)) return true;
    for (iface.files) |f| if (std.mem.eql(u8, f.path, path)) return true;
    for (iface.settings) |st| if (std.mem.eql(u8, st.path, path)) return true;
    return false;
}

/// isTarName reports whether every config tar reader takes s
/// (settings.entryName): [A-Za-z0-9._-/], relative, with no empty, . or ..
/// part, and at most 100 bytes, to fit ustar's name field.
pub fn isTarName(s: []const u8) bool {
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
    _ = @import("discovery.zig");
    _ = @import("local-secure.zig");
    _ = @import("secureboot.zig");
    _ = @import("prerequisites.zig");
    _ = @import("owner.zig");
    _ = @import("download.zig");
    _ = @import("swtpm.zig");
    _ = @import("firmware.zig");
    _ = @import("apply.zig");
    _ = lima;
    _ = bhyve;
    _ = firecracker;
    _ = proxmox;
    _ = gcp;
    _ = aws;
    _ = azure;
    _ = app;
    _ = @import("image.zig");
    _ = @import("slot.zig");
    _ = @import("apk.zig");
    _ = @import("published.zig");
    _ = @import("keys.zig");
    _ = adhoc;
    _ = oci;
    _ = @import("progress.zig");
    _ = @import("qemu.zig");
    _ = @import("boot.zig");
    _ = local;
    _ = cloud;
    _ = verbs;
    _ = native;
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

    // Each service starts with lines leash takes; what follows is refused.
    const head = "exec /a\nuser x\npledge stdio\n";

    // A secret is a file flag named for its variable, optional as its line says.
    const sec = try interface(gpa, &.{.{
        .name = "jobs",
        .path = "",
        .text = head ++ "secret SMTP_PASSWORD /run/config/m/smtp-password optional",
    }}, &why);
    try testing.expectEqualStrings("smtp-password", sec.files[0].flag);
    try testing.expectEqualStrings("m/smtp-password", sec.files[0].path);
    try testing.expect(sec.files[0].optional);
    const refused = [_][]const [2][]const u8{
        // Two services declare one flag, as a form on prod-ssh with a bastion would.
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
        // pack refuses what leash refuses: render twice, or optional settings.
        &.{.{
            "a",
            head ++ "config settings /run/config/a/s.json\nsetting a ip\nrender conf x\n" ++
                "render conf y",
        }},
        &.{.{ "a", head ++ "config settings /run/config/a/s.json optional" }},
        &.{.{ "a", head ++ "config ../k /run/config/a/k" }},
        &.{.{ "a", "config k /run/config/a/k" }},
        // One flag, two services, not alike: of two types, or a file and
        // a setting.
        &.{
            .{
                "a",
                head ++ "config settings /run/config/a/s.json\nsetting d hostname\nrender env e",
            },
            .{
                "b",
                head ++ "config settings /run/config/b/s.json\nsetting d string\nrender env e",
            },
        },
        &.{
            .{
                "a",
                head ++ "config settings /run/config/a/s.json\nsetting d hostname\nrender env e",
            },
            .{ "b", head ++ "config d /run/config/b/d" },
        },
    };
    for (refused) |texts| {
        var svcs: [2]forms.Service = undefined;
        for (texts, svcs[0..texts.len]) |t, *s| s.* = .{ .name = t[0], .path = "", .text = t[1] };
        try testing.expectError(error.Refused, interface(gpa, svcs[0..texts.len], &why));
    }

    // One secret, one path, read by two services: one flag and one file.
    const shared = try interface(gpa, &.{
        .{
            .name = "web",
            .path = "",
            .text = head ++ "secret PAPERLESS_SECRET_KEY /run/config/paperless/secret-key",
        },
        .{
            .name = "worker",
            .path = "",
            .text = head ++ "secret PAPERLESS_SECRET_KEY /run/config/paperless/secret-key",
        },
    }, &why);
    try testing.expectEqual(@as(usize, 2), shared.files.len);
    try testing.expectEqualStrings("paperless-secret-key", shared.files[0].flag);
    try testing.expectEqualStrings("paperless/secret-key", shared.files[0].path);
    try testing.expectEqualStrings(shared.files[0].path, shared.files[1].path);
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

    // A setting two services declare alike is one flag, its value in each
    // service's settings.json, under each one's key.
    const shared = try interface(gpa, &.{
        .{ .name = "web", .path = "", .text = "exec /a\nuser a\npledge stdio\n" ++
            "config settings /run/config/web/s.json\nsetting domain hostname as DOMAIN\nrender " ++
            "env e" },
        .{ .name = "app", .path = "", .text = "exec /b\nuser b\npledge stdio\n" ++
            "config settings /run/config/app/s.json\nsetting domain hostname required\nrender " ++
            "env e" },
    }, &why);
    const e = try gather(
        testing.io,
        gpa,
        shared,
        try options(gpa, &.{ "x", "--domain", "social.example.com" }, &why),
        &why,
    );
    try testing.expectEqual(@as(usize, 2), e.len);
    for (e) |entry| try testing.expectEqualStrings(
        "{\"domain\":\"social.example.com\"}",
        entry.data,
    );

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

test isTarName {
    try testing.expect(isTarName("bastion/settings.json"));
    try testing.expect(isTarName("data.key"));
    for ([_][]const u8{ "", "/etc/x", "a/../b", "a//b", "a b", "a/", "./a", "é" }) |s|
        try testing.expect(!isTarName(s));
}
