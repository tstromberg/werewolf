//! apply publishes a signed local-NAME package, then the boot config of
//! an enrolled machine. It never replaces the machine's image or data disk.
const std = @import("std");
const howl = @import("howl.zig");
const adhoc = @import("adhoc.zig");
const native = @import("build.zig");
const deployment = @import("deployment.zig");
const progress = @import("progress.zig");
const forms = @import("form");
const gcp = @import("gcp.zig");
const azure = @import("azure.zig");
const aws = @import("aws.zig");
const local = @import("local.zig");
const apk = @import("apk");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

const Enrollment = struct {
    form: []const u8,
    on: howl.Platform,
    arch: howl.Arch,
    from: []const u8,
    key: []const u8,
    app: ?[]const u8,
    machine: []const u8 = "",
};

pub fn enroll(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    o: howl.Options,
    on: howl.Platform,
    why: *howl.Why,
) !void {
    const chain = try howl.chain(io, gpa, o.form, why);
    const from = forms.updates(chain).from orelse return;
    const home = howl.environ.get("HOME") orelse return error.NoHome;
    const public = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/.howl/{s}", .{ home, deployment.key_name }),
        gpa,
        .limited(64 << 10),
    );
    const record: Enrollment = .{
        .form = o.form,
        .on = on,
        .arch = o.arch orelse if (on == .proxmox) .x86_64 else howl.hostArch().?,
        .from = from,
        .key = public,
        .app = o.app,
        .machine = try machineText(gpa, chain),
    };
    try howl.writePrivate(io, gpa, try gpa.print(
        "{s}/declaration.json",
        .{try howl.machineDir(gpa, name)},
    ), try std.json.Stringify.valueAlloc(gpa, record, .{ .whitespace = .indent_2 }), why);
}

const Options = struct {
    file: []const u8,
    name: []const u8,
    to: ?[]const u8 = null,
    app: ?[]const u8 = null,
    preview: bool = false,
    flags: []const []const u8,
};

fn options(gpa: Allocator, args: []const []const u8, why: *howl.Why) !Options {
    if (args.len == 0 or mem.startsWith(u8, args[0], "-"))
        return why.refuse("apply FILE [--name NAME] [--app DIR] [--to ssh://HOST/PATH] [-n]", .{});
    var o: Options = .{ .file = args[0], .name = std.fs.path.stem(args[0]), .flags = &.{} };
    var flags: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (mem.eql(u8, args[i], "-n")) {
            o.preview = true;
            continue;
        }
        const flag, const value = try howl.flagValue(args, &i, why);
        if (mem.eql(u8, flag, "--name"))
            o.name = value
        else if (mem.eql(u8, flag, "--to"))
            o.to = value
        else if (mem.eql(u8, flag, "--app"))
            o.app = value
        else if (mem.eql(u8, flag, "--config") or mem.eql(u8, flag, "--root-keys") or
            mem.eql(u8, flag, "--hostname"))
            try flags.appendSlice(gpa, &.{ flag, value })
        else
            return why.refuse(
                "apply takes no {s}; a new disk, address, platform or size needs a new machine",
                .{flag},
            );
    }
    if (!howl.isMachineName(o.name)) return why.refuse("{s}: not a machine name", .{o.name});
    if (o.to) |to| if (!sshDestination(to)) return why.refuse(
        "--to is ssh://HOST/ABSOLUTE/PATH without shell syntax",
        .{},
    );
    o.flags = flags.items;
    return o;
}

pub fn apply(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    const o = try options(gpa, args, why);
    const dir = try howl.machineDir(gpa, o.name);
    const text = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/declaration.json", .{dir}),
        gpa,
        .limited(64 << 10),
    ) catch
        return why.refuse(
            "{s}: no declaration enrolled; create it first with updates.from",
            .{o.name},
        );
    const enrolled = try std.json.parseFromSliceLeaky(Enrollment, gpa, text, .{});
    const application = o.app orelse enrolled.app;
    const line = try mem.concat(gpa, []const u8, &.{ &.{
        o.name,
        "-f",
        o.file,
        "--arch",
        @tagName(enrolled.arch),
    }, if (application) |app| &.{ "--app", app } else &.{}, o.flags });
    const expanded = (try adhoc.take(io, gpa, .create, line, why)).?;
    const ref = expanded[0];
    var config_options = try howl.options(gpa, expanded, why);
    const chain = try howl.chain(io, gpa, ref, why);
    if (!mem.eql(u8, enrolled.machine, try machineText(gpa, chain)))
        return why.refuse("machine settings changed; create a new machine", .{});
    const from = forms.updates(chain).from orelse return why.refuse(
        "apply needs updates.from",
        .{},
    );
    if (!mem.eql(
        u8,
        enrolled.from,
        from,
    )) return why.refuse("updates.from changed; create a new machine for a new repository", .{});
    if (!mem.eql(u8, std.fs.path.basename(enrolled.form), std.fs.path.basename(ref)))
        return why.refuse("{s}: the machine's form name cannot change", .{o.name});
    const home = howl.environ.get("HOME") orelse return error.NoHome;
    const public = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/.howl/{s}", .{ home, deployment.key_name }),
        gpa,
        .limited(64 << 10),
    );
    if (!mem.eql(
        u8,
        public,
        enrolled.key,
    )) return why.refuse(
        "the signing key differs from {s}'s; restore its key or create a new machine",
        .{o.name},
    );
    const app = try howl.appBuild(io, gpa, ref, enrolled.arch, o.app orelse enrolled.app, why);
    const spec: native.Spec = .{
        .form = ref,
        .arch = enrolled.arch,
        .app = app.root,
        .published = true,
    };
    var steps = try progress.Steps.init(io, gpa, why, .{
        .verbose = false,
        .command = try gpa.print("howl apply {s}", .{o.file}),
        .log = try gpa.print("{s}/apply.log", .{dir}),
        .first = howl.start_phase,
    });
    const paths = try native.paths(gpa, spec);
    native.make(io, gpa, &steps, spec, .{ .lock = true }) catch |err| {
        if (err != error.OlderDeclaration) return err;
        const hash = try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/deployment/older", .{paths.out}),
            gpa,
            .limited(64),
        );
        _ = try steps.finish();
        if (o.preview) return howl.say(
            io,
            "older declaration {s}; would try the other slot if it holds this declaration",
            .{hash},
        );
        return @import("verbs.zig").sshTo(
            io,
            gpa,
            &.{ o.name, "--", "/usr/lib/werewolf/slot-update", "try", hash },
            why,
        );
    };
    const prepared_text = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/deployment/prepared.json", .{paths.out}),
        gpa,
        .limited(64 << 10),
    );
    const prepared = try std.json.parseFromSliceLeaky(deployment.Prepared, gpa, prepared_text, .{});
    config_options.app = null;
    const iface = try howl.formInterface(io, gpa, ref, why);
    const fresh = try howl.gather(io, gpa, iface, config_options, why);
    const old = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/config.tar", .{dir}),
        gpa,
        .limited(16 << 20),
    );
    const entries = try keepMachineConfig(gpa, old, fresh);
    const config = try howl.writeTar(gpa, entries);
    if (howl.misfit(entries, config.len, enrolled.on)) |reason|
        return why.refuse("{t}: {s}", .{ enrolled.on, reason });
    const changed = !mem.eql(u8, old, config);
    if (changed) switch (enrolled.on) {
        .qemu,
        .firecracker,
        .bhyve,
        => Dir.cwd().access(io, try gpa.print("{s}/disk.img", .{dir}), .{}) catch
            return why.refuse("{s}: the enrolled machine's disk is missing", .{o.name}),
        .lima => if (!try @import("lima.zig").exists(io, gpa, o.name))
            return why.refuse("{s}: the enrolled Lima machine is missing", .{o.name}),
        .proxmox => {
            const p = try @import("proxmox.zig").place(howl.environ, why);
            if (try @import("proxmox.zig").find(io, gpa, p, o.name, why) == null)
                return why.refuse("{s}: the enrolled Proxmox machine is missing", .{o.name});
        },
        else => {},
    };
    const next = try gpa.print("{s}/apply-config.tar", .{dir});
    try howl.writePrivate(io, gpa, next, config, why);
    _ = try steps.finish();
    if (o.preview) return howl.say(
        io,
        "prepared {s} {s}; config {s}; no upload (-n)",
        .{ prepared.name, prepared.version, next },
    );
    try publish(io, gpa, prepared, enrolled.arch, o.to, public, why);
    if (changed) switch (enrolled.on) {
        .gcp => {
            const b64 = try gpa.print("{s}/apply-config.b64", .{dir});
            const buf = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(config.len));
            try howl.writePrivate(
                io,
                gpa,
                b64,
                std.base64.standard.Encoder.encode(buf, config),
                why,
            );
            try gcp.publishConfig(io, gpa, try gcp.place(io, gpa, why), o.name, b64, why);
        },
        .azure => try azure.publishConfig(
            io,
            gpa,
            try azure.place(io, gpa, why),
            o.name,
            config,
            dir,
            why,
        ),
        .aws => {
            const p = try aws.place(io, gpa, why);
            const instance = try aws.find(
                io,
                gpa,
                p,
                o.name,
                why,
            ) orelse return why.refuse("{s}: no AWS instance", .{o.name});
            const b64 = try gpa.print("{s}/apply-config.b64", .{dir});
            const buf = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(config.len));
            try howl.writePrivate(
                io,
                gpa,
                b64,
                std.base64.standard.Encoder.encode(buf, config),
                why,
            );
            try aws.reconfigure(io, gpa, p, instance.id, b64, why);
        },
        .qemu, .firecracker, .lima, .bhyve, .proxmox => {
            // These transports read their config disk at boot. Use the
            // existing reconfiguration path: retain the disk and restart.
            const tell: howl.Tell = .{
                .verbose = false,
                .command = "howl apply config",
                .began = Io.Clock.awake.now(io),
            };
            var output = Io.File.stdout().writerStreaming(io, &.{});
            config_options.arch = null;
            config_options.size = null;
            switch (enrolled.on) {
                .qemu => try local.createQemu(io, gpa, config_options, o.name, config, tell, why),
                .firecracker => try local.createFirecracker(
                    io,
                    gpa,
                    config_options,
                    o.name,
                    config,
                    null,
                    tell,
                    why,
                ),
                .lima => try local.createLima(
                    io,
                    gpa,
                    config_options,
                    o.name,
                    config,
                    false,
                    tell,
                    &output.interface,
                    why,
                ),
                .bhyve => try local.createBhyve(
                    io,
                    gpa,
                    config_options,
                    o.name,
                    config,
                    tell,
                    &output.interface,
                    why,
                ),
                .proxmox => try local.createProxmox(
                    io,
                    gpa,
                    config_options,
                    o.name,
                    config,
                    &output.interface,
                    why,
                ),
                else => unreachable,
            }
        },
        .disk => return error.NoConfigTransport,
    };
    if (enrolled.on == .gcp or enrolled.on == .azure or enrolled.on == .aws)
        try howl.writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), config, why);
    var saved = enrolled;
    saved.app = application;
    try howl.writePrivate(
        io,
        gpa,
        try gpa.print("{s}/declaration.json", .{dir}),
        try std.json.Stringify.valueAlloc(gpa, saved, .{ .whitespace = .indent_2 }),
        why,
    );
    howl.say(
        io,
        "published {s} {s}; {s} takes it at its next update check",
        .{ prepared.name, prepared.version, o.name },
    );
}

fn keepMachineConfig(
    gpa: Allocator,
    old: []const u8,
    fresh: []const howl.Entry,
) ![]const howl.Entry {
    var out: std.ArrayList(howl.Entry) = .empty;
    try out.appendSlice(gpa, fresh);
    var reader: Io.Reader = .fixed(old);
    var names: [Dir.max_path_bytes]u8 = undefined;
    var links: [Dir.max_path_bytes]u8 = undefined;
    var it = std.tar.Iterator.init(
        &reader,
        .{ .file_name_buffer = &names, .link_name_buffer = &links },
    );
    var had_network = false;
    var had_key = false;
    while (try it.next()) |entry| {
        if (mem.eql(u8, entry.name, "network")) had_network = true;
        if (mem.eql(u8, entry.name, "data.key")) had_key = true;
        if (!mem.eql(u8, entry.name, "network") and !mem.eql(u8, entry.name, "data.key") and
            !mem.eql(u8, entry.name, "authorized_keys") and
            !mem.eql(u8, entry.name, "hostname")) continue;
        if (entry.size > old.len - reader.seek) return error.TruncatedConfig;
        const prior = old[reader.seek..][0..@intCast(entry.size)];
        const exists = for (fresh) |f| {
            if (!mem.eql(u8, f.path, entry.name)) continue;
            if ((mem.eql(u8, f.path, "network") or mem.eql(u8, f.path, "data.key")) and
                !mem.eql(u8, f.data, prior))
                return error.MachineConfigChanged;
            break true;
        } else false;
        if (exists) continue;
        if (entry.size > old.len - reader.seek) return error.TruncatedConfig;
        const data = try gpa.dupe(u8, old[reader.seek..][0..@intCast(entry.size)]);
        try out.append(
            gpa,
            .{
                .path = try gpa.dupe(u8, entry.name),
                .data = data,
                .from = "the machine's boot config",
            },
        );
    }
    for (fresh) |f| {
        if ((!had_network and mem.eql(u8, f.path, "network")) or
            (!had_key and mem.eql(u8, f.path, "data.key"))) return error.MachineConfigChanged;
    }
    mem.sort(howl.Entry, out.items, {}, struct {
        fn less(
            _: void,
            a: howl.Entry,
            b: howl.Entry,
        ) bool {
            return mem.lessThan(u8, a.path, b.path);
        }
    }.less);
    return out.items;
}

fn machineText(gpa: Allocator, chain: []const forms.Form) ![]const u8 {
    const machine = chain[chain.len - 1].spec.get("machine") orelse return "";
    const sorted = try gpa.dupe(forms.Entry, machine.map);
    mem.sort(forms.Entry, sorted, {}, struct {
        fn less(_: void, a: forms.Entry, b: forms.Entry) bool {
            return mem.lessThan(u8, a.key, b.key);
        }
    }.less);
    var out: Io.Writer.Allocating = .init(gpa);
    try forms.write(&out.writer, .{ .map = sorted });
    return out.written();
}

fn sshDestination(to: []const u8) bool {
    const rest = mem.cutPrefix(u8, to, "ssh://") orelse return false;
    const slash = mem.findScalar(u8, rest, '/') orelse return false;
    if (slash == 0 or slash + 1 == rest.len or rest[0] == '-') return false;
    for (rest) |c| if (!std.ascii.isAlphanumeric(c) and
        mem.findScalar(u8, "@._/-", c) == null) return false;
    return mem.find(u8, rest, "/../") == null and !mem.endsWith(u8, rest, "/..");
}

fn publish(
    io: Io,
    gpa: Allocator,
    p: deployment.Prepared,
    arch: howl.Arch,
    to: ?[]const u8,
    public: []const u8,
    why: *howl.Why,
) !void {
    const dir = try gpa.print("{s}/{t}", .{ p.repository, arch });
    const url = try gpa.print("{s}/{t}", .{ mem.trimEnd(u8, p.from, "/"), arch });
    // A second publisher must not erase versions it has never seen.
    const remote = try std.process.run(gpa, io, .{
        .argv = &.{
            "curl",
            "-sS",
            "--max-time",
            "30",
            "-w",
            "\n%{http_code}",
            try gpa.print("{s}/APKINDEX.tar.gz", .{url}),
        },
        .stdout_limit = .limited(16 << 20),
    });
    if (remote.term != .exited or
        remote.term.exited != 0) return why.refuse(
        "cannot read the existing repository index",
        .{},
    );
    const split = mem.findScalarLast(u8, remote.stdout, '\n') orelse return error.BadHttpStatus;
    const status = remote.stdout[split + 1 ..];
    if (mem.eql(u8, status, "200")) {
        const trusted = [_]apk.Trusted{.{
            .name = deployment.key_name,
            .key = try apk.parseKey(gpa, public),
        }};
        const have = try apk.records(gpa, &trusted, remote.stdout[0..split]);
        const index_text = try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/APKINDEX.tar.gz", .{dir}),
            gpa,
            .limited(16 << 20),
        );
        const ours = try apk.records(gpa, &trusted, index_text);
        for (have) |r| {
            // Check membership explicitly: losing a publisher's local history
            // requires restoring it before publishing another index.
            const kept = for (ours) |n| {
                if (mem.eql(u8, r.name, n.name) and
                    mem.eql(u8, r.version, n.version) and mem.eql(u8, &r.sha1, &n.sha1)) break true;
            } else false;
            if (!kept) return why.refuse(
                "repository has versions missing locally; restore its build repository before " ++
                    "applying",
                .{},
            );
        }
    } else if (!mem.eql(
        u8,
        status,
        "404",
    )) return why.refuse("repository index: HTTP {s}", .{status});
    // Packages first, the signed index last. A failed package upload never
    // makes an index point at an incomplete package.
    var files: std.ArrayList([]const u8) = .empty;
    var repo = try Dir.cwd().openDir(io, dir, .{ .iterate = true });
    defer repo.close(io);
    var it = repo.iterate();
    while (try it.next(io)) |entry| if (mem.endsWith(u8, entry.name, ".apk"))
        try files.append(gpa, try gpa.print("{s}/{s}", .{ dir, entry.name }));
    try files.append(gpa, try gpa.print("{s}/APKINDEX.tar.gz", .{dir}));
    for (files.items) |file| {
        const name = std.fs.path.basename(file);
        if (to) |target| {
            const rest = target["ssh://".len..];
            const slash = mem.findScalar(u8, rest, '/').?;
            const host = rest[0..slash];
            const destination = try gpa.print(
                "{s}/{t}/{s}",
                .{ mem.trimEnd(u8, rest[slash..], "/"), arch, name },
            );
            try howl.run(
                io,
                why,
                &.{ "ssh", host, "mkdir", "-p", std.fs.path.dirname(destination).? },
            );
            try howl.run(
                io,
                why,
                &.{ "scp", file, try gpa.print("{s}:{s}.new", .{ host, destination }) },
            );
            try howl.run(
                io,
                why,
                &.{ "ssh", host, "mv", try gpa.print("{s}.new", .{destination}), destination },
            );
        } else try howl.run(
            io,
            why,
            &.{
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--upload-file",
                file,
                try gpa.print("{s}/{s}", .{ url, name }),
            },
        );
    }
}

test "apply refuses machine changes and shell syntax in SSH destinations" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var why: howl.Why = .{};
    try t.expectError(
        error.Refused,
        options(arena.allocator(), &.{ "shop.yaml", "--ip", "1.2.3.4" }, &why),
    );
    try t.expect(sshDestination("ssh://deploy@host/srv/apk"));
    for ([_][]const u8{
        "ssh://-host/path",
        "ssh://host/path;id",
        "ssh://host/path/../x",
        "ssh://host",
    }) |s| try t.expect(!sshDestination(s));
}

test "apply config retains machine identity and replaces people and secrets" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const old = try howl.writeTar(gpa, &.{
        .{ .path = "hostname", .data = "shop", .from = "test" },
        .{ .path = "network", .data = "old network", .from = "test" },
        .{ .path = "users", .data = "old people", .from = "test" },
        .{ .path = "secret", .data = "old secret", .from = "test" },
    });
    const merged = try keepMachineConfig(
        gpa,
        old,
        &.{.{ .path = "users", .data = "new people", .from = "test" }},
    );
    try t.expectEqual(@as(usize, 3), merged.len);
    try t.expectEqualStrings("hostname", merged[0].path);
    try t.expectEqualStrings("old network", merged[1].data);
    try t.expectEqualStrings("new people", merged[2].data);
    try t.expectError(
        error.MachineConfigChanged,
        keepMachineConfig(gpa, old, &.{.{ .path = "network", .data = "changed", .from = "test" }}),
    );
    try t.expectError(
        error.MachineConfigChanged,
        keepMachineConfig(gpa, old, &.{.{ .path = "data.key", .data = "new", .from = "test" }}),
    );
}
