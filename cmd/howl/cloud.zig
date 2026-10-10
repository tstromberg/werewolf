//! cloud creates machines on GCP, AWS and Azure and opens their ports, and
//! uploads a release disk as an image for VMs made some other way. See
//! README.md.

const std = @import("std");
const howl = @import("howl.zig");
const gcp = @import("gcp.zig");
const aws = @import("aws.zig");
const azure = @import("azure.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Why = howl.Why;
const say = howl.say;
const run = howl.run;
const writePrivate = howl.writePrivate;
const Options = howl.Options;
const Platform = howl.Platform;
const Arch = howl.Arch;
const Entry = howl.Entry;
const machineDir = howl.machineDir;
const listens = howl.listens;
const reconfigurable = howl.reconfigurable;
const releaseDisk = howl.releaseDisk;
const flagValue = howl.flagValue;
const hostArch = howl.hostArch;
const not_built_here = howl.not_built_here;
const options = howl.options;
const testing = std.testing;

/// sayOpen opens a new cloud machine, which lets nothing in, to
/// --allow-from on the form's TCP ports. Without it, it prints the commands
/// that would open them to this host ($ME), ready to paste. delete removes
/// what they make. cloud is gcp, aws or azure, and p its place.
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

/// openText writes why nothing reaches the machine, then the commands to
/// open it, one per line, ready to paste into sh, bash or zsh.
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

/// shellWord writes word so a shell reads it back: bare, or in double
/// quotes if it holds anything but letters, digits and . _ / : , = @ -.
/// Double quotes still let "$ME/32" expand. Only howl's own words come
/// here, none with a quote or backslash.
fn shellWord(w: *Io.Writer, word: []const u8) !void {
    for (word) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and std.mem.findScalar(u8, "._/:,=@-", ch) == null) {
            return w.print("\"{s}\"", .{word});
        }
    } else if (word.len == 0) return w.writeAll("\"\"");
    try w.writeAll(word);
}

/// portList returns "port 22" or "ports 22 8080".
fn portList(gpa: Allocator, ports: []const u16) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, if (ports.len == 1) "port" else "ports");
    for (ports) |port| try out.print(gpa, " {d}", .{port});
    return out.items;
}

/// allowSource checks --allow-from: me, meaning this host's public IPv4
/// address as checkip.amazonaws.com sees it, or an IPv4 address and prefix.
pub fn allowSource(io: Io, gpa: Allocator, given: []const u8, why: *Why) ![]const u8 {
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

/// isCidr reports whether s is an IPv4 address and a prefix of 0 to 32:
/// 10.0.0.0/8.
fn isCidr(s: []const u8) bool {
    const slash = std.mem.findScalar(u8, s, '/') orelse return false;
    const bits = s[slash + 1 ..];
    if (bits.len == 0 or bits.len > 2) return false;
    for (bits) |c| if (!std.ascii.isDigit(c)) return false;
    if ((std.fmt.parseInt(u8, bits, 10) catch return false) > 32) return false;
    _ = std.Io.net.Ip4Address.parse(s[0..slash], 0) catch return false;
    return true;
}

/// newOnly refuses --allow-from for a machine that exists. A second create
/// keeps the rules as the owner left them; --allow-from opens only a new
/// machine's ports.
fn newOnly(o: Options, name: []const u8, on: Platform, why: *Why) error{Refused}!void {
    if (o.allow_from == null) return;
    return why.refuse(
        "{s} exists, and keeps its rules as they are: --allow-from opens a new machine's ports " ++
            "(howl delete {s} --on {t}, then create)",
        .{ name, name, on },
    );
}

/// Cloud is a machine in a cloud: its arch (--arch or this host's), the
/// directory where create keeps its files, and the path of its config tar
/// in base64, as clouds take user data, written 0600 in that directory.
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
    try writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), tar, why);
    const encoded = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(tar.len));
    try writePrivate(io, gpa, b64, std.base64.standard.Encoder.encode(encoded, tar), why);
    return .{ .arch = arch, .dir = dir, .b64 = b64 };
}

/// createGcp makes the release disk a GCP image, once, and a VM of it with
/// the config as user data. A VM of the same form gets a new config and a
/// restart.
pub fn createGcp(
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

/// createAws imports the release disk as an AMI, once, and starts an
/// instance of it with the config as user data, in its own security group
/// that lets nothing in. An instance of the same form gets a new config and
/// a restart.
pub fn createAws(
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

/// createAzure uploads the release disk as a managed disk, once
/// (azure.zig), and makes a specialized VM on a copy of it, with the config
/// tar as its userData. A VM of the same form gets a new config and a
/// restart.
pub fn createAzure(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    entries: []const Entry,
    tar: []const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    // az vm create reads user data as text (azure.carried). Refuse a file
    // it would change here, by name, rather than let az alter it.
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

/// azureUp waits for an Azure machine to boot, reading its console after
/// before, the console's end when the boot began, then prints its address.
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

/// upload is howl upload DISK --on gcp|aws|azure. It makes a release's
/// FORM-ARCH-disk.qcow2 a GCP image, an AMI or an Azure managed disk, as
/// create does, for VMs made some other way (Terraform, the console), and
/// prints the image name or AMI id. An Azure disk serves one VM, so copy it
/// for each (az disk create --source).
pub fn upload(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
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
    // Work in a fresh directory beside the disk, so two uploads at once,
    // of one disk to two clouds or of both arches, never clobber each other.
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

// --- tests -------------------------------------------------------------------------------

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
