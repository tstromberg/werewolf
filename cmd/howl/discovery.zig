//! Browse forms in a checkout or the signed catalog of published images.
const std = @import("std");
const forms = @import("form");
const howl = @import("howl.zig");
const files = @import("files");
const mem = std.mem;
const Io = std.Io;
const Allocator = mem.Allocator;

const repository = "https://github.com/werewolf-linux/werewolf/blob/main/";
const syntax = "usage: howl forms [FORM|SEARCH] [--arch ARCH] [--build|--published] [--json]\n" ++
    "List forms, search names and descriptions, or show one form's setup and commands.\n" ++
    "Uses this checkout when present; otherwise the signed published catalog.\n" ++
    "--build uses this checkout; --published shows which images run/create can download.";

const Image = struct { object: []const u8, serial: []const u8 };
const Row = struct {
    form: []const u8,
    /// Each provider of a published architecture is its own image.
    provider: []const u8 = "",
    arch: howl.Arch,
    summary: []const u8 = "",
    guide: []const u8 = "",
    status: []const u8,
    latest: ?Image = null,
};
const Description = struct { summary: []const u8 = "", guide: []const u8 = "" };

fn description(gpa: Allocator, text: []const u8, name: []const u8) !Description {
    const prefix = try gpa.print("| [{s}](", .{name});
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const rest = mem.cutPrefix(u8, line, prefix) orelse continue;
        const end = mem.find(u8, rest, ") | ") orelse continue;
        return .{
            .summary = mem.trim(u8, rest[end + 4 ..], " |\r"),
            .guide = try gpa.print("{s}{s}", .{
                repository,
                mem.cutPrefix(u8, rest[0..end], "../") orelse rest[0..end],
            }),
        };
    }
    return .{ .guide = try gpa.print("{s}forms/{s}/form.yaml", .{ repository, name }) };
}

fn checkout(io: Io, gpa: Allocator, why: *howl.Why) ![]Row {
    var dir = Io.Dir.cwd().openDir(io, "forms", .{ .iterate = true }) catch
        return why.refuse("no ./forms; use --build from a werewolf checkout root", .{});
    defer dir.close(io);
    const text = Io.Dir.cwd().readFileAlloc(
        io,
        "docs/forms-catalog.md",
        gpa,
        .limited(1 << 20),
    ) catch
        files.forms_catalog;
    var rows: std.ArrayList(Row) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory or !forms.isName(entry.name)) continue;
        dir.access(io, try gpa.print("{s}/form.yaml", .{entry.name}), .{}) catch continue;
        const name = try gpa.dupe(u8, entry.name);
        var failure: forms.Failure = .{};
        const chain = forms.chain(io, gpa, Io.Dir.cwd(), name, &failure) catch |err| switch (err) {
            error.Form => return why.refuse("{s}", .{failure.text}),
            else => return err,
        };
        var arches: []const []const u8 = &.{ "aarch64", "x86_64" };
        for (chain) |form| if (form.spec.get("archs") != null) {
            arches = try form.items(gpa, "archs");
        };
        const details = try description(gpa, text, name);
        for (arches) |arch| try rows.append(gpa, .{
            .form = name,
            .arch = howl.archName(arch) orelse return error.BadFormArch,
            .summary = details.summary,
            .guide = details.guide,
            .status = "source in checkout; image availability not queried",
        });
    }
    return rows.items;
}

/// mirror is where werewolf publishes images and their catalog.
fn mirror(gpa: Allocator) ![]const u8 {
    if (howl.environ.get("WEREWOLF_BOOT_MIRROR")) |url| return url;
    const trust = try std.json.parseFromSliceLeaky(
        struct { source: []const u8 },
        gpa,
        files.protected_trust,
        .{ .ignore_unknown_fields = true },
    );
    return trust.source;
}

fn catalogKey(gpa: Allocator) !@import("apk").Key {
    const pem = files.protected_image_certificate;
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = mem.find(u8, pem, "-----END CERTIFICATE-----") orelse return error.BadCatalogKey;
    var base64: std.ArrayList(u8) = .empty;
    for (pem[begin.len..end]) |c| if (!std.ascii.isWhitespace(c)) try base64.append(gpa, c);
    const decoder = std.base64.standard.Decoder;
    const der = try gpa.alloc(u8, try decoder.calcSizeForSlice(base64.items));
    try decoder.decode(der, base64.items);
    return @import("tpm").firmware.certificateKey(der);
}

fn published(io: Io, gpa: Allocator, base: []const u8, why: *howl.Why) ![]Row {
    @import("prebuilt").channel(base) catch
        return why.refuse("the image mirror must be an HTTPS directory", .{});
    const result = std.process.run(gpa, io, .{
        .argv = &.{
            "curl",       "--fail",
            "--silent",   "--show-error",
            "--location", "--proto",
            "=https",     "--proto-redir",
            "=https",     "--connect-timeout",
            "10",         "--max-time",
            "45",         try gpa.print("{s}/index.json", .{base}),
        },
        .stdout_limit = .limited(4 << 20),
        .stderr_limit = .limited(8192),
    });
    const fetched = result catch |err| return why.refuse("form catalog: {t}", .{err});
    if (fetched.term != .exited or fetched.term.exited != 0) return why.refuse(
        "cannot fetch the published form catalog: {s}\nUse howl forms --build from a checkout.",
        .{mem.trim(u8, fetched.stderr, "\r\n ")},
    );
    const head = try std.json.parseFromSliceLeaky(struct {
        manifest: []const u8,
        signature: []const u8,
    }, gpa, fetched.stdout, .{});
    if (head.signature.len != 512 and head.signature.len != 768 and head.signature.len != 1024)
        return error.BadCatalogSignature;
    const signature = try gpa.alloc(u8, head.signature.len / 2);
    _ = try std.fmt.hexToBytes(signature, head.signature);
    try @import("apk").verify(try catalogKey(gpa), head.manifest, signature);
    const catalog = try std.json.parseFromSliceLeaky(struct {
        format: []const u8,
        forms: []Row,
    }, gpa, head.manifest, .{ .ignore_unknown_fields = true });
    if (!mem.eql(u8, catalog.format, "werewolf-form-catalog/1")) return error.BadCatalogFormat;
    return catalog.forms;
}

fn printable(text: []const u8) bool {
    for (text) |c| if (c < ' ' or c == 127) return false;
    return true;
}

pub fn command(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    var query: ?[]const u8 = null;
    var arch: ?howl.Arch = null;
    var local = false;
    var remote = false;
    var json = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            howl.say(io, "{s}", .{syntax});
            return;
        } else if (mem.eql(u8, arg, "--build")) {
            local = true;
        } else if (mem.eql(u8, arg, "--published")) {
            remote = true;
        } else if (mem.eql(u8, arg, "--json")) {
            json = true;
        } else if (arg.len > 0 and arg[0] == '-') {
            const flag, const value = try howl.flagValue(args, &i, why);
            if (!mem.eql(u8, flag, "--arch")) return why.refuse("{s}\n{s}", .{ flag, syntax });
            if (arch != null) return why.refuse("--arch given twice", .{});
            arch = howl.archName(value) orelse return why.refuse(howl.arch_refusal, .{value});
        } else {
            if (query != null) return why.refuse(
                "give one form name or search term\n{s}",
                .{syntax},
            );
            query = arg;
        }
    }
    if (local and remote) return why.refuse("--build and --published conflict", .{});
    const have_checkout = if (Io.Dir.cwd().access(io, "forms", .{})) |_| true else |_| false;
    local = local or (!remote and have_checkout);
    const base = try mirror(gpa);
    const all = if (local) try checkout(io, gpa, why) else try published(io, gpa, base, why);
    var selected: std.ArrayList(Row) = .empty;
    const exact = if (query) |q| for (all) |row| {
        if (mem.eql(u8, row.form, q)) break true;
    } else false else false;
    for (all) |row| {
        if (!forms.isName(row.form) or !printable(row.summary) or !printable(row.status) or
            !printable(row.guide) or
            (row.guide.len > 0 and !mem.startsWith(u8, row.guide, repository)) or
            (!local and !mem.eql(u8, row.provider, "qemu") and !mem.eql(u8, row.provider, "lima")))
            return error.BadCatalogEntry;
        if (row.latest) |latest| if (!printable(latest.object) or !printable(latest.serial))
            return error.BadCatalogEntry;
        if (arch != null and arch.? != row.arch) continue;
        if (query) |q| {
            if (exact) {
                if (!mem.eql(u8, row.form, q)) continue;
            } else if (std.ascii.findIgnoreCase(row.form, q) == null and
                std.ascii.findIgnoreCase(row.summary, q) == null) continue;
        }
        if (!exact and mem.eql(u8, row.status, "unsupported architecture")) continue;
        try selected.append(gpa, row);
    }
    if (selected.items.len == 0) {
        if (exact and arch != null) return why.refuse(
            "{s} has no {t} form; use howl forms {s} for supported architectures",
            .{ query.?, arch.?, query.? },
        );
        return why.refuse("no forms match; use howl forms to browse", .{});
    }
    mem.sort(Row, selected.items, {}, struct {
        fn less(_: void, a: Row, b: Row) bool {
            const order = mem.order(u8, a.form, b.form);
            if (order != .eq) return order == .lt;
            if (a.arch != b.arch) return @backingInt(a.arch) < @backingInt(b.arch);
            return mem.order(u8, a.provider, b.provider) == .lt;
        }
    }.less);
    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    if (json) {
        try w.writeAll(try std.json.Stringify.valueAlloc(gpa, .{
            .source = if (local) "checkout" else "published",
            .forms = selected.items,
        }, .{ .whitespace = .indent_2 }));
        return w.writeByte('\n');
    }
    try w.print("Forms from {s}\n", .{if (local) "this checkout" else "the signed image catalog"});
    if (exact) {
        const row = selected.items[0];
        try w.print("\n{s}\n{s}\nSetup: {s}\nImages: {s}/{s}/index.html\n", .{
            row.form, row.summary, row.guide, base, row.form,
        });
        for (selected.items) |item| {
            if (local) {
                try w.print("  {t}: {s}\n", .{ item.arch, item.status });
                continue;
            }
            try w.print("  {s}/{t}: {s}\n", .{ item.provider, item.arch, item.status });
            if (item.latest) |latest| try w.print(
                "    Image {s}; release notes: {s}/{s}/release-notes.html\n",
                .{ latest.serial, base, latest.object },
            );
        }
        try w.print(
            "\nFrom a checkout:\n  howl pack --build --with {s} -h\n" ++
                "  howl run --build --with {s}\n  howl create {s} --build --with {s}\n" ++
                "  howl test --with {s}\n  howl test --with {s} --iterate\n\n" ++
                "Add the configuration flags shown by pack and the setup guide.\n" ++
                "Without --build, run/create download a published image for the provider and\n" ++
                "architecture; with --build they make one here, signed with your keys.\n",
            .{ row.form, row.form, row.form, row.form, row.form, row.form },
        );
        return;
    }
    try w.writeAll(
        "\nFORM                     ARCHITECTURES       PUBLISHED           DESCRIPTION\n",
    );
    var previous: []const u8 = "";
    for (selected.items) |row| {
        if (mem.eql(u8, previous, row.form)) continue;
        previous = row.form;
        var arches: Io.Writer.Allocating = .init(gpa);
        var images: Io.Writer.Allocating = .init(gpa);
        var seen: std.EnumSet(howl.Arch) = .empty;
        for (selected.items) |item| if (mem.eql(u8, item.form, row.form)) {
            if (!seen.contains(item.arch)) {
                seen.insert(item.arch);
                if (arches.written().len > 0) try arches.writer.writeByte(',');
                try arches.writer.print("{t}", .{item.arch});
            }
            if (item.latest != null) {
                if (images.written().len > 0) try images.writer.writeByte(',');
                try images.writer.print("{s}/{t}", .{ item.provider, item.arch });
            }
        };
        try w.print("{s: <24} {s: <19} {s: <19} {s}\n", .{
            row.form,
            arches.written(),
            if (local)
                "not queried"
            else if (images.written().len > 0)
                images.written()
            else
                "none",
            row.summary,
        });
    }
    try w.writeAll("\nUse howl forms NAME for setup, images and run/test commands.\n");
    if (local) try w.writeAll("Use --published to see which images run/create can download.\n");
}

test "catalog trust is a valid pinned RSA certificate" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const key = try catalogKey(arena.allocator());
    try std.testing.expect(key.modulus.len >= 256);
}

test "form descriptions preserve setup guide links" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const info = try description(
        arena.allocator(),
        "| [caddy](../forms/caddy/README.md) | A web server. |\n",
        "caddy",
    );
    try std.testing.expectEqualStrings("A web server.", info.summary);
    try std.testing.expectEqualStrings(repository ++ "forms/caddy/README.md", info.guide);
}
