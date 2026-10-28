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
    variants: []const []const u8 = &.{},
    available_variants: []const []const u8 = &.{},
    variant_descriptions: forms.VariantDescriptions = .{},
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

/// checkout returns a row per form and architecture under root's forms/,
/// described from root's docs/forms-catalog.md, else howl's copy of it.
fn checkout(io: Io, gpa: Allocator, root: Io.Dir, why: *howl.Why) ![]Row {
    var dir = root.openDir(io, "forms", .{ .iterate = true }) catch
        return why.refuse("no ./forms; use --build from a werewolf checkout root", .{});
    defer dir.close(io);
    const text = root.readFileAlloc(io, "docs/forms-catalog.md", gpa, .limited(1 << 20)) catch
        files.forms_catalog;
    var rows: std.ArrayList(Row) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory or !forms.isName(entry.name)) continue;
        dir.access(io, try gpa.print("{s}/form.yaml", .{entry.name}), .{}) catch continue;
        const name = try gpa.dupe(u8, entry.name);
        var failure: forms.Failure = .{};
        const chain = forms.chain(io, gpa, root, name, &failure) catch |err| switch (err) {
            error.Form => return why.refuse("{s}", .{failure.text}),
            else => return err,
        };
        var arches: []const []const u8 = &.{ "aarch64", "x86_64" };
        for (chain) |form| if (form.spec.get("archs") != null) {
            arches = try form.items(gpa, "archs");
        };
        var available: std.ArrayList([]const u8) = .empty;
        try available.append(gpa, "ssh");
        if (chain[chain.len - 1].spec.get("variants")) |definitions| {
            for (definitions.map) |definition| try available.append(gpa, definition.key);
        }
        var supported = true;
        for (howl.variants) |variant| {
            const known = for (available.items) |v| {
                if (mem.eql(
                    u8,
                    v,
                    variant,
                )) break true;
            } else false;
            if (!known) supported = false;
        }
        if (!supported) continue;
        const details = try description(gpa, text, name);
        for (arches) |arch| try rows.append(gpa, .{
            .form = name,
            .variants = howl.variants,
            .available_variants = available.items,
            .variant_descriptions = try forms.variantDescriptions(gpa, chain[chain.len - 1]),
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
    return verified(gpa, fetched.stdout);
}

/// verified returns the rows of a catalog werewolf's image key signed.
fn verified(gpa: Allocator, text: []const u8) ![]Row {
    const head = try std.json.parseFromSliceLeaky(struct {
        manifest: []const u8,
        signature: []const u8,
    }, gpa, text, .{});
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

/// Query is howl forms' line: a form's name or a search, an architecture,
/// the source and the format.
const Query = struct {
    word: ?[]const u8 = null,
    arch: ?howl.Arch = null,
    local: bool = false,
    remote: bool = false,
    json: bool = false,
    help: bool = false,
};

fn parse(args: []const []const u8, why: *howl.Why) !Query {
    var q: Query = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            return .{ .help = true };
        } else if (mem.eql(u8, arg, "--build")) {
            q.local = true;
        } else if (mem.eql(u8, arg, "--published")) {
            q.remote = true;
        } else if (mem.eql(u8, arg, "--json")) {
            q.json = true;
        } else if (arg.len > 0 and arg[0] == '-') {
            const flag, const value = try howl.flagValue(args, &i, why);
            if (!mem.eql(u8, flag, "--arch")) return why.refuse("{s}\n{s}", .{ flag, syntax });
            if (q.arch != null) return why.refuse("--arch given twice", .{});
            q.arch = howl.archName(value) orelse return why.refuse(howl.arch_refusal, .{value});
        } else {
            if (q.word != null) return why.refuse(
                "give one form name or search term\n{s}",
                .{syntax},
            );
            q.word = arg;
        }
    }
    if (q.local and q.remote) return why.refuse("--build and --published conflict", .{});
    return q;
}

pub fn command(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    const q = try parse(args, why);
    if (q.help) {
        howl.say(io, "{s}", .{syntax});
        return;
    }
    const have_checkout = if (Io.Dir.cwd().access(io, "forms", .{})) |_| true else |_| false;
    const local = q.local or (!q.remote and have_checkout);
    const base = try mirror(gpa);
    const all = if (local)
        try checkout(io, gpa, Io.Dir.cwd(), why)
    else
        try published(io, gpa, base, why);
    const found = try select(gpa, all, q, local, why);
    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    if (q.json) {
        try w.writeAll(try std.json.Stringify.valueAlloc(gpa, .{
            .source = if (local) "checkout" else "published",
            .forms = found.rows,
        }, .{ .whitespace = .indent_2 }));
        return w.writeByte('\n');
    }
    try show(w, gpa, found, local, base);
}

/// Found is what a query selected, sorted, and whether it named one form.
const Found = struct { rows: []Row, exact: bool };

fn matches(row: Row, word: []const u8) bool {
    if (std.ascii.findIgnoreCase(row.form, word) != null or
        std.ascii.findIgnoreCase(row.summary, word) != null) return true;
    for (row.available_variants) |name| if (std.ascii.findIgnoreCase(
        name,
        word,
    ) != null) return true;
    for (row.variant_descriptions.map.keys(), row.variant_descriptions.map.values()) |name, text| {
        if (std.ascii.findIgnoreCase(name, word) != null or
            std.ascii.findIgnoreCase(text, word) != null) return true;
    }
    return false;
}

/// select returns all's rows q asks for. A word naming a form selects it;
/// any other word searches names and descriptions. It refuses a catalog row
/// that could drive a terminal or point anywhere but werewolf's repository.
fn select(gpa: Allocator, all: []const Row, q: Query, local: bool, why: *howl.Why) !Found {
    var selected: std.ArrayList(Row) = .empty;
    const exact = if (q.word) |word| for (all) |row| {
        if (mem.eql(u8, row.form, word)) break true;
    } else false else false;
    for (all) |row| {
        if (!forms.isName(row.form) or !printable(row.summary) or !printable(row.status) or
            !printable(row.guide) or
            (row.guide.len > 0 and !mem.startsWith(u8, row.guide, repository)) or
            (!local and !mem.eql(u8, row.provider, "qemu") and !mem.eql(u8, row.provider, "lima")))
            return error.BadCatalogEntry;
        if (row.latest) |latest| if (!printable(latest.object) or !printable(latest.serial))
            return error.BadCatalogEntry;
        const descriptions = row.variant_descriptions.map;
        for (descriptions.keys(), descriptions.values()) |name, text| {
            if (!forms.isName(name) or
                !forms.isVariantDescription(text)) return error.BadCatalogEntry;
        }
        if (row.variants.len > 0 and
            !@import("prebuilt").variantSelection(try mem.join(
                gpa,
                ",",
                row.variants,
            ))) return error.BadCatalogEntry;
        if (howl.variants.len > 0) {
            if (row.variants.len != howl.variants.len) continue;
            var same = true;
            for (row.variants, howl.variants) |a, b| if (!mem.eql(
                u8,
                a,
                b,
            )) {
                same = false;
                break;
            };
            if (!same) continue;
        }
        if (q.arch != null and q.arch.? != row.arch) continue;
        if (q.word) |word| {
            if (exact) {
                if (!mem.eql(u8, row.form, word)) continue;
            } else if (!matches(row, word)) continue;
        }
        if (!exact and mem.eql(u8, row.status, "unsupported architecture")) continue;
        try selected.append(gpa, row);
    }
    if (selected.items.len == 0) {
        if (exact and q.arch != null) return why.refuse(
            "{s} has no {t} form; use howl forms {s} for supported architectures",
            .{ q.word.?, q.arch.?, q.word.? },
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
    return .{ .rows = selected.items, .exact = exact };
}

/// show writes found as a table, or one form's setup and commands.
fn show(w: *Io.Writer, gpa: Allocator, found: Found, local: bool, base: []const u8) !void {
    try w.print("Forms from {s}\n", .{if (local) "this checkout" else "the signed image catalog"});
    if (found.exact) {
        const row = found.rows[0];
        try w.print("\n{s}\n{s}\nSetup: {s}\nImages: {s}/{s}/index.html\n", .{
            row.form, row.summary, row.guide, base, row.form,
        });
        try showVariants(w, gpa, found.rows, "");
        for (found.rows) |item| {
            if (item.variants.len > 0) try w.print(
                "  variants: {s}\n",
                .{try mem.join(gpa, ",", item.variants)},
            );
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
    for (found.rows) |row| {
        if (mem.eql(u8, previous, row.form)) continue;
        previous = row.form;
        var arches: Io.Writer.Allocating = .init(gpa);
        var images: Io.Writer.Allocating = .init(gpa);
        var seen: std.EnumSet(howl.Arch) = .empty;
        for (found.rows) |item| if (mem.eql(u8, item.form, row.form)) {
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
        if (local) {
            try showVariants(w, gpa, &.{row}, "  ");
        } else {
            var combinations: std.ArrayList([]const u8) = .empty;
            for (found.rows) |item| if (mem.eql(u8, item.form, row.form) and item.latest != null) {
                const names = if (item.variants.len == 0)
                    "default"
                else
                    try mem.join(gpa, ",", item.variants);
                var seen_combination = false;
                for (combinations.items) |previous_names| if (mem.eql(u8, names, previous_names)) {
                    seen_combination = true;
                    break;
                };
                if (!seen_combination) try combinations.append(gpa, names);
            };
            if (combinations.items.len > 0) try w.print(
                "  published variants: {s}\n",
                .{try mem.join(gpa, "; ", combinations.items)},
            );
            var mine: std.ArrayList(Row) = .empty;
            for (found.rows) |item| if (mem.eql(
                u8,
                item.form,
                row.form,
            )) try mine.append(gpa, item);
            try showVariants(w, gpa, mine.items, "  ");
        }
    }
    try w.writeAll("\nUse howl forms NAME for setup, images and run/test commands.\n");
    if (local) try w.writeAll("Use --published to see which images run/create can download.\n");
}

fn showVariants(w: *Io.Writer, gpa: Allocator, rows: []const Row, indent: []const u8) !void {
    var names: std.ArrayList([]const u8) = .empty;
    try names.append(gpa, "ssh");
    for (rows) |row| {
        try names.appendSlice(gpa, row.available_variants);
        try names.appendSlice(gpa, row.variants);
        try names.appendSlice(gpa, row.variant_descriptions.map.keys());
    }
    var failure: forms.Failure = .{};
    const canonical = try forms.variantNames(gpa, names.items, &failure);
    try w.print("{s}Variants:\n", .{indent});
    for (canonical) |name| {
        const text = if (mem.eql(u8, name, "ssh"))
            forms.ssh_variant_description
        else for (rows) |row| {
            if (row.variant_descriptions.map.get(name)) |description_| break description_;
        } else "";
        try w.print("{s}  {s: <12} {s}\n", .{ indent, name, text });
    }
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

const testing = std.testing;

test "howl forms takes one word, an architecture and one source" {
    var why: howl.Why = .{};
    const q = try parse(&.{ "web", "--arch=arm64", "--build", "--json" }, &why);
    try testing.expectEqualStrings("web", q.word.?);
    try testing.expect(q.arch.? == .aarch64 and q.local and q.json and !q.remote);
    try testing.expect((try parse(&.{ "--help", "--unknown" }, &why)).help);
    for ([_][]const []const u8{
        &.{ "--published", "--build" },
        &.{"--unknown"},
        &.{ "one", "two" },
        &.{ "--arch", "riscv64" },
        &.{ "--arch", "arm64", "--arch", "x86_64" },
    }) |args| try testing.expectError(error.Refused, parse(args, &why));
}

test "a checkout's forms, by name, search and architecture" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][2][]const u8{
        .{ "minimal", "archs: [aarch64, x86_64]\n" },
        .{ "web", "base: minimal\nvariants:\n  vector:\n" ++
            "    description: Vector search with pgvector\n    packages: [pgvector]\n" },
        .{ "intel-only", "base: minimal\narchs: [x86_64]\n" },
    }) |form| {
        try tmp.dir.createDirPath(io, try gpa.print("forms/{s}", .{form[0]}));
        try tmp.dir.writeFile(io, .{
            .sub_path = try gpa.print("forms/{s}/form.yaml", .{form[0]}),
            .data = form[1],
        });
    }
    try tmp.dir.createDirPath(io, "docs");
    try tmp.dir.writeFile(io, .{
        .sub_path = "docs/forms-catalog.md",
        .data = "| [web](../forms/web/README.md) | A searchable web server. |\n",
    });
    var why: howl.Why = .{};
    const rows = try checkout(io, gpa, tmp.dir, &why);
    var names: Io.Writer.Allocating = .init(gpa);
    for ([_]struct { Query, []const u8 }{
        .{ .{}, "intel-only/x86_64 minimal/aarch64 minimal/x86_64 web/aarch64 web/x86_64 " },
        .{ .{ .arch = .aarch64 }, "minimal/aarch64 web/aarch64 " },
        .{ .{ .word = "searchable" }, "web/aarch64 web/x86_64 " },
        .{ .{ .word = "pgvector" }, "web/aarch64 web/x86_64 " },
        .{ .{ .word = "web" }, "web/aarch64 web/x86_64 " },
    }) |case| {
        names.clearRetainingCapacity();
        for ((try select(gpa, rows, case[0], true, &why)).rows) |row|
            try names.writer.print("{s}/{t} ", .{ row.form, row.arch });
        try testing.expectEqualStrings(case[1], names.written());
    }
    try testing.expectError(
        error.Refused,
        select(gpa, rows, .{ .word = "intel-only", .arch = .aarch64 }, true, &why),
    );
    try testing.expect(mem.find(u8, why.text, "has no aarch64 form") != null);
    try testing.expectError(error.Refused, select(gpa, rows, .{ .word = "missing" }, true, &why));
    var text: Io.Writer.Allocating = .init(gpa);
    try show(&text.writer, gpa, try select(gpa, rows, .{ .word = "web" }, true, &why), true, "");
    for ([_][]const u8{
        "howl run --build --with web\n",
        "howl test --with web\n",
        "howl pack --build --with web -h\n",
        "Setup: " ++ repository ++ "forms/web/README.md\n",
        "ssh          SSH access\n",
        "vector       Vector search with pgvector\n",
    }) |line| try testing.expect(mem.find(u8, text.written(), line) != null);
    try tmp.dir.createDirPath(io, "outside");
    var outside = try tmp.dir.openDir(io, "outside", .{});
    defer outside.close(io);
    try testing.expectError(error.Refused, checkout(io, gpa, outside, &why));
    try testing.expect(mem.find(u8, why.text, "no ./forms") != null);
}

test "published descriptions survive JSON and older rows still explain SSH" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const described = try std.json.parseFromSliceLeaky(Row, gpa,
        \\{"form":"postgresql","provider":"qemu","arch":"aarch64","status":"published",
        \\ "variants":["ssh","vector"],"variant_descriptions":{"ssh":"SSH access","vector":"Vector search with pgvector"}}
    , .{});
    var why: howl.Why = .{};
    var text: Io.Writer.Allocating = .init(gpa);
    try show(&text.writer, gpa, try select(
        gpa,
        &.{described},
        .{ .word = "postgresql" },
        false,
        &why,
    ), false, "https://example.test");
    try testing.expect(mem.find(u8, text.written(), "ssh          SSH access") != null);
    try testing.expect(mem.find(
        u8,
        text.written(),
        "vector       Vector search with pgvector",
    ) != null);
    const encoded = try std.json.Stringify.valueAlloc(gpa, described, .{});
    const decoded = try std.json.parseFromSliceLeaky(Row, gpa, encoded, .{});
    try testing.expectEqualStrings(
        "Vector search with pgvector",
        decoded.variant_descriptions.map.get("vector").?,
    );
    const old = try std.json.parseFromSliceLeaky(Row, gpa, "{\"form\":\"postgresql\",\"provider" ++
        "\":\"qemu\",\"arch\":\"aarch64\",\"status\":\"publis" ++
        "hed\"}", .{});
    text.clearRetainingCapacity();
    try showVariants(&text.writer, gpa, &.{old}, "");
    try testing.expect(mem.find(u8, text.written(), "ssh          SSH access") != null);
}

test "a catalog must carry werewolf's signature" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try testing.expectError(
        error.BadCatalogSignature,
        verified(gpa, "{\"manifest\":\"{}\",\"signature\":\"00\"}"),
    );
    const zeros: [512]u8 = @splat('0');
    try testing.expectError(
        error.BadSignature,
        verified(gpa, "{\"manifest\":\"{}\",\"signature\":\"" ++ zeros ++ "\"}"),
    );
}
