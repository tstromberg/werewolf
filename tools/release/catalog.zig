//! catalog is the signed catalog of every form's protected targets, its
//! browsable pages, and the RSA signatures release records carry. No bucket
//! listing is public: the catalog is how a reader finds an image.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const images = @import("images.zig");
const form_lib = @import("form");

pub const format = "werewolf-form-catalog/1";
pub const published = "published";
pub const ungated = "passed; not published: no lifecycle gates for this target";
pub const no_runner = "passed; not published: no gate runner for this target";
/// settled states need no rebuild while their inputs hold; failures retry.
pub const settled = [_][]const u8{ published, ungated, no_runner };
pub const repository = "https://github.com/werewolf-linux/werewolf";

pub fn isSettled(status: []const u8) bool {
    return images.has(&settled, status);
}

/// public is the mirror release/protected/trust.json names, which every
/// published URL starts with.
pub fn public(s: *Sys) ![]const u8 {
    const trust = try sys.readJson(s, "release/protected/trust.json", 4096);
    return json.text(trust, "source");
}

/// namespace is FORM/PROVIDER/ARCH, for a provider the arch has images for.
pub fn namespace(
    s: *Sys,
    t: images.Images,
    name: []const u8,
    provider: []const u8,
    arch: []const u8,
) ![]const u8 {
    if (!images.isName(name) or !images.has(t.providers(arch), provider))
        return s.refuse("invalid form image target {s}/{s}/{s}", .{ name, provider, arch });
    return s.gpa.print("{s}/{s}/{s}", .{ try s.variantPath(name), provider, arch });
}

pub fn isHex(text: []const u8, n: usize) bool {
    if (text.len != n) return false;
    for (text) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return false;
    return true;
}

/// isSerial is [0-9]{8}T[0-9]{6}Z, the shape of a release serial.
pub fn isSerial(text: []const u8) bool {
    if (text.len != 16 or text[8] != 'T' or text[15] != 'Z') return false;
    for (text[0..8]) |c| if (!std.ascii.isDigit(c)) return false;
    for (text[9..15]) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// isPrintable is Python's str.isprintable for the text a catalog holds:
/// no control, format, separator (but space), private or noncharacter
/// code points. Python also refuses unassigned ones, which need tables.
pub fn isPrintable(text: []const u8) bool {
    const view = std.unicode.Utf8View.init(text) catch return false;
    var it = view.iterator();
    while (it.nextCodepoint()) |c| switch (c) {
        0...0x1f,
        0x7f...0xa0,
        0xad,
        0x600...0x605,
        0x61c,
        0x6dd,
        0x70f,
        0x890,
        0x891,
        0x8e2,
        0x1680,
        0x180e,
        0x2000...0x200f,
        0x2028...0x202f,
        0x205f...0x206f,
        0x3000,
        0xd800...0xf8ff,
        0xfdd0...0xfdef,
        0xfeff,
        0xfff9...0xfffb,
        0x110bd,
        0x110cd,
        0x13430...0x1343f,
        0x1bca0...0x1bca3,
        0x1d173...0x1d17a,
        0xe0001,
        0xe0020...0xe007f,
        0xf0000...0x10ffff,
        => return false,
        else => if (c & 0xfffe == 0xfffe) return false,
    };
    return true;
}

/// escape is Python's html.escape(text, quote=True).
pub fn escape(gpa: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (text) |c| switch (c) {
        '&' => try out.appendSlice(gpa, "&amp;"),
        '<' => try out.appendSlice(gpa, "&lt;"),
        '>' => try out.appendSlice(gpa, "&gt;"),
        '"' => try out.appendSlice(gpa, "&quot;"),
        '\'' => try out.appendSlice(gpa, "&#x27;"),
        else => try out.append(gpa, c),
    };
    return out.items;
}

/// publicKey is a certificate's public key, as openssl prints it.
pub fn publicKey(s: *Sys, certificate: []const u8) ![]const u8 {
    return sys.output(s, &.{ "openssl", "x509", "-in", certificate, "-pubkey", "-noout" });
}

/// sign is an RSA/SHA-256 signature of data by the PEM key at key.
pub fn sign(s: *Sys, data: []const u8, key: []const u8) ![]const u8 {
    const work = try sys.scratch(s, null, "ww-image-sign-");
    defer sys.remove(s, work);
    const file = try sys.join(s, &.{ work, "data" });
    try sys.write(s, file, data);
    return sys.output(s, &.{ "openssl", "dgst", "-sha256", "-sign", key, file });
}

/// verify refuses unless signature is the certificate's over data.
pub fn verify(s: *Sys, data: []const u8, signature: []const u8, certificate: []const u8) !void {
    if (data.len > 4 << 20 or (signature.len != 256 and signature.len != 384 and
        signature.len != 512))
        return s.refuse("invalid signed image metadata size", .{});
    const work = try sys.scratch(s, null, "ww-image-signature-");
    defer sys.remove(s, work);
    const paths = [_][]const u8{
        try sys.join(s, &.{ work, "data" }),
        try sys.join(s, &.{ work, "signature" }),
        try sys.join(s, &.{ work, "key" }),
    };
    try sys.write(s, paths[0], data);
    try sys.write(s, paths[1], signature);
    try sys.write(s, paths[2], try publicKey(s, certificate));
    const r = try sys.exec(
        s,
        &.{ "openssl", "dgst", "-sha256", "-verify", paths[2], "-signature", paths[1], paths[0] },
        .{ .capture = .both },
    );
    if (!r.ok()) return s.refuse("signature does not verify against {s}", .{certificate});
}

/// unhex reads Python's bytes.fromhex: hex digits in pairs, ASCII
/// whitespace between them ignored.
pub fn unhex(s: *Sys, text: []const u8) ![]const u8 {
    var digits: std.ArrayList(u8) = .empty;
    for (text) |c| if (!std.ascii.isWhitespace(c)) try digits.append(s.gpa, c);
    if (digits.items.len % 2 != 0) return s.refuse("invalid hex signature", .{});
    const out = try s.gpa.alloc(u8, digits.items.len / 2);
    return std.fmt.hexToBytes(out, digits.items) catch s.refuse("invalid hex signature", .{});
}

/// envelope is data and its signature in one signed record:
/// {"manifest": CANONICAL, "signature": HEX}.
pub fn envelope(s: *Sys, data: Json, key: []const u8) ![]const u8 {
    const raw = try json.encode(s.gpa, data);
    const signature = try sign(s, raw, key);
    return json.encode(s.gpa, try json.from(s.gpa, .{
        .manifest = raw,
        .signature = try sys.hexAlloc(s.gpa, signature),
    }));
}

/// opened is a signed envelope's manifest, verified.
pub fn opened(s: *Sys, raw: []const u8, certificate: []const u8) !Json {
    const head = try json.parse(s.gpa, raw);
    if (!json.hasKeys(
        head,
        &.{ "manifest", "signature" },
    )) return s.refuse("invalid signed envelope", .{});
    const manifest = try json.text(head, "manifest");
    try verify(s, manifest, try unhex(s, try json.text(head, "signature")), certificate);
    return json.parse(s.gpa, manifest);
}

const row_fields = [_][]const u8{
    "form",
    "provider",
    "arch",
    "status",
    "run",
    "summary",
    "guide",
    "inputs",
    "latest",
    "variants",
    "variant_descriptions",
};
const latest_fields = [_][]const u8{ "serial", "commit", "descriptor", "object", "size" };

/// validate refuses a catalog row with other members, unprintable text or
/// a latest release that is not the target's own.
pub fn validate(s: *Sys, t: images.Images, row: Json) !Json {
    const o = json.object(row) catch return s.refuse("invalid form catalog row", .{});
    for (o.keys()) |k| if (!images.has(
        &row_fields,
        k,
    )) return s.refuse("invalid form catalog row", .{});
    for (row_fields[0..4]) |k| if (o.get(k) == null) return s.refuse(
        "invalid form catalog row",
        .{},
    );
    const f = o.get("form").?;
    const p = o.get("provider").?;
    const a = o.get("arch").?;
    if (f != .string or p != .string or
        a != .string) return s.refuse("invalid form image target", .{});
    if (json.get(
        row,
        "variants",
    )) |v| if (v != .array) return s.refuse("catalog variants must be a list", .{});
    if (json.get(
        row,
        "variant_descriptions",
    )) |descriptions_| try validateVariantDescriptions(s, descriptions_);
    const saved = s.variants;
    defer s.variants = saved;
    s.variants = try sys.selection(s, row);
    const key = try namespace(s, t, f.string, p.string, a.string);
    for ([_][]const u8{ "status", "run", "summary", "guide" }) |k| if (o.get(k)) |v| {
        if (v != .string or
            !isPrintable(v.string)) return s.refuse("invalid form catalog text", .{});
    };
    if (o.get("inputs")) |v| if (v != .string or
        !isHex(v.string, 64)) return s.refuse("invalid form catalog inputs", .{});
    if (o.get("latest")) |latest| if (!validLatest(
        s,
        latest,
        key,
    )) return s.refuse("invalid published form image", .{});
    return row;
}

pub fn validateVariantDescriptions(s: *Sys, value: Json) !void {
    const descriptions_ = json.object(value) catch return s.refuse(
        "invalid variant descriptions",
        .{},
    );
    for (descriptions_.keys(), descriptions_.values()) |name, description_| {
        if (!form_lib.isName(name) or description_ != .string or
            !form_lib.isVariantDescription(description_.string))
            return s.refuse("invalid variant description for {s}", .{name});
    }
}

fn variantLabel(s: *Sys, row: Json, selection: []const u8) ![]const u8 {
    if (selection.len == 0) return "default";
    var labels: std.ArrayList([]const u8) = .empty;
    var names = mem.splitScalar(u8, selection, ',');
    while (names.next()) |name| {
        const text = if (mem.eql(u8, name, "ssh"))
            form_lib.ssh_variant_description
        else
            json.text(json.get(row, "variant_descriptions") orelse .null, name) catch "";
        try labels.append(
            s.gpa,
            if (text.len == 0) name else try s.gpa.print("{s}: {s}", .{ name, text }),
        );
    }
    return mem.join(s.gpa, "; ", labels.items);
}

fn validLatest(s: *Sys, latest: Json, key: []const u8) bool {
    const o = json.object(latest) catch return false;
    // index, the release's place in its channel, came with protocol v3.
    const n: usize = if (o.get("index") != null) 1 else 0;
    if (o.count() != latest_fields.len + n) return false;
    for (latest_fields) |k| if (o.get(k) == null) return false;
    if (o.get("index")) |i| if (i != .integer or i.integer < 1) return false;
    const serial = o.get("serial").?;
    const commit = o.get("commit").?;
    const descriptor = o.get("descriptor").?;
    const object = o.get("object").?;
    if (serial != .string or !isSerial(serial.string)) return false;
    if (commit != .string or !isHex(commit.string, 40)) return false;
    if (descriptor != .string or !isHex(descriptor.string, 64)) return false;
    const want = s.gpa.print("{s}/objects/{s}", .{ key, descriptor.string }) catch return false;
    if (object != .string or !mem.eql(u8, object.string, want)) return false;
    return o.get("size").? == .integer;
}

/// Index is a signed catalog's rows, in its order.
pub const Index = struct {
    rows: []const Json = &.{},
    variants: []const u8 = "",

    /// row is the target's row, or null.
    pub fn row(x: Index, name: []const u8, provider: []const u8, arch: []const u8) ?Json {
        for (x.rows) |r| {
            if (!sys.selectionMatches(r, x.variants)) continue;
            if (mem.eql(u8, json.text(r, "form") catch "", name) and
                mem.eql(u8, json.text(r, "provider") catch "", provider) and
                mem.eql(u8, json.text(r, "arch") catch "", arch)) return r;
        }
        return null;
    }

    /// latest is the target's last publication, or null.
    pub fn latest(x: Index, name: []const u8, provider: []const u8, arch: []const u8) ?Json {
        return json.get(x.row(name, provider, arch) orelse return null, "latest");
    }
};

/// openIndex is the rows of a signed index, each validated, none repeated.
pub fn openIndex(s: *Sys, t: images.Images, raw: []const u8, certificate: []const u8) !Index {
    const doc = try opened(s, raw, certificate);
    if (!json.hasKeys(doc, &.{ "format", "forms" }) or
        !mem.eql(u8, json.text(doc, "format") catch "", format))
        return s.refuse("invalid form catalog", .{});
    var rows: std.ArrayList(Json) = .empty;
    var index: Index = .{ .variants = s.variants };
    for (try json.items(try json.field(doc, "forms"))) |r| {
        const valid = try validate(s, t, r);
        index.variants = try sys.selection(s, valid);
        if (index.row(
            try json.text(r, "form"),
            try json.text(r, "provider"),
            try json.text(r, "arch"),
        ) != null)
            return s.refuse("duplicate form catalog row", .{});
        try rows.append(s.gpa, valid);
        index.rows = rows.items;
    }
    index.variants = s.variants;
    return index;
}

/// readIndex is the public index, or none before the first publication.
pub fn readIndex(s: *Sys, t: images.Images, certificate: []const u8) !Index {
    const url = try s.gpa.print("{s}/index.json", .{try public(s)});
    return switch (try sys.get(s, url, 4 << 20)) {
        .missing => .{},
        .body => |raw| openIndex(s, t, raw, certificate),
    };
}

/// descriptions are docs/forms-catalog.md's summaries and guides, by form.
pub fn descriptions(s: *Sys, path: []const u8) ![]const Description {
    const text = try std.Io.Dir.cwd().readFileAlloc(s.io, path, s.gpa, .limited(1 << 20));
    var out: std.ArrayList(Description) = .empty;
    var it = mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const d = describe(mem.trimEnd(u8, line, "\r")) orelse continue;
        const guide = try s.gpa.print("{s}/blob/main/{s}", .{ repository, d.guide });
        for (out.items) |*seen| {
            if (mem.eql(u8, seen.form, d.form)) {
                seen.* = .{ .form = d.form, .summary = d.summary, .guide = guide };
                break;
            }
        } else try out.append(s.gpa, .{ .form = d.form, .summary = d.summary, .guide = guide });
    }
    return out.items;
}

pub const Description = struct { form: []const u8, summary: []const u8, guide: []const u8 };

pub fn description(all: []const Description, name: []const u8) ?Description {
    for (all) |d| if (mem.eql(u8, d.form, name)) return d;
    return null;
}

/// describe reads a table line `| [NAME](../GUIDE) | SUMMARY |`.
fn describe(line: []const u8) ?Description {
    if (!mem.startsWith(u8, line, "| [")) return null;
    const close = mem.findScalarPos(u8, line, 3, ']') orelse return null;
    const name = line[3..close];
    if (name.len == 0 or !std.ascii.isLower(name[0])) return null;
    for (name) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return null;
    const rest = line[close + 1 ..];
    if (!mem.startsWith(u8, rest, "(../")) return null;
    const end = mem.findScalar(u8, rest, ')') orelse return null;
    const guide = rest[4..end];
    const tail = rest[end + 1 ..];
    if (!mem.startsWith(u8, tail, " | ") or tail.len < 5 or
        !mem.endsWith(u8, tail, " |")) return null;
    return .{ .form = name, .summary = tail[3 .. tail.len - 2], .guide = guide };
}

/// mebibytes is str(round(size / 2**20, 1)), rounding half to even.
pub fn mebibytes(gpa: Allocator, size: i64) ![]const u8 {
    const magnitude: u128 = @abs(size);
    const q = magnitude * 10;
    const d: u128 = 1 << 20;
    var tenths = q / d;
    const rem = q % d;
    if (rem * 2 > d or (rem * 2 == d and tenths % 2 == 1)) tenths += 1;
    return gpa.print("{s}{d}.{d}", .{ if (size < 0) "-" else "", tenths / 10, tenths % 10 });
}

const style =
    "<style>body{font:16px system-ui;max-width:80rem;margin:2rem auto;padding:0 1rem}" ++
    "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.6rem;border-bottom" ++
    ":1px solid #bbb}";

/// page is the browsable catalog of rows and legacy rows.
pub fn page(
    s: *Sys,
    t: images.Images,
    rows: []const Json,
    title: []const u8,
    legacy_rows: []const Json,
) ![]const u8 {
    const gpa = s.gpa;
    const base_url = try public(s);
    const title_html = try escape(gpa, title);
    var body: std.ArrayList([]const u8) = .empty;
    try body.appendSlice(gpa, &.{
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        try gpa.print("<title>{s}</title>", .{title_html}),
        style ++ "a{color:#1265ac}small{display:block}code{overflow-wrap:anywhere}</style>",
        try gpa.print("<h1>{s}</h1>", .{title_html}),
        "<p>Secure-boot images are built twice with every protection: signed UEFI boot, IPE, a " ++
            "verified root " ++
            "and TPM-anchored A/B updates. A target is published only when its exact bundle has " ++
            "passed " ++
            "all twelve lifecycle gates; a failed build or gate keeps the previous release.</p>",
        "<p><code>howl run --with FORM</code> downloads, verifies and enrolls a published " ++
            "image. " ++
            "Its qcow2 boots only through that enrollment. " ++
            "<a href=\"https://github.com/werewolf-linux/werewolf/blob/main/docs/form-images.md" ++
            "\">" ++
            "How images are built and verified</a>.</p>",
        try gpa.print("<p><a href=\"{0s}/index.html\">All forms</a> · " ++
            "<a href=\"{0s}/index.json\">Signed secure catalog</a> · " ++
            "<a href=\"{0s}/boot-profiles.json\">Signed boot profile catalog</a></p>", .{base_url}),
        "<h2>Secure boot</h2><table><thead><tr><th>Form</th><th>Target</th><th>Latest published " ++
            "image</th>" ++
            "<th>Latest attempt</th></tr></thead><tbody>",
    });
    for (rows) |row| {
        _ = try validate(s, t, row);
        const name = try json.text(row, "form");
        const selection = try sys.selection(s, row);
        const guide_text = json.text(row, "guide") catch "";
        const guide = if (guide_text.len > 0)
            guide_text
        else
            try gpa.print("{s}/tree/main/forms/{s}", .{ repository, name });
        var links: []const u8 = "Not published";
        if (json.get(row, "latest")) |latest| {
            const base = try gpa.print("{s}/{s}", .{ base_url, try json.text(latest, "object") });
            links = try gpa.print("<a href=\"{0s}/disk.qcow2\">qcow2</a> · " ++
                "<a href=\"{0s}/release-notes.html\">release notes</a> · " ++
                "<a href=\"{0s}/downloads.json\">manifest</a> · " ++
                "<a href=\"{0s}/downloads.json.sig\">signature</a> · " ++
                "<a href=\"{0s}/gates.json\">gates</a> · " ++
                "<a href=\"{0s}/tests.json\">tests</a>" ++
                "<small>{1s} · {2s} MiB · {3d} hours old</small>", .{
                base,
                try json.text(latest, "serial"),
                try mebibytes(gpa, try json.int(latest, "size")),
                @divFloor(@max(0, s.now() - (sys.serialTime(try json.text(latest, "serial")) orelse
                    return s.refuse("invalid published serial", .{}))), 3600),
            });
        }
        var status = try escape(gpa, try json.text(row, "status"));
        const run_url = json.text(row, "run") catch "";
        if (run_url.len > 0) status = try gpa.print(
            "<a href=\"{s}\">{s}</a>",
            .{ try escape(gpa, run_url), status },
        );
        try body.append(gpa, try gpa.print("<tr><td><a href=\"{s}/{s}/index.html\">{s}</a>" ++
            "<small>{s}</small>" ++
            "<small><a href=\"{s}\">Setup guide</a></small></td><td>" ++
            "{s}/{s}<small>{s}</small></td><td>{s}</td><td>{s}</td></tr>", .{
            base_url,
            name,
            name,
            try escape(gpa, json.text(row, "summary") catch ""),
            try escape(gpa, guide),
            try json.text(row, "provider"),
            try json.text(row, "arch"),
            try escape(gpa, try variantLabel(s, row, selection)),
            links,
            status,
        }));
    }
    try body.appendSlice(gpa, &.{
        "</tbody></table>",
        "<h2>Legacy boot</h2>",
        "<p>These images boot without Secure Boot, TPM enrollment or IPE enforcement. " ++
            "They retain sandboxing and verified roots. Download signatures authenticate the " ++
            "files; " ++
            "they do not provide firmware authentication or TPM rollback protection.</p>",
    });
    for (legacy_rows) |row| {
        const base = try gpa.print("{s}/{s}", .{ base_url, try json.text(row, "object") });
        const files = try json.field(row, "files");
        const disk = try json.text(try json.field(files, "disk.qcow2"), "asset");
        const name = try json.text(row, "form");
        const arch = try json.text(row, "arch");
        const manifest = try gpa.print("{s}-{s}-legacy-boot-downloads.json", .{ name, arch });
        var changes: []const u8 = "";
        if (json.get(files, "release-notes.html")) |notes| changes = try gpa.print(
            " · <a href=\"{s}\">Package changes</a>",
            .{try escape(gpa, try gpa.print("{s}/{s}", .{ base, try json.text(notes, "asset") }))},
        );
        try body.append(gpa, try gpa.print("<p>{s}: " ++
            "<a href=\"{s}\">legacy-boot qcow2</a> · " ++
            "<a href=\"{s}\">manifest</a> · " ++
            "<a href=\"{s}\">signature</a> · {s}{s}</p>", .{
            try escape(gpa, try gpa.print("{s} / {s}", .{ name, arch })),
            try escape(gpa, try gpa.print("{s}/{s}", .{ base, disk })),
            try escape(gpa, try gpa.print("{s}/{s}", .{ base, manifest })),
            try escape(gpa, try gpa.print("{s}/{s}.sig", .{ base, manifest })),
            try escape(gpa, try json.text(row, "serial")),
            changes,
        }));
    }
    try body.append(gpa, "</html>");
    return gpa.print("{s}\n", .{try mem.join(gpa, "\n", body.items)});
}

const testing = std.testing;
const fixture = @import("fixture.zig");

test "signed catalog keeps base and SSH selections as separate identities" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const key = try fixture.keys(&f, "image");
    const table = try images.load(s);
    const base = try json.from(
        s.gpa,
        .{ .form = "playground", .provider = "qemu", .arch = "x86_64", .status = ungated },
    );
    const ssh = try json.from(
        s.gpa,
        .{
            .form = "playground",
            .variants = &[_][]const u8{"ssh"},
            .provider = "qemu",
            .arch = "x86_64",
            .status = ungated,
        },
    );
    const raw = try envelope(
        s,
        try json.from(s.gpa, .{ .format = format, .forms = &[_]Json{ base, ssh } }),
        key.key,
    );
    const plain = try openIndex(s, table, raw, key.crt);
    try testing.expectEqual(@as(usize, 2), plain.rows.len);
    try testing.expect(json.eql(base, plain.row("playground", "qemu", "x86_64").?));
    s.variants = "ssh";
    const selected = try openIndex(s, table, raw, key.crt);
    try testing.expect(json.eql(ssh, selected.row("playground", "qemu", "x86_64").?));
    try testing.expectEqualStrings(
        "playground/variants/ssh/qemu/x86_64",
        try namespace(s, table, "playground", "qemu", "x86_64"),
    );
    const duplicate = try envelope(
        s,
        try json.from(s.gpa, .{ .format = format, .forms = &[_]Json{ ssh, ssh } }),
        key.key,
    );
    try testing.expectError(error.Refused, openIndex(s, table, duplicate, key.crt));
}

test "the catalog's signature, rows and published objects are checked" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const gpa = f.gpa();
    const k = try fixture.keys(&f, "image");
    const t = try images.load(s);
    const row = try json.from(
        gpa,
        .{
            .form = "caddy",
            .provider = "qemu",
            .arch = "x86_64",
            .status = ungated,
            .inputs = fixture.rep('a', 64),
            .variant_descriptions = .{ .ssh = "SSH access" },
        },
    );
    const raw = try envelope(
        s,
        try json.from(gpa, .{ .format = format, .forms = &[_]Json{row} }),
        k.key,
    );
    const index = try openIndex(s, t, raw, k.crt);
    try testing.expectEqual(@as(usize, 1), index.rows.len);
    try testing.expect(json.eql(row, index.row("caddy", "qemu", "x86_64").?));
    var changed = try json.parse(gpa, raw);
    const replaced = try mem.replaceOwned(
        u8,
        gpa,
        changed.object.get("manifest").?.string,
        "caddy",
        "nginx",
    );
    try changed.object.put(gpa, "manifest", .{ .string = replaced });
    try testing.expectError(error.Refused, openIndex(s, t, try json.encode(gpa, changed), k.crt));
    try testing.expectStringStartsWith(s.why.text, "signature does not verify");

    const serial_now = sys.serial(s.now());
    const latest = try json.from(
        gpa,
        .{
            .serial = &serial_now,
            .commit = fixture.rep('b', 40),
            .descriptor = fixture.rep('d', 64),
            .size = 1,
            .object = "nginx/qemu/x86_64/objects/" ++ fixture.rep('d', 64),
        },
    );
    var good = try json.parse(gpa, try json.encode(gpa, latest));
    try good.object.put(gpa, "index", .{ .integer = 2 });
    try good.object.put(
        gpa,
        "object",
        .{ .string = "caddy/qemu/x86_64/objects/" ++ fixture.rep('d', 64) },
    );
    var published_row = try json.parse(gpa, try json.encode(gpa, row));
    try published_row.object.put(gpa, "status", .{ .string = published });
    try published_row.object.put(gpa, "latest", good);
    try testing.expect(json.eql(published_row, try validate(s, t, published_row)));

    const variants = [_][]const u8{
        "{\"provider\":\"lima\"}",
        "{\"status\":\"\\u001b[2J\"}",
        "{\"extra\":1}",
        "{\"variant_descriptions\":[]}",
        "{\"variant_descriptions\":{\"ssh\":\"bad\\nline\"}}",
        "{\"variant_descriptions\":{\"bad,name\":\"Description\"}}",
    };
    var bad: std.ArrayList([]const Json) = .empty;
    try bad.append(gpa, &.{ row, row });
    for (variants) |v| {
        var r = try json.parse(gpa, try json.encode(gpa, row));
        var it = (try json.parse(gpa, v)).object.iterator();
        while (it.next()) |e| try r.object.put(gpa, e.key_ptr.*, e.value_ptr.*);
        try bad.append(gpa, try gpa.dupe(Json, &.{r}));
    }
    var foreign_latest = try json.parse(gpa, try json.encode(gpa, row));
    try foreign_latest.object.put(gpa, "latest", latest);
    try bad.append(gpa, try gpa.dupe(Json, &.{foreign_latest}));
    for ([_][]const u8{ "0", "-1", "\"2\"", "true", "null" }) |index_text| {
        var r = try json.parse(gpa, try json.encode(gpa, published_row));
        var l = try json.parse(gpa, try json.encode(gpa, good));
        try l.object.put(gpa, "index", try json.parse(gpa, index_text));
        try r.object.put(gpa, "latest", l);
        try bad.append(gpa, try gpa.dupe(Json, &.{r}));
    }
    for (bad.items) |rows| {
        const signed_rows = try envelope(
            s,
            try json.from(gpa, .{ .format = format, .forms = rows }),
            k.key,
        );
        try testing.expectError(error.Refused, openIndex(s, t, signed_rows, k.crt));
    }
}

test "the browsable catalog escapes text and links each form" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const row = try json.from(
        f.gpa(),
        .{
            .form = "caddy",
            .provider = "qemu",
            .arch = "x86_64",
            .status = "tests failed <script>",
            .summary = "A <server>",
        },
    );
    const html = try page(s, try images.load(s), &.{row}, "Werewolf images", &.{});
    try testing.expect(mem.find(u8, html, "tests failed &lt;script&gt;") != null);
    try testing.expect(mem.find(u8, html, "A &lt;server&gt;") != null);
    try testing.expect(mem.find(u8, html, "<script>") == null);
    try testing.expect(mem.find(u8, html, "caddy/index.html") != null);
}

test "variant descriptions are rendered and escaped in the catalog" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const row = try json.from(s.gpa, .{
        .form = "postgresql",
        .provider = "qemu",
        .arch = "x86_64",
        .status = ungated,
        .variants = &[_][]const u8{ "ssh", "vector" },
        .variant_descriptions = .{ .vector = "Vector search <pgvector>" },
    });
    const html = try page(s, try images.load(s), &.{row}, "Images", &.{});
    try testing.expect(mem.find(u8, html, "ssh: SSH access") != null);
    try testing.expect(mem.find(u8, html, "vector: Vector search &lt;pgvector&gt;") != null);
    try testing.expect(mem.find(u8, html, "<pgvector>") == null);
}

test "descriptions use the forms catalog's guides" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const caddy = description(try descriptions(&f.s, "docs/forms-catalog.md"), "caddy").?;
    try testing.expect(mem.find(u8, caddy.summary, "web server") != null);
    try testing.expectStringEndsWith(caddy.guide, "/forms/caddy/README.md");
    try testing.expect(describe("| [x](../y) |  |") != null);
    try testing.expect(describe("| [X](../y) | z |") == null);
    try testing.expect(describe("| [x](../y) | z") == null);
}

test "sizes round half to even, as Python's round does" {
    const cases = [_]struct { i64, []const u8 }{
        .{ 262144, "0.2" },  .{ 786432, "0.8" },      .{ 123, "0.0" },           .{ -1, "-0.0" },
        .{ 1 << 20, "1.0" }, .{ 512 << 20, "512.0" }, .{ 1234567890, "1177.4" },
    };
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for (cases) |c| try testing.expectEqualStrings(c[1], try mebibytes(arena.allocator(), c[0]));
}

test "printable text is Python's for what catalogs hold" {
    try testing.expect(isPrintable("tests failed — retry"));
    try testing.expect(isPrintable(""));
    for ([_][]const u8{
        "\x1b[2J",
        "a\nb",
        "\xc2\xa0",
        "\xe2\x80\x8b",
        "\xef\xbb\xbf",
        "\x7f",
        "\xff",
    }) |bad|
        try testing.expect(!isPrintable(bad));
}
