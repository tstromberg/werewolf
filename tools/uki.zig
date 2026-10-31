//! uki assembles a Unified Kernel Image on the build host: sections named
//! on the command line (.linux, .initrd, .cmdline, ...) are appended to a
//! stub (systemd's linuxaa64.efi.stub), making one PE the firmware can
//! load, and a signature can cover whole. See docs/design/implemented/verified-boot.md.
//!
//!     uki STUB OUT NAME=FILE...

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 4) {
        std.log.err("usage: uki STUB OUT NAME=FILE...", .{});
        std.process.exit(2);
    }
    const stub = try Dir.cwd().readFileAlloc(io, args[1], gpa, .limited(1 << 20));
    var names: std.ArrayList([]const u8) = .empty;
    var datas: std.ArrayList([]const u8) = .empty;
    for (args[3..]) |a| {
        const eq = std.mem.findScalar(u8, a, '=') orelse {
            std.log.err("usage: uki STUB OUT NAME=FILE...", .{});
            std.process.exit(2);
        };
        try names.append(gpa, a[0..eq]);
        try datas.append(
            gpa,
            try Dir.cwd().readFileAlloc(io, a[eq + 1 ..], gpa, .limited(512 << 20)),
        );
    }
    const out = try assemble(gpa, stub, names.items, datas.items);
    try Dir.cwd().writeFile(io, .{ .sub_path = args[2], .data = out });
}

/// Pe points at a parsed PE32+ image: where the headers are, and the
/// alignment new sections must keep.
const Pe = struct {
    coff: usize,
    opt: usize,
    optional: usize,
    sections: usize,
    nsections: usize,
    machine: u16,
    file_align: usize,
    sect_align: usize,
    size_of_headers: usize,
    first_raw: usize,
    last_virt_end: usize,
    sec_off: usize,
    sec_size: usize,
};

pub const Error = error{
    NotPE,
    UnsupportedMachine,
    NotPE32Plus,
    NoSections,
    BadSection,
    DuplicateSection,
    NameTooLong,
    NoHeaderRoom,
    ImageTooLarge,
};

pub fn section(image: []const u8, wanted: []const u8) Error!?[]const u8 {
    const p = try parse(image);
    var found: ?[]const u8 = null;
    for (0..p.nsections) |i| {
        const h = p.sections + i * 40;
        const name = std.mem.trimEnd(u8, image[h..][0..8], "\x00");
        if (!std.mem.eql(u8, name, wanted)) continue;
        if (found != null) return Error.DuplicateSection;
        const size = std.mem.readInt(u32, image[h + 8 ..][0..4], .little);
        const raw_size = std.mem.readInt(u32, image[h + 16 ..][0..4], .little);
        const at = std.mem.readInt(u32, image[h + 20 ..][0..4], .little);
        if (size == 0 or size > raw_size or at > image.len or size > image.len - at)
            return Error.BadSection;
        found = image[at..][0..size];
    }
    return found;
}

/// hasAuthenticode reports whether image is a well-formed PE32+ carrying at
/// least one PKCS#7 Authenticode WIN_CERTIFICATE record in DataDirectory[4].
pub fn hasAuthenticode(image: []const u8) Error!bool {
    const p = try parse(image);
    if (p.sec_off == 0 and p.sec_size == 0) return false;
    const table = image[p.sec_off .. p.sec_off + p.sec_size];
    var at: usize = 0;
    var count: usize = 0;
    while (at < table.len) {
        if (table.len - at < 8) return Error.BadSection;
        const len: usize = std.mem.readInt(u32, table[at..][0..4], .little);
        const rev = std.mem.readInt(u16, table[at + 4 ..][0..2], .little);
        const kind = std.mem.readInt(u16, table[at + 6 ..][0..2], .little);
        if (len < 9 or len > table.len - at) return Error.BadSection;
        if (rev != 0x0200 or kind != 0x0002 or table[at + 8] != 0x30)
            return Error.BadSection;
        count += 1;
        if (at + len == table.len) break;
        const step = std.mem.alignForward(usize, len, 8);
        if (step > table.len - at) return Error.BadSection;
        at += step;
    }
    return count > 0;
}

/// parse reads the headers whose fields uki keeps to, rejecting truncated,
/// overlapping or out-of-bounds headers, sections and certificate tables.
fn parse(image: []const u8) Error!Pe {
    if (image.len < 0x40 or !std.mem.eql(u8, image[0..2], "MZ")) return Error.NotPE;
    const pe: usize = std.mem.readInt(u32, image[0x3c..][0..4], .little);
    if (pe > image.len - 24 or
        !std.mem.eql(u8, image[pe..][0..4], "PE\x00\x00")) return Error.NotPE;
    const coff = pe + 4;
    const optional: usize = std.mem.readInt(u16, image[coff + 16 ..][0..2], .little);
    const count: usize = std.mem.readInt(u16, image[coff + 2 ..][0..2], .little);
    if (optional < 112 or optional > image.len - (coff + 20)) return Error.NotPE;
    const sections = coff + 20 + optional;
    if (count > (image.len - sections) / 40) return Error.NotPE;
    const headers_end = sections + count * 40;
    var p: Pe = .{
        .coff = coff,
        .opt = coff + 20,
        .optional = optional,
        .sections = sections,
        .nsections = count,
        .machine = std.mem.readInt(u16, image[coff..][0..2], .little),
        .file_align = std.mem.readInt(u32, image[coff + 56 ..][0..4], .little),
        .sect_align = std.mem.readInt(u32, image[coff + 52 ..][0..4], .little),
        .size_of_headers = std.mem.readInt(u32, image[coff + 20 + 60 ..][0..4], .little),
        .first_raw = std.math.maxInt(usize),
        .last_virt_end = 0,
        .sec_off = 0,
        .sec_size = 0,
    };
    if (p.machine != 0xaa64 and p.machine != 0x8664) return Error.UnsupportedMachine;
    if (std.mem.readInt(u16, image[p.opt..][0..2], .little) != 0x20b) return Error.NotPE32Plus;
    if (p.file_align < 0x200 or p.file_align > 0x10000 or !std.math.isPowerOfTwo(p.file_align))
        return Error.NotPE;
    if (p.sect_align < p.file_align or !std.math.isPowerOfTwo(p.sect_align))
        return Error.NotPE;
    const num_dirs: usize = std.mem.readInt(u32, image[p.opt + 108 ..][0..4], .little);
    if (num_dirs > (optional - 112) / 8) return Error.NotPE;
    if (p.nsections == 0) return Error.NoSections;
    var max_raw_end: usize = headers_end;
    for (0..p.nsections) |i| {
        const h = p.sections + i * 40;
        const vsize = std.mem.readInt(u32, image[h + 8 ..][0..4], .little);
        const vaddr = std.mem.readInt(u32, image[h + 12 ..][0..4], .little);
        const raw_size = std.mem.readInt(u32, image[h + 16 ..][0..4], .little);
        const raw = std.mem.readInt(u32, image[h + 20 ..][0..4], .little);
        const vspan = if (vsize != 0) vsize else raw_size;
        const vend = std.math.add(u32, vaddr, vspan) catch return Error.BadSection;
        p.last_virt_end = @max(p.last_virt_end, vend);
        var rend: u32 = raw;
        if (raw != 0 or raw_size != 0) {
            if (raw < headers_end) return Error.BadSection;
            rend = std.math.add(u32, raw, raw_size) catch return Error.BadSection;
            if (rend > image.len) return Error.BadSection;
            if (raw_size != 0) {
                p.first_raw = @min(p.first_raw, raw);
                max_raw_end = @max(max_raw_end, rend);
            }
        }
        for (0..i) |j| {
            const hj = p.sections + j * 40;
            const vsj = std.mem.readInt(u32, image[hj + 8 ..][0..4], .little);
            const vaj = std.mem.readInt(u32, image[hj + 12 ..][0..4], .little);
            const rsj = std.mem.readInt(u32, image[hj + 16 ..][0..4], .little);
            const rj = std.mem.readInt(u32, image[hj + 20 ..][0..4], .little);
            const vspan_j = if (vsj != 0) vsj else rsj;
            if (vspan > 0 and vspan_j > 0 and vaddr < vaj + vspan_j and vaj < vend)
                return Error.BadSection;
            if (raw_size > 0 and rsj > 0 and raw < rj + rsj and rj < rend)
                return Error.BadSection;
        }
    }
    if (p.first_raw == std.math.maxInt(usize)) return Error.NoSections;
    if (p.size_of_headers != 0 and
        (p.size_of_headers < headers_end or p.size_of_headers > p.first_raw))
        return Error.NotPE;
    if (num_dirs > 4) {
        p.sec_off = std.mem.readInt(u32, image[p.opt + 144 ..][0..4], .little);
        p.sec_size = std.mem.readInt(u32, image[p.opt + 148 ..][0..4], .little);
        if (p.sec_off != 0 or p.sec_size != 0) {
            if (p.sec_off < max_raw_end or p.sec_off % 8 != 0 or p.sec_size < 8 or
                p.sec_off > image.len or p.sec_size > image.len - p.sec_off)
                return Error.BadSection;
        }
    }
    return p;
}

fn alignForwardU32(n: u32, alignment: usize) Error!u32 {
    const a = std.math.cast(u32, alignment) orelse return Error.ImageTooLarge;
    const mask = a - 1;
    const padded = std.math.add(u32, n, mask) catch return Error.ImageTooLarge;
    return padded & ~mask;
}

/// assemble appends one section per name to stub, each holding its file,
/// and returns the image: sections laid out in order after the last one's
/// raw data, their headers in the room between the headers and the first
/// section's raw data, and the header patched to count and cover them.
pub fn assemble(
    gpa: std.mem.Allocator,
    stub: []const u8,
    names: []const []const u8,
    datas: []const []const u8,
) Error![]const u8 {
    if (names.len != datas.len) return Error.BadSection;
    const p = try parse(stub);
    const headers_end = p.sections + p.nsections * 40;
    const hdr_limit = if (p.size_of_headers != 0)
        @min(p.first_raw, p.size_of_headers)
    else
        p.first_raw;
    const added_hdrs = std.math.mul(usize, names.len, 40) catch return Error.NoHeaderRoom;
    if (added_hdrs > hdr_limit - headers_end) return Error.NoHeaderRoom;
    const total_sections = std.math.add(
        usize,
        p.nsections,
        names.len,
    ) catch return Error.ImageTooLarge;
    const nsections_u16 = std.math.cast(u16, total_sections) orelse return Error.ImageTooLarge;
    for (names) |n| if (n.len == 0 or n.len > 8) return Error.NameTooLong;

    // Strip any signature table on the input stub; appending sections invalidates it.
    const base = if (p.sec_off != 0) stub[0..p.sec_off] else stub;
    const base_u32 = std.math.cast(u32, base.len) orelse return Error.ImageTooLarge;
    const new_raw = try alignForwardU32(base_u32, p.file_align);
    const last_virt_u32 = std.math.cast(u32, p.last_virt_end) orelse return Error.ImageTooLarge;

    var out: std.ArrayList(u8) = .empty;
    out.appendSlice(gpa, base) catch return Error.NoHeaderRoom;
    out.appendNTimes(gpa, 0, new_raw - base.len) catch return Error.NoHeaderRoom;

    const image_scn_cnt_initialized_data: u32 = 0x40;
    const image_scn_mem_read: u32 = 0x40000000;
    const image_scn_mem_discardable: u32 = 0x2000000;
    var raw: u32 = new_raw;
    var virt: u32 = try alignForwardU32(last_virt_u32, p.sect_align);
    var nsections = p.nsections;
    for (names, datas) |name, data| {
        const data_u32 = std.math.cast(u32, data.len) orelse return Error.ImageTooLarge;
        const raw_aligned = try alignForwardU32(data_u32, p.file_align);
        const virt_aligned = try alignForwardU32(@max(data_u32, 1), p.sect_align);
        const next_raw = std.math.add(u32, raw, raw_aligned) catch return Error.ImageTooLarge;
        const next_virt = std.math.add(u32, virt, virt_aligned) catch return Error.ImageTooLarge;
        const h = headers_end + (nsections - p.nsections) * 40;
        var hdr: [40]u8 = @splat(0);
        @memcpy(hdr[0..name.len], name);
        std.mem.writeInt(u32, hdr[8..12], data_u32, .little);
        std.mem.writeInt(u32, hdr[12..16], virt, .little);
        std.mem.writeInt(u32, hdr[16..20], raw_aligned, .little);
        std.mem.writeInt(u32, hdr[20..24], raw, .little);
        std.mem.writeInt(u32, hdr[36..40], image_scn_cnt_initialized_data | image_scn_mem_read |
            if (std.mem.eql(u8, name, ".cmdline")) image_scn_mem_discardable else 0, .little);
        @memcpy(out.items[h .. h + 40], &hdr);
        out.appendNTimes(gpa, 0, @as(usize, raw) - out.items.len) catch return Error.NoHeaderRoom;
        out.appendSlice(gpa, data) catch return Error.NoHeaderRoom;
        const pad = @as(usize, raw_aligned) - data.len;
        out.appendNTimes(gpa, 0, pad) catch return Error.NoHeaderRoom;
        virt = next_virt;
        raw = next_raw;
        nsections += 1;
    }
    const size_of_image = try alignForwardU32(virt, p.sect_align);
    const buf = out.items;
    std.mem.writeInt(u16, buf[p.coff + 2 ..][0..2], nsections_u16, .little);
    std.mem.writeInt(u32, buf[p.opt + 56 ..][0..4], size_of_image, .little);
    std.mem.writeInt(u32, buf[p.opt + 64 ..][0..4], 0, .little);
    if (p.optional >= 152) @memset(buf[p.opt + 144 ..][0..8], 0);
    return buf;
}

/// peForTests is a PE32+ arm64 image of one .text section, for the tests.
fn peForTests(gpa: std.mem.Allocator, text_len: usize) ![]u8 {
    const file_align = 0x200;
    const sect_align = 0x1000;
    const first_raw = 0x200;
    var out = try gpa.alloc(u8, first_raw + text_len);
    @memset(out, 0);
    std.mem.writeInt(u16, out[0..2], 'M' | ('Z' << 8), .little);
    std.mem.writeInt(u32, out[0x3c..][0..4], 0x80, .little);
    @memcpy(out[0x80..][0..4], "PE\x00\x00");
    std.mem.writeInt(u16, out[0x84..][0..2], 0xaa64, .little); // machine
    std.mem.writeInt(u16, out[0x86..][0..2], 1, .little); // sections
    std.mem.writeInt(u16, out[0x94..][0..2], 240, .little); // optional size
    std.mem.writeInt(u16, out[0x98..][0..2], 0x20b, .little); // PE32+
    std.mem.writeInt(u32, out[0x84 + 52 ..][0..4], sect_align, .little);
    std.mem.writeInt(u32, out[0x84 + 56 ..][0..4], file_align, .little);
    const h = 0x84 + 20 + 240;
    @memcpy(out[h..][0..5], ".text");
    std.mem.writeInt(u32, out[h + 8 ..][0..4], @intCast(text_len), .little);
    std.mem.writeInt(u32, out[h + 12 ..][0..4], sect_align, .little);
    std.mem.writeInt(u32, out[h + 16 ..][0..4], @intCast(text_len), .little);
    std.mem.writeInt(u32, out[h + 20 ..][0..4], first_raw, .little);
    @memset(out[first_raw..], 0x90);
    return out;
}

const testing = std.testing;

test "assemble appends sections the headers name, and the header counts" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const stub = try peForTests(gpa, 0x123);
    const names = [_][]const u8{ ".cmdline", ".initrd" };
    const datas = [_][]const u8{ "console=ttyAMA0\x00", "initrd-bytes" };
    const out = try assemble(gpa, stub, &names, &datas);

    const p = try parse(out);
    try testing.expectEqual(@as(usize, 3), p.nsections);
    try testing.expectEqualStrings(".cmdline", out[p.sections + 40 ..][0..8]);
    try testing.expectEqualStrings(".initrd", out[p.sections + 80 ..][0..7]);

    // VirtualSize holds the data's length; SizeOfRawData is file-aligned.
    const cmdline = p.sections + 40;
    try testing.expectEqual(@as(u32, 16), std.mem.readInt(u32, out[cmdline + 8 ..][0..4], .little));
    try testing.expectEqual(
        @as(u32, 0x200),
        std.mem.readInt(u32, out[cmdline + 16 ..][0..4], .little),
    );

    // The section's raw data is where its header says, past the stub.
    const raw = std.mem.readInt(u32, out[cmdline + 20 ..][0..4], .little);
    try testing.expectEqualSlices(u8, datas[0], out[raw..][0..16]);

    // SizeOfImage covers the last section.
    const initrd = p.sections + 80;
    const vaddr = std.mem.readInt(u32, out[initrd + 12 ..][0..4], .little);
    const vsize = std.mem.readInt(u32, out[initrd + 8 ..][0..4], .little);
    const size_of_image = std.mem.readInt(u32, out[p.opt + 56 ..][0..4], .little);
    try testing.expect(vaddr + vsize <= size_of_image);
}

test "assemble refuses a name longer than a section's" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const stub = try peForTests(a.allocator(), 4);
    const names = [_][]const u8{".toolongname"};
    const datas = [_][]const u8{"x"};
    try testing.expectError(Error.NameTooLong, assemble(a.allocator(), stub, &names, &datas));
}

test "section extraction rejects ambiguous names, truncated headers and raw bounds" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const stub = try peForTests(a.allocator(), 6);
    const out = try assemble(
        a.allocator(),
        stub,
        &.{ ".cmdline", ".cmdline" },
        &.{ "a\x00", "b\x00" },
    );
    try testing.expectError(error.DuplicateSection, section(out, ".cmdline"));
    for (0..out.len) |n| {
        _ = section(out[0..n], ".cmdline") catch continue;
        if (n < 0x200) return error.TestUnexpectedResult;
    }
    const p = try parse(out);
    const altered = try a.allocator().dupe(u8, out);
    std.mem.writeInt(u32, altered[p.sections + 40 + 20 ..][0..4], 0xffffffff, .little);
    try testing.expectError(error.BadSection, section(altered, ".cmdline"));
}

test "PE32+ supports arm64 and x86_64, and refuses other machines" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    try testing.expectError(Error.NotPE, parse("not a PE"));
    const stub = try peForTests(a.allocator(), 4);
    std.mem.writeInt(u16, stub[0x84..][0..2], 0x8664, .little); // x86_64
    try testing.expectEqual(@as(u16, 0x8664), (try parse(stub)).machine);
    const x = try assemble(a.allocator(), stub, &.{".cmdline"}, &.{"quiet\x00"});
    try testing.expectEqual(@as(u16, 0x8664), (try parse(x)).machine);
    std.mem.writeInt(u16, stub[0x84..][0..2], 0x14c, .little);
    try testing.expectError(Error.UnsupportedMachine, parse(stub));
}

test "parse rejects adversarial alignments, e_lfanew wraparound and overlapping sections" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const base = try peForTests(gpa, 0x200);

    const bad_lfanew = try gpa.dupe(u8, base);
    std.mem.writeInt(u32, bad_lfanew[0x3c..][0..4], 0xfffffff0, .little);
    try testing.expectError(Error.NotPE, parse(bad_lfanew));

    for ([_]u32{ 0, 0x100, 0x300, 0x20000 }) |fa| {
        const bad_fa = try gpa.dupe(u8, base);
        std.mem.writeInt(u32, bad_fa[0x84 + 56 ..][0..4], fa, .little);
        try testing.expectError(Error.NotPE, parse(bad_fa));
    }

    const bad_sa = try gpa.dupe(u8, base);
    std.mem.writeInt(u32, bad_sa[0x84 + 52 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, bad_sa[0x84 + 56 ..][0..4], 0x400, .little);
    try testing.expectError(Error.NotPE, parse(bad_sa));

    const two = try assemble(gpa, base, &.{".cmdline"}, &.{"quiet\x00"});
    const p = try parse(two);
    const raw_overlap = try gpa.dupe(u8, two);
    std.mem.writeInt(u32, raw_overlap[p.sections + 40 + 20 ..][0..4], 0x200, .little);
    try testing.expectError(Error.BadSection, parse(raw_overlap));

    const virt_overlap = try gpa.dupe(u8, two);
    std.mem.writeInt(u32, virt_overlap[p.sections + 40 + 12 ..][0..4], 0x1000, .little);
    try testing.expectError(Error.BadSection, parse(virt_overlap));
}

test "Authenticode verification and stripping on assemble" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const stub = try peForTests(gpa, 0x200);
    std.mem.writeInt(u32, stub[0x98 + 108 ..][0..4], 16, .little); // NumberOfRvaAndSizes
    std.mem.writeInt(u32, stub[0x98 + 64 ..][0..4], 0xdeadbeef, .little); // CheckSum
    try testing.expect(!try hasAuthenticode(stub));

    const cert_off: u32 = @intCast(std.mem.alignForward(usize, stub.len, 8));
    var cert: [16]u8 = @splat(0);
    std.mem.writeInt(u32, cert[0..4], 12, .little); // dwLength
    std.mem.writeInt(u16, cert[4..6], 0x0200, .little); // WIN_CERT_REVISION_2_0
    std.mem.writeInt(u16, cert[6..8], 0x0002, .little); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    cert[8] = 0x30; // DER SEQUENCE
    cert[9] = 0x02;
    var signed_pe: std.ArrayList(u8) = .empty;
    try signed_pe.appendSlice(gpa, stub);
    try signed_pe.appendNTimes(gpa, 0, cert_off - stub.len);
    try signed_pe.appendSlice(gpa, &cert);
    std.mem.writeInt(u32, signed_pe.items[0x98 + 144 ..][0..4], cert_off, .little);
    std.mem.writeInt(u32, signed_pe.items[0x98 + 148 ..][0..4], cert.len, .little);
    try testing.expect(try hasAuthenticode(signed_pe.items));

    const bad_cert = try gpa.dupe(u8, signed_pe.items);
    bad_cert[cert_off + 8] = 0x04; // OCTET STRING, not SEQUENCE
    try testing.expectError(Error.BadSection, hasAuthenticode(bad_cert));

    const unaligned = try gpa.dupe(u8, signed_pe.items);
    std.mem.writeInt(u32, unaligned[0x98 + 144 ..][0..4], cert_off + 4, .little);
    std.mem.writeInt(u32, unaligned[0x98 + 148 ..][0..4], 8, .little);
    try testing.expectError(Error.BadSection, hasAuthenticode(unaligned));

    const rebuilt = try assemble(gpa, signed_pe.items, &.{".cmdline"}, &.{"quiet\x00"});
    try testing.expect(!try hasAuthenticode(rebuilt));
    try testing.expectEqual(
        @as(u32, 0),
        std.mem.readInt(u32, rebuilt[0x98 + 64 ..][0..4], .little),
    );
    try testing.expectEqual(
        @as(u64, 0),
        std.mem.readInt(u64, rebuilt[0x98 + 144 ..][0..8], .little),
    );
}
