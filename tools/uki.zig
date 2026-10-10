//! uki assembles a Unified Kernel Image on the build host: sections named
//! on the command line (.linux, .initrd, .cmdline, ...) are appended to a
//! stub (systemd's linuxaa64.efi.stub), making one PE the firmware can
//! load, and a signature can cover whole. See docs/design/verified-boot.md.
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
        const eq = std.mem.indexOfScalar(u8, a, '=') orelse {
            std.log.err("usage: uki STUB OUT NAME=FILE...", .{});
            std.process.exit(2);
        };
        try names.append(gpa, a[0..eq]);
        try datas.append(gpa, try Dir.cwd().readFileAlloc(io, a[eq + 1 ..], gpa, .limited(512 << 20)));
    }
    const out = try assemble(gpa, stub, names.items, datas.items);
    try Dir.cwd().writeFile(io, .{ .sub_path = args[2], .data = out });
}

/// Pe points at a parsed PE32+ image: where the headers are, and the
/// alignment new sections must keep.
const Pe = struct {
    coff: usize,
    opt: usize,
    sections: usize,
    nsections: usize,
    machine: u16,
    file_align: usize,
    sect_align: usize,
    first_raw: usize,
    last_virt_end: usize,
};

const Error = error{
    NotPE,
    NotArm64,
    NotPE32Plus,
    NoSections,
    NameTooLong,
    NoHeaderRoom,
};

/// parse reads the headers whose fields uki keeps to.
fn parse(image: []const u8) Error!Pe {
    if (image.len < 0x40 or !std.mem.eql(u8, image[0..2], "MZ")) return Error.NotPE;
    const pe = std.mem.readInt(u32, image[0x3c..][0..4], .little);
    if (pe + 24 > image.len or !std.mem.eql(u8, image[pe..][0..4], "PE\x00\x00")) return Error.NotPE;
    const coff = pe + 4;
    var p: Pe = .{
        .coff = coff,
        .opt = coff + 20,
        .sections = coff + 20 + std.mem.readInt(u16, image[coff + 16 ..][0..2], .little),
        .nsections = std.mem.readInt(u16, image[coff + 2 ..][0..2], .little),
        .machine = std.mem.readInt(u16, image[coff..][0..2], .little),
        .file_align = std.mem.readInt(u32, image[coff + 56 ..][0..4], .little),
        .sect_align = std.mem.readInt(u32, image[coff + 52 ..][0..4], .little),
        .first_raw = std.math.maxInt(usize),
        .last_virt_end = 0,
    };
    if (p.machine != 0xaa64) return Error.NotArm64;
    if (std.mem.readInt(u16, image[p.opt..][0..2], .little) != 0x20b) return Error.NotPE32Plus;
    if (p.nsections == 0) return Error.NoSections;
    var i: usize = 0;
    while (i < p.nsections) : (i += 1) {
        const h = p.sections + i * 40;
        const raw = std.mem.readInt(u32, image[h + 20 ..][0..4], .little);
        if (raw != 0) p.first_raw = @min(p.first_raw, raw);
        const vsize = std.mem.readInt(u32, image[h + 8 ..][0..4], .little);
        const vaddr = std.mem.readInt(u32, image[h + 12 ..][0..4], .little);
        p.last_virt_end = @max(p.last_virt_end, vaddr +| vsize);
    }
    if (p.first_raw == std.math.maxInt(usize)) return Error.NoSections;
    return p;
}

/// assemble appends one section per name to stub, each holding its file,
/// and returns the image: sections laid out in order after the last one's
/// raw data, their headers in the room between the headers and the first
/// section's raw data, and the header patched to count and cover them.
fn assemble(gpa: std.mem.Allocator, stub: []const u8, names: []const []const u8, datas: []const []const u8) ![]const u8 {
    const p = try parse(stub);
    const headers_end = p.sections + p.nsections * 40;
    if (headers_end + names.len * 40 > p.first_raw) return Error.NoHeaderRoom;
    for (names) |n| if (n.len > 8) return Error.NameTooLong;

    var out: std.ArrayList(u8) = .empty;
    out.appendSlice(gpa, stub) catch return Error.NoHeaderRoom;
    const new_raw = std.mem.alignForward(usize, stub.len, p.file_align);
    out.appendNTimes(gpa, 0, new_raw - stub.len) catch return Error.NoHeaderRoom;

    const image_scn_cnt_initialized_data: u32 = 0x40;
    const image_scn_mem_read: u32 = 0x40000000;
    const image_scn_mem_discardable: u32 = 0x2000000;
    var raw = new_raw;
    var virt = std.mem.alignForward(usize, p.last_virt_end, p.sect_align);
    var nsections = p.nsections;
    for (names, datas) |name, data| {
        const h = headers_end + (nsections - p.nsections) * 40;
        var hdr: [40]u8 = @splat(0);
        @memcpy(hdr[0..name.len], name);
        std.mem.writeInt(u32, hdr[8..12], @intCast(data.len), .little);
        std.mem.writeInt(u32, hdr[12..16], @intCast(virt), .little);
        std.mem.writeInt(
            u32,
            hdr[16..20],
            @intCast(std.mem.alignForward(usize, data.len, p.file_align)),
            .little,
        );
        std.mem.writeInt(u32, hdr[20..24], @intCast(raw), .little);
        std.mem.writeInt(u32, hdr[36..40], image_scn_cnt_initialized_data | image_scn_mem_read |
            if (std.mem.eql(u8, name, ".cmdline")) image_scn_mem_discardable else 0, .little);
        @memcpy(out.items[h .. h + 40], &hdr);
        out.appendNTimes(gpa, 0, raw - out.items.len) catch return Error.NoHeaderRoom;
        out.appendSlice(gpa, data) catch return Error.NoHeaderRoom;
        const pad = std.mem.alignForward(usize, data.len, p.file_align) - data.len;
        out.appendNTimes(gpa, 0, pad) catch return Error.NoHeaderRoom;
        virt += std.mem.alignForward(usize, data.len, p.sect_align);
        raw += std.mem.alignForward(usize, data.len, p.file_align);
        nsections += 1;
    }
    const buf = out.items;
    std.mem.writeInt(u16, buf[p.coff + 2 ..][0..2], @intCast(nsections), .little);
    std.mem.writeInt(
        u32,
        buf[p.opt + 56 ..][0..4],
        @intCast(std.mem.alignForward(usize, virt, p.sect_align)),
        .little,
    );
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
    try testing.expectEqual(@as(u32, 0x200), std.mem.readInt(u32, out[cmdline + 16 ..][0..4], .little));

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

test "parse refuses what is not an arm64 PE32+" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    try testing.expectError(Error.NotPE, parse("not a PE"));
    const stub = try peForTests(a.allocator(), 4);
    std.mem.writeInt(u16, stub[0x84..][0..2], 0x8664, .little); // x86_64
    try testing.expectError(Error.NotArm64, parse(stub));
}
