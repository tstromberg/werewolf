//! Signed diagnostic loader: public firmware capabilities and fixed bootstrap
//! chain load only. It changes no variables or security settings and issues
//! no TPM commands; firmware still measures the ordinary image loads.
const std = @import("std");
const efi = std.os.uefi;

const Tcg2 = extern struct {
    capability: *const fn (*Tcg2, *[256]u8) callconv(efi.cc) efi.Status,
    pub const guid: efi.Guid = .{
        .time_low = 0x607f766c,
        .time_mid = 0x7455,
        .time_high_and_version = 0x42be,
        .clock_seq_high_and_reserved = 0x93,
        .clock_seq_low = 0x0b,
        .node = .{ 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f },
    };
};

fn say(comptime format: []const u8, args: anytype) void {
    var text: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&text, "efi-bootstrap-probe: " ++ format ++ "\r\n", args) catch return;
    if (efi.system_table.con_out) |console| {
        var wide: [513:0]u16 = @splat(0);
        for (line, 0..) |byte, i| wide[i] = byte;
        _ = console.outputString(&wide) catch false;
    }
    if (efi.system_table.boot_services) |boot| {
        if (boot.locateProtocol(efi.protocol.SerialIo, null) catch null) |serial|
            _ = serial.write(line) catch 0;
    }
}

pub fn main() efi.Status {
    run() catch |err| {
        say("refused: {s}", .{@errorName(err)});
        return .load_error;
    };
    return .success;
}

fn run() !void {
    const boot = efi.system_table.boot_services orelse return error.NoBootServices;
    say("firmware revision={x}, UEFI revision={x}", .{
        efi.system_table.firmware_revision, efi.system_table.hdr.revision,
    });
    if (try boot.locateProtocol(Tcg2, null)) |tpm| {
        var capability: [256]u8 = @splat(0);
        capability[0] = 255;
        const status = tpm.capability(tpm, &capability);
        say("TCG2 capability status={x} public={x}", .{
            @backingInt(status), capability[0..@min(capability[0], 64)],
        });
    } else say("TCG2 protocol absent", .{});
    acpi();
    const loaded = (try boot.handleProtocol(efi.protocol.LoadedImage, efi.handle)) orelse return error.NoLoadedImage;
    const device = loaded.device_handle orelse return error.NoBootDevice;
    const source = (try boot.handleProtocol(efi.protocol.DevicePath, device)) orelse return error.NoBootPath;
    const target = try source.createFileDevicePath(efi.pool_allocator, std.unicode.utf8ToUtf16LeStringLiteral("\\EFI\\Linux\\bootstrap.efi"));
    say("loading fixed signed bootstrap", .{});
    const image = boot.loadImage(false, efi.handle, .{ .device_path = target }) catch |err| {
        say("LoadImage: {s}", .{@errorName(err)});
        return err;
    };
    say("starting measured bootstrap", .{});
    const ended = try boot.startImage(image);
    say("bootstrap returned status={x}", .{@backingInt(ended.code)});
}

fn integer(comptime T: type, raw: [*]const u8, offset: usize) T {
    return std.mem.readInt(T, raw[offset..][0..@sizeOf(T)], .little);
}

fn acpi() void {
    const table = efi.system_table;
    if (table.number_of_table_entries > 256) return;
    for (table.configuration_table[0..table.number_of_table_entries]) |entry| {
        if (!entry.vendor_guid.eql(efi.tables.ConfigurationTable.acpi_20_table_guid)) continue;
        const rsdp: [*]const u8 = @ptrCast(entry.vendor_table);
        if (!std.mem.eql(u8, rsdp[0..8], "RSD PTR ") or rsdp[15] < 2) continue;
        const address = integer(u64, rsdp, 24);
        if (address == 0) continue;
        const xsdt: [*]const u8 = @ptrFromInt(address);
        const size = integer(u32, xsdt, 4);
        if (!std.mem.eql(u8, xsdt[0..4], "XSDT") or size < 36 or size > 4096) continue;
        for (0..(size - 36) / 8) |index| {
            const pointer = integer(u64, xsdt, 36 + index * 8);
            if (pointer == 0) continue;
            const data: [*]const u8 = @ptrFromInt(pointer);
            const length = integer(u32, data, 4);
            say("ACPI table {s} size={d}", .{ data[0..4], length });
            if (std.mem.eql(u8, data[0..4], "SPCR") and length >= 80)
                say("SPCR interface={d} space={d} width={d} access={d} address={x} baud={d}", .{
                    data[36], data[40], data[41], data[43], integer(u64, data, 44), data[58],
                });
            if (std.mem.eql(u8, data[0..4], "TPM2") and length >= 52)
                say("TPM2 control={x} start-method={d}", .{ integer(u64, data, 40), integer(u32, data, 48) });
        }
    }
}
