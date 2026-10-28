//! The v1 metadata subset: ordinary modes/times/owners and the unnamed
//! three-entry default ACL used by leash's share-group directories. Reject
//! other xattrs/ACLs explicitly rather than silently changing a backup.
const std = @import("std");
const data = @import("data-transfer.zig");
const linux = std.os.linux;
const mem = std.mem;

pub fn owner(_: ?*anyopaque, file: std.Io.File) !data.Owner {
    if (@import("builtin").os.tag != .linux) return error.TransferLinuxMetadata;
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .{
        .UID = true,
        .GID = true,
        .MODE = true,
        .TYPE = true,
    }, &st)) != .SUCCESS) return error.TransferMetadata;
    if (@as(u64, @bitCast(st.attributes)) & (0x10 | 0x20 | 0x800 | 0x2000 | 0x100000) != 0)
        return error.TransferMetadata;
    var result: data.Owner = .{ .uid = st.uid, .gid = st.gid };
    var names: [4096]u8 = undefined;
    const n = linux.flistxattr(file.handle, &names, names.len);
    if (linux.errno(n) != .SUCCESS or n > names.len) return error.TransferMetadata;
    var at: usize = 0;
    while (at < n) {
        const end = mem.findScalarPos(u8, names[0..n], at, 0) orelse return error.TransferMetadata;
        const name = names[at..end];
        const is_default = mem.eql(u8, name, "system.posix_acl_default");
        const is_access = mem.eql(u8, name, "system.posix_acl_access");
        if (!is_default and !is_access) return error.TransferMetadata;
        var acl_bytes: [28]u8 = undefined;
        const got = linux.fgetxattr(
            file.handle,
            if (is_default) "system.posix_acl_default" else "system.posix_acl_access",
            &acl_bytes,
            acl_bytes.len,
        );
        if (linux.errno(got) != .SUCCESS or got != acl_bytes.len) return error.TransferMetadata;
        const acl = try decode(&acl_bytes);
        if (is_default) {
            if (st.mode & linux.S.IFMT != linux.S.IFDIR) return error.TransferMetadata;
            result.default_acl = acl;
        } else if (acl.user != (st.mode >> 6) & 7 or acl.group != (st.mode >> 3) & 7 or
            acl.other != st.mode & 7)
            return error.TransferMetadata;
        at = end + 1;
    }
    return result;
}

pub fn setDefault(file: std.Io.File, acl: data.DefaultAcl) !void {
    if (@import("builtin").os.tag != .linux) return error.TransferLinuxMetadata;
    const bytes = encode(acl);
    if (linux.errno(linux.fsetxattr(
        file.handle,
        "system.posix_acl_default",
        &bytes,
        bytes.len,
        0,
    )) != .SUCCESS)
        return error.TransferMetadata;
}

pub fn clearDefault(file: std.Io.File) !void {
    if (@import("builtin").os.tag != .linux) return;
    const rc = linux.fremovexattr(file.handle, "system.posix_acl_default");
    switch (linux.errno(rc)) {
        .SUCCESS, .NODATA => {},
        else => return error.TransferMetadata,
    }
}

pub fn encode(acl: data.DefaultAcl) [28]u8 {
    var bytes: [28]u8 = @splat(0);
    mem.writeInt(u32, bytes[0..4], 2, .little);
    for ([_]u16{ 1, 4, 32 }, [_]u3{ acl.user, acl.group, acl.other }, 0..) |tag, perm, i| {
        const offset = 4 + i * 8;
        mem.writeInt(u16, bytes[offset..][0..2], tag, .little);
        mem.writeInt(u16, bytes[offset + 2 ..][0..2], perm, .little);
        mem.writeInt(u32, bytes[offset + 4 ..][0..4], 0xffffffff, .little);
    }
    return bytes;
}

pub fn decode(bytes: *const [28]u8) !data.DefaultAcl {
    if (mem.readInt(u32, bytes[0..4], .little) != 2) return error.TransferMetadata;
    var permissions: [3]u3 = undefined;
    for ([_]u16{ 1, 4, 32 }, 0..) |tag, i| {
        const offset = 4 + i * 8;
        if (mem.readInt(u16, bytes[offset..][0..2], .little) != tag or
            mem.readInt(
                u32,
                bytes[offset + 4 ..][0..4],
                .little,
            ) != 0xffffffff) return error.TransferMetadata;
        const perm = mem.readInt(u16, bytes[offset + 2 ..][0..2], .little);
        if (perm > 7) return error.TransferMetadata;
        permissions[i] = @intCast(perm);
    }
    return .{ .user = permissions[0], .group = permissions[1], .other = permissions[2] };
}

test "default group ACL survives encoding and named or privileged extensions fail" {
    const t = std.testing;
    const acl: data.DefaultAcl = .{ .user = 7, .group = 7, .other = 5 };
    var bytes = encode(acl);
    try t.expectEqualDeep(acl, try decode(&bytes));
    bytes[4] = 2; // A named user is outside the v1 subset.
    try t.expectError(error.TransferMetadata, decode(&bytes));
    bytes = encode(acl);
    bytes[6] = 8;
    try t.expectError(error.TransferMetadata, decode(&bytes));
    bytes = encode(acl);
    bytes[8] = 0;
    try t.expectError(error.TransferMetadata, decode(&bytes));
}
