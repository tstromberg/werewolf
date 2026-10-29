//! The signed image declares the boot barrier version. Separate data volumes
//! record the verified root that last booted them; neither comes from archives.
const std = @import("std");
const data = @import("data-transfer.zig");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const mem = std.mem;
pub const barrier = "usr/share/werewolf/data-transfer-version";
pub const record_path = ".werewolf/data-image";

pub fn requireBarrier(io: Io, image: Dir) !void {
    var parent = data.parentDir(io, image, barrier) catch return error.TransferBootBarrier;
    defer parent.close(io);
    const f = data.openRegular(
        io,
        parent,
        std.fs.path.basename(barrier),
    ) catch return error.TransferBootBarrier;
    defer f.close(io);
    var bytes: [3]u8 = undefined;
    if ((try f.stat(io)).size != 2 or try f.readPositionalAll(io, &bytes, 0) != 2 or
        !mem.eql(u8, bytes[0..2], "1\n")) return error.TransferBootBarrier;
}

pub fn requireRecorded(io: Io, root: Dir, image: []const u8) !void {
    var parent = data.parentDir(io, root, record_path) catch |err| switch (err) {
        error.FileNotFound => return error.TransferImageUnrecorded,
        else => return err,
    };
    defer parent.close(io);
    const f = data.openRegular(io, parent, "data-image") catch |err| switch (err) {
        error.FileNotFound => return error.TransferImageUnrecorded,
        else => return err,
    };
    defer f.close(io);
    if ((try f.stat(io)).permissions.toMode() & 0o7777 != 0o600) return error.TransferState;
    if (@import("builtin").os.tag == .linux) {
        const linux = std.os.linux;
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(
            f.handle,
            "",
            linux.AT.EMPTY_PATH,
            .{ .UID = true, .GID = true },
            &st,
        )) != .SUCCESS or
            st.uid != 0 or st.gid != 0) return error.TransferState;
    }
    var bytes: [66]u8 = undefined;
    if (image.len != 64 or (try f.stat(io)).size != 65 or
        try f.readPositionalAll(io, &bytes, 0) != 65 or bytes[64] != '\n' or
        !mem.eql(u8, bytes[0..64], image)) return error.TransferImage;
}

/// Called by init with stage0's verified identity, before any service starts.
pub fn record(io: Io, root: Dir, image: []const u8) !void {
    if (image.len != 64) return error.TransferImage;
    for (image) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return error.TransferImage;
    var machine = try data.install.openMachine(io, root);
    defer machine.close(io);
    machine.deleteFile(io, "data-image-part") catch |err| if (err != error.FileNotFound) return err;
    const f = try machine.createFile(
        io,
        "data-image-part",
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    defer f.close(io);
    try f.writeStreamingAll(io, image);
    try f.writeStreamingAll(io, "\n");
    try f.sync(io);
    try machine.rename("data-image-part", machine, "data-image", io);
    try data.install.syncDir(io, machine);
    try data.install.syncDir(io, root);
}

test "image declarations fail closed when absent, mismatched or linked" {
    const t = std.testing;
    const io = t.io;
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try t.expectError(error.TransferImageUnrecorded, requireRecorded(io, tmp.dir, image));
    try record(io, tmp.dir, image);
    // Unprivileged Linux tests cannot create root-owned records. Exercise that
    // refusal here; the root-run transfer boundary suite checks the valid record.
    const unprivileged = @import("builtin").os.tag == .linux and
        (std.os.linux.getuid() != 0 or std.os.linux.getgid() != 0);
    if (unprivileged) {
        try t.expectError(error.TransferState, requireRecorded(io, tmp.dir, image));
    } else {
        try requireRecorded(io, tmp.dir, image);
        try t.expectError(
            error.TransferImage,
            requireRecorded(
                io,
                tmp.dir,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        );
    }
    try tmp.dir.deleteFile(io, record_path);
    try tmp.dir.symLink(io, "missing", record_path, .{});
    if (requireRecorded(io, tmp.dir, image)) |_| return error.AcceptedLinkedIdentity else |_| {}
    try tmp.dir.createDirPath(io, "usr/share/werewolf");
    if (requireBarrier(io, tmp.dir)) |_| return error.AcceptedMissingBarrier else |_| {}
    try tmp.dir.writeFile(io, .{ .sub_path = barrier, .data = "0\n" });
    try t.expectError(error.TransferBootBarrier, requireBarrier(io, tmp.dir));
    try tmp.dir.writeFile(io, .{ .sub_path = barrier, .data = "1\n" });
    try requireBarrier(io, tmp.dir);
}
