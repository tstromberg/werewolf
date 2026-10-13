//! Host permit generation and integration probes for TPM retirement policies.
const std = @import("std");
const apk = @import("apk");
const tpm = @import("tpm");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 5) return error.BadArguments;
    if (std.mem.eql(u8, args[1], "transition") and args.len == 6) {
        const old = try stateFile(io, gpa, args[2]);
        const next = try stateFile(io, gpa, args[3]);
        try old.transition(
            next,
            try digestFile(io, gpa, args[4]),
            try digestFile(io, gpa, args[5]),
        );
        return;
    }
    const key = try apk.parseKey(
        gpa,
        try std.Io.Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(8192)),
    );
    if (std.mem.eql(u8, args[1], "read-pair") and args.len == 5) {
        var device = try connect(io, args[3]);
        defer device.close();
        try device.disablePlatform();
        try std.Io.Dir.cwd().writeFile(
            io,
            .{ .sub_path = args[4], .data = &try device.anchor(key) },
        );
        return;
    }
    if (std.mem.eql(u8, args[1], "recover-pair") and args.len == 7) {
        const initial = try tpm.bundle(key, try read(io, gpa, args[3], tpm.record_size + 512));
        var credentials: [2][32]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&credentials));
        for ([2][]const u8{ "owner.auth", "lockout.auth" }, &credentials) |name, *secret| {
            const raw = try read(io, gpa, try gpa.print("{s}/{s}", .{ args[5], name }), 32);
            defer std.crypto.secureZero(u8, raw);
            if (raw.len != 32) return error.BadProvisioningCredential;
            @memcpy(secret, raw);
        }
        var device = try connect(io, args[4]);
        defer device.close();
        try device.recover(key, initial, &credentials);
        try std.Io.Dir.cwd().writeFile(
            io,
            .{ .sub_path = args[6], .data = &try device.anchor(key) },
        );
        return;
    }
    if (std.mem.eql(u8, args[1], "bootstrap-pair") and args.len == 6) {
        const raw = try read(io, gpa, args[3], tpm.record_size + 512);
        const initial = try tpm.bundle(key, raw);
        const directory = try std.Io.Dir.cwd().createDirPathOpen(
            io,
            args[5],
            .{ .open_options = .{ .iterate = true } },
        );
        defer directory.close(io);
        try directory.setPermissions(io, .fromMode(0o700));
        var credentials: [2][32]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&credentials));
        for ([2][]const u8{ "owner.auth", "lockout.auth" }, &credentials) |filename, *secret| {
            try io.randomSecure(secret);
            const file = try directory.createFile(io, filename, .{
                .exclusive = true,
                .permissions = .fromMode(0o600),
            });
            defer file.close(io);
            try file.writeStreamingAll(io, secret);
            try file.sync(io);
        }
        const directory_file: std.Io.File = .{
            .handle = directory.handle,
            .flags = .{ .nonblocking = false },
        };
        try directory_file.sync(io);
        var device = try connect(io, args[4]);
        defer device.close();
        try device.provision(key, initial, &credentials);
        return;
    }
    if (std.mem.eql(u8, args[1], "permit-pair") and args.len == 5) {
        const data = try tpm.pairMessage(key, try stateFile(io, gpa, args[3]));
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[4], .data = &data });
        return;
    }
    if (std.mem.eql(u8, args[1], "verify-pair") and args.len == 7) {
        _ = try tpm.verifyRecord(
            key,
            try read(io, gpa, args[3], tpm.record_size),
            try read(io, gpa, args[4], 8192),
            try digestFile(io, gpa, args[5]),
            try digestFile(io, gpa, args[6]),
        );
        return;
    }
    const pair = std.mem.eql(u8, args[1], "read-pair") or std.mem.eql(u8, args[1], "retire");
    const serial = if (pair) 0 else try std.fmt.parseUnsigned(u64, args[3], 10);
    if (std.mem.eql(u8, args[1], "permit")) {
        const policy = try tpm.approved(key, serial);
        const data = try std.mem.concat(gpa, u8, &.{ &policy, tpm.qualifier });
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[4], .data = data });
        return;
    }
    var device = try connect(io, if (std.mem.eql(u8, args[1], "read-pair")) args[3] else args[4]);
    defer device.close();
    try device.disablePlatform();
    if (pair) {
        if (std.mem.eql(u8, args[1], "retire") and args.len == 6) {
            try device.retire(
                key,
                try stateFile(io, gpa, args[3]),
                try read(io, gpa, args[5], 8192),
            );
        } else if (std.mem.eql(u8, args[1], "read-pair") and args.len == 5) {
            const anchor = try device.anchor(key);
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[4], .data = &anchor });
        } else return error.BadArguments;
        return;
    }
    if (std.mem.eql(u8, args[1], "check")) {
        try device.check(key, serial);
    } else if (std.mem.eql(u8, args[1], "advance") and args.len == 6) {
        const sig = try std.Io.Dir.cwd().readFileAlloc(io, args[5], gpa, .limited(8192));
        try device.advance(key, serial, sig);
    } else return error.BadArguments;
    try std.Io.File.stdout().writeStreamingAll(
        io,
        try gpa.print("floor {d}\n", .{try device.floor(key)}),
    );
}

fn connect(io: std.Io, endpoint: []const u8) !tpm.Device {
    const stream = if (std.mem.startsWith(u8, endpoint, "unix:")) blk: {
        const address = try std.Io.net.UnixAddress.init(endpoint[5..]);
        break :blk try address.connect(io);
    } else blk: {
        const address = try std.Io.net.IpAddress.parseIp4(
            "127.0.0.1",
            try std.fmt.parseUnsigned(u16, endpoint, 10),
        );
        break :blk try address.connect(io, .{ .mode = .stream });
    };
    return .{
        .io = io,
        .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } },
    };
}

fn read(io: std.Io, gpa: std.mem.Allocator, file: []const u8, limit: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, file, gpa, .limited(limit + 1));
}

fn stateFile(io: std.Io, gpa: std.mem.Allocator, file: []const u8) !tpm.Record {
    return tpm.Record.decode(try read(io, gpa, file, tpm.record_size));
}

fn digestFile(io: std.Io, gpa: std.mem.Allocator, file: []const u8) ![32]u8 {
    const raw = try read(io, gpa, file, 32);
    if (raw.len != 32) return error.BadDigest;
    var result: [32]u8 = undefined;
    @memcpy(&result, raw);
    return result;
}
