//! The base filesystem Werewolf owns. No login, spool or device-group policy.
pub const name = "werewolf-baselayout";
pub const passwd = "root:x:0:0:root:/root:/sbin/nologin\nnobody:x:65534:65534::/var/empty:/sbin/" ++
    "nologin\n";
pub const group = "root:x:0:root\nnobody:x:65534:\n";
pub const shadow = "root:!:::::::\nnobody:!:::::::\n";
pub const provides = &[_][]const u8{
    "wolfi-baselayout=20230201", "merged-bin",     "merged-lib",
    "merged-sbin",               "merged-usrsbin", "merged-varrun",
};

/// entries uses package.Entry without making this data depend on the packer.
pub fn entries(comptime Entry: type) []const Entry {
    return &.{
        .{ .path = "dev", .kind = .dir },
        .{ .path = "etc", .kind = .dir },
        .{ .path = "etc/group", .kind = .file, .mode = 0o644, .data = group },
        .{ .path = "etc/os-releas" ++
            "e", .kind = .file, .mode = 0o644, .data = "ID=wolfi\nNAME=\"Werewolf " ++
            "Linux\"\nPRETTY_NAME=\"Werewolf Linux (Wolfi-based)\"\n" ++
            "HOME_URL=\"https://github.com/werewolf-linux/werewolf\"\n" ++
            "BUG_REPORT_URL=\"https://github.com/werewolf-linux/werewolf/issues\"\n" },
        .{ .path = "etc/passwd", .kind = .file, .mode = 0o644, .data = passwd },
        .{ .path = "etc/shadow", .kind = .file, .mode = 0o600, .data = shadow },
        .{ .path = "proc", .kind = .dir },
        .{ .path = "root", .kind = .dir, .mode = 0o700 },
        .{ .path = "run", .kind = .dir },
        .{ .path = "sys", .kind = .dir },
        .{ .path = "tmp", .kind = .dir, .mode = 0o1777 },
        .{ .path = "usr", .kind = .dir },
        .{ .path = "usr/bin", .kind = .dir },
        .{ .path = "usr/lib", .kind = .dir },
        .{ .path = "usr/lib64", .kind = .link, .data = "lib" },
        .{ .path = "usr/sbin", .kind = .link, .data = "bin" },
        .{ .path = "bin", .kind = .link, .data = "usr/bin" },
        .{ .path = "lib", .kind = .link, .data = "usr/lib" },
        .{ .path = "lib64", .kind = .link, .data = "usr/lib" },
        .{ .path = "sbin", .kind = .link, .data = "usr/bin" },
        .{ .path = "var", .kind = .dir },
        .{ .path = "var/empty", .kind = .dir },
        .{ .path = "var/run", .kind = .link, .data = "../run" },
        .{ .path = "var/tmp", .kind = .dir, .mode = 0o1777 },
    };
}
