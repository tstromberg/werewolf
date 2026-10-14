//! Answer RabbitMQ's two OS probes without interpreting shell commands.
//! /bin/sh names this native program inside the broker image alone.
const std = @import("std");
const linux = std.os.linux;

const Mode = enum { pagesize, disk };

pub fn main(init: std.process.Init.Minimal) void {
    const args = init.args.vector;
    if (args.len != 3) refuse();
    const mode = probeMode(std.mem.span(args[1]), std.mem.span(args[2])) orelse refuse();
    var input: [2048]u8 = undefined;
    var used: usize = 0;
    while (true) {
        if (used == input.len) refuse();
        const n = linux.read(0, input[used..].ptr, input.len - used);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS) refuse();
        if (n == 0) return;
        used += n;
        switch (mode) {
            .pagesize => {
                if (std.mem.findScalar(u8, input[0..used], 4) == null) continue;
                if (!pageRequest(input[0..used])) refuse();
                var buf: [64]u8 = undefined;
                const output = std.mem.print(&buf, "{d}\n\x04\n", .{
                    linux.getauxval(std.elf.AT.PAGESZ),
                }) catch refuse();
                write(output);
                return;
            },
            .disk => {
                while (std.mem.findScalar(u8, input[0..used], '\n')) |end| {
                    const line = input[0..end];
                    if (line.len > 0) {
                        if (!diskRequest(line)) refuse();
                        disk();
                    }
                    const left = used - end - 1;
                    @memmove(input[0..left], input[end + 1 .. used]);
                    used = left;
                }
            },
        }
    }
}

fn probeMode(option: []const u8, argument: []const u8) ?Mode {
    if (std.mem.eql(u8, option, "-s")) {
        if (std.mem.eql(u8, argument, "unix:cmd")) return .pagesize;
        if (std.mem.eql(u8, argument, "rabbit_disk_monitor")) return .disk;
    }
    // open_port({spawn, Command}) adds this fixed shell indirection.
    // Recognize it as the same protocol, without executing its text.
    if (std.mem.eql(u8, option, "-c")) {
        for ([_][]const u8{ "/bin/sh -s unix:cmd", "exec /bin/sh -s unix:cmd" }) |command|
            if (std.mem.eql(u8, argument, command)) return .pagesize;
    }
    return null;
}

fn pageRequest(input: []const u8) bool {
    return std.mem.eql(u8, input, "(getconf PAGESIZE\n) </dev/null; echo \"\x04\"\n");
}

fn diskRequest(input: []const u8) bool {
    const prefix = "/usr/bin/df -kP '";
    const suffix = "' < /dev/null; echo \"\r\"";
    if (!std.mem.startsWith(u8, input, prefix) or !std.mem.endsWith(u8, input, suffix))
        return false;
    const path = input[prefix.len .. input.len - suffix.len];
    if (!std.mem.startsWith(u8, path, "/data/") or std.mem.find(u8, path, "..") != null)
        return false;
    for (path) |c| if (!std.ascii.isAlphanumeric(c) and
        std.mem.findScalar(u8, "/@._-", c) == null) return false;
    return true;
}

// Linux's 64-bit statfs layout, used by both architectures this form ships.
const Statfs = extern struct {
    kind: isize,
    block_size: isize,
    blocks: u64,
    free_blocks: u64,
    available: u64,
    files: u64,
    free_files: u64,
    fsid: [2]i32,
    name_length: isize,
    fragment_size: isize,
    flags: isize,
    spare: [4]isize,
};

fn disk() void {
    var stats: Statfs = undefined;
    const rc = linux.syscall2(
        .statfs,
        @intFromPtr(@as([*:0]const u8, "/data")),
        @intFromPtr(&stats),
    );
    if (linux.errno(rc) != .SUCCESS or stats.block_size <= 0) refuse();
    const kb = @as(u64, @intCast(stats.block_size)) / 1024;
    var buf: [256]u8 = undefined;
    const output = std.mem.print(
        &buf,
        "Filesystem 1K-blocks Used Available Use% Mounted on\n" ++
            "werewolf-data {d} {d} {d} 0% /data\n\r\n",
        .{ stats.blocks * kb, (stats.blocks - stats.free_blocks) * kb, stats.available * kb },
    ) catch refuse();
    write(output);
}

fn write(text: []const u8) void {
    var left = text;
    while (left.len > 0) {
        const n = linux.write(1, left.ptr, left.len);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) refuse();
        left = left[n..];
    }
}

fn refuse() noreturn {
    const message = "rabbitmq-os-probe: unsupported OS probe\n";
    _ = linux.write(2, message.ptr, message.len);
    linux.exit_group(126);
}

test "OS probe requests cannot execute commands or inspect other directories" {
    try std.testing.expectEqual(Mode.pagesize, probeMode("-c", "exec /bin/sh -s unix:cmd").?);
    try std.testing.expect(probeMode("-c", "exec /bin/sh -s unix:cmd; id") == null);
    try std.testing.expect(pageRequest("(getconf PAGESIZE\n) </dev/null; echo \"\x04\"\n"));
    try std.testing.expect(!pageRequest("(getconf PAGESIZE; id\n) </dev/null; echo \"\x04\"\n"));
    try std.testing.expect(
        diskRequest("/usr/bin/df -kP '/data/mnesia/rabbit@localhost' < /dev/null; echo \"\r\""),
    );
    try std.testing.expect(!diskRequest("/usr/bin/df -kP '/etc' < /dev/null; echo \"\r\""));
    try std.testing.expect(!diskRequest("/usr/bin/df -kP '/data/../etc' < /dev/null; echo \"\r\""));
    try std.testing.expect(!diskRequest("/usr/bin/df -kP '/data/a'; id; echo \"\r\""));
}
