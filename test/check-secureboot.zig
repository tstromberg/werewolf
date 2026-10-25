//! check-secureboot QEMU... builds prod as a natively signed disk, checks
//! the disk holds the UKI it signed and that the UKI carries stage0,
//! enrolls the boot certificate, and boots it: posture must fail exactly
//! what a Secure Boot release without IPE or a TPM fails, and the console
//! must show Secure Boot enforced, only the image's signer trusted and
//! slot a verified. The same disk with its UKI changed must be refused by
//! the firmware (make check-secureboot).

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;
const Why = host.check.Why;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(
        init,
        "secureboot",
    ) catch |err| std.process.fatal("check-secureboot: {t}", .{err});
    c.finish(run(&c));
}

fn need(c: *host.Check, name: []const u8) ![]const u8 {
    return c.env.get(name) orelse c.fail("{s} is not set", .{name});
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const arch = try need(c, "ARCH");
    try c.setWork(try std.fs.path.join(gpa, &.{ try need(c, "CHECK"), "secureboot" }));
    const key = try Io.Dir.cwd().realPathFileAlloc(io, try need(c, "BOOT_KEY"), gpa);
    const cert = try Io.Dir.cwd().realPathFileAlloc(io, try need(c, "BOOT_CRT"), gpa);
    const howl = try Io.Dir.cwd().realPathFileAlloc(io, try need(c, "HOWL"), gpa);
    const arm = mem.eql(u8, arch, "aarch64");

    const release = try c.path("release");
    const build = try c.path("build");
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(gpa, &.{
        howl,                "_build",        "--with",  "prod",
        "--arch",            arch,            "--build", build,
        "--disable=ipe,tpm", "--boot-key",    key,       "--boot-cert",
        cert,                "--boot-native",
    });
    if (c.env.get("KERNEL_ROOTFS")) |rootfs| try args.appendSlice(
        gpa,
        &.{ "--kernel-rootfs", rootfs },
    );
    try args.append(gpa, "qcow2");
    _ = try c.must(args.items, "build", .{ .timeout = .fromSeconds(7200) });
    try host.provider.exportRelease(io, gpa, try c.path("build/prod"), "prod", arch, release);
    const uki = try gpa.print("{s}/prod-{s}-uki", .{ release, arch });
    const stage0 = try gpa.print("{s}/prod-{s}-stage0.zst", .{ release, arch });
    var why: Why = .{};
    host.evidence.nativeInitrd(
        try Io.Dir.cwd().readFileAlloc(io, uki, gpa, .unlimited),
        try Io.Dir.cwd().readFileAlloc(io, stage0, gpa, .unlimited),
        &why,
    ) catch return c.fail("{s}", .{why.text});
    const uki_digest = try host.check.digest(io, uki);
    const disk = try gpa.print("{s}/prod-{s}-disk.qcow2", .{ release, arch });
    _ = try c.must(
        &.{ "sh", "tools/verify-boot-disk", arch, disk, cert, c.work },
        "verify-disk",
        .{},
    );
    const enrolled = try c.path("enrolled");
    _ = try c.must(&.{ "sh", "tools/enroll-boot", arch, cert, enrolled }, "enroll", .{});
    const raw = try c.path("disk.raw");
    _ = try c.must(&.{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, raw }, "raw", .{});
    const installed = try c.path("installed.efi");
    Io.Dir.cwd().deleteFile(io, installed) catch {};
    const esp = try gpa.print("{s}@@1048576", .{raw});
    _ = try c.must(&.{ "mcopy", "-i", esp, "::/werewolf/a/uki.efi", installed }, "extract", .{});
    if (!mem.eql(u8, &try host.check.digest(io, installed), &uki_digest))
        return c.fail("the disk's UKI is not the signed release's", .{});

    var qemu: std.ArrayList([]const u8) = .empty;
    for (c.args[1..], 0..) |a, i| try qemu.append(gpa, if (i > 0 and mem.eql(u8, c.args[i], "-M"))
        (if (arm) "virt" else "q35,smm=on")
    else
        a);
    if (!arm) try qemu.appendSlice(
        gpa,
        &.{ "-global", "driver=cfi.pflash01,property=secure,value=on" },
    );
    try boot(c, qemu.items, enrolled, raw, "boot", false);
    var data = try Io.Dir.cwd().readFileAlloc(io, installed, gpa, .unlimited);
    data[data.len / 2] ^= 1;
    const changed = try c.path("tampered.efi");
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = changed, .data = data });
    _ = try c.must(&.{ "mcopy", "-o", "-i", esp, changed, "::/werewolf/a/uki.efi" }, "tamper", .{});
    try boot(c, qemu.items, enrolled, raw, "refused", true);
    c.say(
        "pass   secureboot: native disk contains the signed UKI; enrolled boot passes posture; " ++
            "tampered UKI refused",
        .{},
    );
}

/// Judge decides a firmware boot from its console: an enrolled release
/// must reach posture as Secure Boot without IPE or a TPM; a refused one
/// must be denied before anything hands over.
const Judge = struct {
    c: *host.Check,
    refused: bool,
    scratch: *std.heap.ArenaAllocator,

    pub fn done(j: Judge, console: []const u8) !bool {
        if (j.refused) {
            if (mem.find(
                u8,
                console,
                "up in ",
            ) != null) return j.c.fail("tampered UKI handed over", .{});
            return std.ascii.findIgnoreCase(console, "access denied") != null;
        }
        _ = j.scratch.reset(.retain_capacity);
        const failures = try host.evidence.postureFailures(
            j.scratch.allocator(),
            console,
        ) orelse return false;
        // This fixture tests Secure Boot without IPE or a TPM.
        const expected = [_][]const u8{ "boot-ipe-enforced", "boot-rollback-protected" };
        if (!host.evidence.sameSet(failures, &expected))
            return j.c.fail(
                "posture failed {s}, not exactly the missing IPE and TPM",
                .{try mem.join(j.c.gpa, ",", failures)},
            );
        for ([_][]const u8{
            "Secure Boot enforced outside setup mode",
            "Secure Boot admits only this image's signer",
            "native UKI selected slot a",
        }) |line| if (mem.find(
            u8,
            console,
            line,
        ) == null) return j.c.fail("the console never said: {s}", .{line});
        if (!verifiedSlotA(console)) return j.c.fail(
            "the console never said slot a was verified",
            .{},
        );
        return true;
    }
};

/// verifiedSlotA is whether a console line says "slot a:" and then, on the
/// same line, "verified".
fn verifiedSlotA(console: []const u8) bool {
    var from: usize = 0;
    while (mem.findPos(u8, console, from, "slot a:")) |at| : (from = at + 1) {
        const end = mem.findAnyPos(u8, console, at, "\r\n") orelse console.len;
        if (mem.find(u8, console[at..end], "verified") != null) return true;
    }
    return false;
}

fn boot(
    c: *host.Check,
    qemu: []const []const u8,
    enrolled: []const u8,
    raw: []const u8,
    label: []const u8,
    refused: bool,
) !void {
    const io = c.io;
    const gpa = c.gpa;
    const variables = try c.path("run.fd");
    try Io.Dir.cwd().copyFile(
        try gpa.print("{s}/vars.fd", .{enrolled}),
        .cwd(),
        variables,
        io,
        .{},
    );
    // AAVMF cannot log a rejected boot once its flash writes are refused,
    // so a refused boot gets a writable clone; the successful boot proves
    // immutable enrollment and checks the digest.
    const arm = mem.eql(u8, c.env.get("ARCH").?, "aarch64");
    const frozen = arm and !refused;
    const before = try host.check.digest(io, variables);
    const argv = try mem.concat(gpa, []const u8, &.{ qemu, &.{
        "-drive",  try gpa.print("if=pflash,format=raw,readonly=on,file={s}/code.fd", .{enrolled}),
        "-drive",
        try gpa.print(
            "if=pflash,format=raw,{s}file={s}",
            .{ if (frozen) "readonly=on," else "", variables },
        ),
        "-drive",  try gpa.print("format=raw,if=virtio,file={s}", .{raw}),
        "-netdev", "user,id=n0",
        "-device", "virtio-net-pci,netdev=n0,romfile=",
    } });
    const log = try c.path(try gpa.print("{s}.log", .{label}));
    var m: host.qemu.Machine = undefined;
    try m.start(io, gpa, argv, .{ .log = log, .environ_map = &c.env });
    var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer scratch.deinit();
    const outcome = m.until(
        host.qemu.after(io, 300),
        Judge{ .c = c, .refused = refused, .scratch = &scratch },
    );
    m.stop(.fromSeconds(30));
    outcome catch |err| switch (err) {
        error.CheckFailed => return err,
        error.MachineExited,
        error.Timeout,
        => return c.fail("no expected firmware outcome: {s}; QEMU {s}; see {s}", .{
            label, if (m.term) |t| try gpa.print("{f}", .{t}) else "running", log,
        }),
        else => |e| return e,
    };
    if (frozen and !mem.eql(u8, &try host.check.digest(io, variables), &before))
        return c.fail("immutable Arm enrollment changed during boot", .{});
}

test "verifiedSlotA looks on slot a's own line" {
    try std.testing.expect(verifiedSlotA("stage0: slot a: root.erofs, read-only, verified\r\n"));
    try std.testing.expect(!verifiedSlotA("stage0: slot a: root.erofs\r\nverified\r\n"));
    try std.testing.expect(!verifiedSlotA("stage0: slot b: verified\n"));
}
