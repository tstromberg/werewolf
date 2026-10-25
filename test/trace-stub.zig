//! trace-stub STUB_C [--sync-arm-cache] [--firmware-kernel-loader] adds
//! progress messages to the pinned systemd EFI stub's stub.c and the
//! linux.c beside it, in place, before build-tpm-stub compiles them: each
//! step of the stub, and of its kernel handover, prints before and after
//! itself on the firmware console. --sync-arm-cache also cleans and
//! invalidates the caches over the loaded kernel on arm64;
//! --firmware-kernel-loader lets the firmware load the kernel under
//! Secure Boot without shim. test/build-traced-stub.zig builds it for its
//! Linux helper. Every anchor must be found exactly as often as expected,
//! or the stub is left alone.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const Options = struct {
    sync_arm_cache: bool = false,
    firmware_kernel_loader: bool = false,
};

pub const Sources = struct { stub: []const u8, linux: []const u8 };

/// Point is a statement traced before and after, the name its messages
/// carry, and how often the pinned source has it.
const Point = struct { statement: []const u8, name: []const u8, count: usize = 1 };

const stub_points = [_]Point{
    .{
        .statement = "        process_arguments(image, loaded_image, &profile, &cmdline);",
        .name = "arguments",
    },
    .{
        .statement = "        measure_profile(profile, &parameters_measured);",
        .name = "profile",
    },
    .{
        .statement = "        measure_sections(loaded_image, sections, &sections_measured);",
        .name = "sections",
    },
    .{
        .statement = "        refresh_random_seed(loaded_image);",
        .name = "random-seed",
    },
    .{
        .statement = "        (void) prepare_boot_secret(loaded_image, " ++
            "sections + UNIFIED_SECTION_OSREL, boot_secret);",
        .name = "boot-secret",
    },
    .{
        .statement = "        settle_command_line(loaded_image, sections, " ++
            "&cmdline, &parameters_measured);",
        .name = "command-line",
    },
    .{
        .statement = "        load_all_addons(image, loaded_image, uname, " ++
            "&cmdline_addons, &dt_addons, &n_dt_addons, " ++
            "&initrd_addons, &n_initrd_addons, &ucode_addons, &n_ucode_addons);",
        .name = "addons",
    },
    .{
        .statement = "        cmdline_append_console(&cmdline);",
        .name = "console",
    },
    .{
        .statement = "        measure_smbios();",
        .name = "smbios",
    },
    .{
        .statement = "        generate_sidecar_initrds(loaded_image, initrds, " ++
            "&parameters_measured, &sysext_measured, &confext_measured);",
        .name = "sidecars",
    },
    .{
        .statement = "        generate_embedded_initrds(loaded_image, sections, initrds);",
        .name = "embedded-initrd",
    },
    .{
        .statement = "        export_pcr_variables(sections_measured, " ++
            "parameters_measured, sysext_measured, confext_measured);",
        .name = "pcr-variables",
    },
    .{
        .statement = "        err = linux_exec(image, cmdline, &kernel, &final_initrd);",
        .name = "kernel-entry",
    },
};

const linux_points = [_]Point{
    .{
        .statement = "        assert(parent_image);",
        .name = "linux-exec-entry",
    },
    .{
        .statement = "        /* When running with shim < v16",
        .name = "firmware-loader-entry",
    },
    .{
        .statement = "        err = pe_kernel_info(kernel->iov_base, kernel->iov_len, " ++
            "&entry_point, &compat_entry_point, &kernel_size_in_memory, &section_alignment);",
        .name = "kernel-info",
    },
    .{
        .statement = "        err = pe_kernel_check_no_relocation(kernel->iov_base);",
        .name = "manual-loader-entry",
    },
    .{
        .statement = "        uint8_t* loaded_kernel = " ++
            "PHYSICAL_ADDRESS_TO_POINTER(loaded_kernel_pages.addr);",
        .name = "kernel-allocated",
    },
    .{
        .statement = "        /* Patch the parent_image(_handle)",
        .name = "kernel-copy-complete",
    },
    .{
        .statement = "        err = initrd_register(initrd, &initrd_handle);",
        .name = "register-initrd",
        .count = 2,
    },
    .{
        .statement = "        log_wait();",
        .name = "log-wait",
        .count = 2,
    },
    .{
        .statement = "        err = BS->StartImage(kernel_image, NULL, NULL);",
        .name = "firmware-start-kernel",
    },
    .{
        .statement = "                err = entry(parent_image, ST);",
        .name = "manual-call-kernel",
    },
};

/// tracer is a C function named name that prints on the firmware console.
fn tracer(comptime name: []const u8) []const u8 {
    return "static void " ++ name ++ "(const char16_t *s) {\n" ++
        "        if (ST->ConOut) (void) ST->ConOut->OutputString(ST->ConOut, (char16_t *) s);\n" ++
        "}\n\n";
}

const cache_sync =
    \\
    \\#if defined(__aarch64__)
    \\static void ww_sync_kernel_code(void *base, size_t size) {
    \\        uint64_t ctr;
    \\        __asm__ __volatile__("mrs %0, ctr_el0" : "=r" (ctr));
    \\        uintptr_t first = (uintptr_t) base, last = first + size;
    \\        uintptr_t dline = 4UL << ((ctr >> 16) & 15);
    \\        uintptr_t iline = 4UL << (ctr & 15);
    \\        for (uintptr_t p = first & ~(dline - 1); p < last; p += dline)
    \\                __asm__ __volatile__("dc cvau, %0" :: "r" (p) : "memory");
    \\        __asm__ __volatile__("dsb ish" ::: "memory");
    \\        for (uintptr_t p = first & ~(iline - 1); p < last; p += iline)
    \\                __asm__ __volatile__("ic ivau, %0" :: "r" (p) : "memory");
    \\        __asm__ __volatile__("dsb ish\nisb" ::: "memory");
    \\}
    \\#endif
    \\
    \\
;

const cache_synced = "#if defined(__aarch64__)\n" ++
    "        ww_sync_kernel_code(loaded_kernel, kernel_size_in_memory);\n" ++
    "        if (ST->ConOut) (void) ST->ConOut->OutputString(ST->ConOut, " ++
    "(char16_t *) u\"ww-stub-trace: cache-sync-complete\\r\\n\");\n" ++
    "#endif\n";

const shim_required = "if (secure_boot_enabled() && (shim_loader_available() || " ++
    "(shim_loaded() && security_override_available())))";
const shim_optional = "if (secure_boot_enabled() && (shim_loader_available() || " ++
    "security_override_available()))";

/// trace is the stub's sources with every trace point added, or
/// error.MissingAnchor, naming it in why, if the sources are not the
/// pinned ones it knows.
pub fn trace(gpa: Allocator, sources: Sources, o: Options, why: *[]const u8) !Sources {
    const entry = "static EFI_STATUS run(EFI_HANDLE image) {";
    const traced_entry = comptime tracer("ww_trace") ++ entry ++
        "\n        ww_trace(u\"ww-stub-trace: entry\\r\\n\");";
    var stub = try once(gpa, sources.stub, entry, traced_entry, "run", why);
    for (stub_points) |p| stub = try around(gpa, stub, p, "ww_trace", "ww-stub-trace", why);
    const anchor = "static EFI_STATUS load_via_boot_services(";
    const traced_anchor = comptime tracer("ww_linux_trace") ++ anchor;
    var linux = try once(gpa, sources.linux, anchor, traced_anchor, "load_via_boot_services", why);
    for (linux_points) |p|
        linux = try around(gpa, linux, p, "ww_linux_trace", "ww-linux-trace", why);
    if (o.sync_arm_cache) {
        const exec = "EFI_STATUS linux_exec(";
        linux = try once(gpa, linux, exec, cache_sync ++ exec, "linux_exec", why);
        const point = "        if (entry_point > 0) {";
        linux = try once(gpa, linux, point, cache_synced ++ point, "entry_point", why);
    }
    if (o.firmware_kernel_loader)
        linux = try once(gpa, linux, shim_required, shim_optional, "shim_loader_available", why);
    return .{ .stub = stub, .linux = linux };
}

/// around marks text's every occurrence of p's statement before and
/// after; only before when it opens a comment, a block of its own.
fn around(
    gpa: Allocator,
    text: []const u8,
    p: Point,
    function: []const u8,
    prefix: []const u8,
    why: *[]const u8,
) ![]u8 {
    if (mem.count(u8, text, p.statement) != p.count) return missing(why, p.name);
    const before = try mark(gpa, function, prefix, "before", p.name);
    const after = try mark(gpa, function, prefix, "after", p.name);
    const comment = mem.startsWith(u8, mem.trimStart(u8, p.statement, " "), "/*");
    const replacement = if (comment)
        try mem.concat(gpa, u8, &.{ before, "\n", p.statement })
    else
        try mem.concat(gpa, u8, &.{ before, "\n", p.statement, "\n", after });
    return mem.replaceOwned(u8, gpa, text, p.statement, replacement);
}

/// once replaces anchor, which must occur exactly once, with with.
fn once(
    gpa: Allocator,
    text: []const u8,
    anchor: []const u8,
    with: []const u8,
    name: []const u8,
    why: *[]const u8,
) ![]u8 {
    if (mem.count(u8, text, anchor) != 1) return missing(why, name);
    return mem.replaceOwned(u8, gpa, text, anchor, with);
}

fn missing(why: *[]const u8, name: []const u8) error{MissingAnchor} {
    why.* = name;
    return error.MissingAnchor;
}

fn mark(
    gpa: Allocator,
    function: []const u8,
    prefix: []const u8,
    when: []const u8,
    name: []const u8,
) ![]const u8 {
    return gpa.print("        {s}(u\"{s}: {s}-{s}\\r\\n\");", .{ function, prefix, when, name });
}

const usage = "usage: trace-stub STUB_C [--sync-arm-cache] [--firmware-kernel-loader]";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 2) fatal("{s}", .{usage});
    var o: Options = .{};
    for (args[2..]) |a| {
        if (mem.eql(u8, a, "--sync-arm-cache")) {
            o.sync_arm_cache = true;
        } else if (mem.eql(u8, a, "--firmware-kernel-loader")) {
            o.firmware_kernel_loader = true;
        } else fatal("unknown option {s}", .{a});
    }
    const stub_path = args[1];
    const dir = std.fs.path.dirname(stub_path) orelse ".";
    const linux_path = try std.fs.path.join(gpa, &.{ dir, "linux.c" });
    const cwd = Io.Dir.cwd();
    const sources: Sources = .{
        .stub = try cwd.readFileAlloc(io, stub_path, gpa, .limited(16 << 20)),
        .linux = try cwd.readFileAlloc(io, linux_path, gpa, .limited(16 << 20)),
    };
    var why: []const u8 = "";
    const traced = trace(gpa, sources, o, &why) catch |err| switch (err) {
        error.MissingAnchor => fatal("{s}: not the pinned source: no single {s}", .{
            stub_path,
            why,
        }),
        else => |e| return e,
    };
    try cwd.writeFile(io, .{ .sub_path = stub_path, .data = traced.stub });
    try cwd.writeFile(io, .{ .sub_path = linux_path, .data = traced.linux });
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err("trace-stub: " ++ fmt, args);
    std.process.exit(1);
}

test "every trace point is added once, and an unknown source is refused" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var stub: std.ArrayList(u8) = .empty;
    try stub.appendSlice(gpa, "static EFI_STATUS run(EFI_HANDLE image) {\n");
    for (stub_points) |p| try stub.print(gpa, "{s}\n", .{p.statement});
    var linux: std.ArrayList(u8) = .empty;
    try linux.appendSlice(gpa, "static EFI_STATUS load_via_boot_services(void) {}\n");
    try linux.appendSlice(gpa, "EFI_STATUS linux_exec(void) {\n");
    for (linux_points) |p| for (0..p.count) |_| try linux.print(gpa, "{s}\n", .{p.statement});
    try linux.appendSlice(gpa, "        if (entry_point > 0) {\n" ++ shim_required ++ "\n");
    var why: []const u8 = "";
    const sources: Sources = .{ .stub = stub.items, .linux = linux.items };
    const all: Options = .{ .sync_arm_cache = true, .firmware_kernel_loader = true };
    const traced = try trace(gpa, sources, all, &why);
    const count = struct {
        fn f(text: []const u8, needle: []const u8) usize {
            return mem.count(u8, text, needle);
        }
    }.f;
    const entry = "ww_trace(u\"ww-stub-trace: entry\\r\\n\");";
    try std.testing.expectEqual(1, count(traced.stub, entry));
    try std.testing.expectEqual(1, count(traced.stub, "ww-stub-trace: before-kernel-entry\\r\\n"));
    try std.testing.expectEqual(1, count(traced.stub, "ww-stub-trace: after-kernel-entry\\r\\n"));
    try std.testing.expectEqual(2, count(traced.linux, "ww-linux-trace: before-log-wait\\r\\n"));
    try std.testing.expectEqual(1, count(traced.linux, "before-firmware-loader-entry"));
    try std.testing.expectEqual(0, count(traced.linux, "after-firmware-loader-entry"));
    try std.testing.expectEqual(1, count(traced.linux, "ww_sync_kernel_code(loaded_kernel"));
    try std.testing.expectEqual(0, count(traced.linux, "shim_loaded() &&"));
    const plain = try trace(gpa, sources, .{}, &why);
    try std.testing.expectEqual(0, count(plain.linux, "ww_sync_kernel_code"));
    const changed = try mem.replaceOwned(u8, gpa, stub.items, "        measure_smbios();\n", "");
    const without = trace(gpa, .{ .stub = changed, .linux = linux.items }, .{}, &why);
    try std.testing.expectError(error.MissingAnchor, without);
    try std.testing.expectEqualStrings("smbios", why);
    const doubled = try mem.concat(gpa, u8, &.{ linux.items, "        log_wait();\n" });
    const twice = trace(gpa, .{ .stub = stub.items, .linux = doubled }, .{}, &why);
    try std.testing.expectError(error.MissingAnchor, twice);
    try std.testing.expectEqualStrings("log-wait", why);
}
