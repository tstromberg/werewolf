const std = @import("std");

pub fn build(b: *std.Build) void {
    const filter = b.option([]const u8, "filter", "Run one fuzz target");
    const target = b.standardTargetOptions(.{});
    const seal = b.createModule(.{
        .root_source_file = b.path("../../lib/seal.zig"),
        .target = target,
    });
    const sandbox = b.createModule(.{
        .root_source_file = b.path("../../lib/sandbox.zig"),
        .target = target,
        .imports = &.{.{ .name = "seal", .module = seal }},
    });
    const network = b.createModule(.{
        .root_source_file = b.path("../../lib/network.zig"),
        .target = target,
    });
    const net_rule = b.createModule(.{
        .root_source_file = b.path("../../lib/net-rule.zig"),
        .target = target,
        .imports = &.{.{ .name = "sandbox", .module = sandbox }},
    });
    const dns = b.createModule(.{
        .root_source_file = b.path("../../lib/dns.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "network", .module = network },
            .{ .name = "net-rule", .module = net_rule },
            .{ .name = "sandbox", .module = sandbox },
        },
    });
    const tests = b.addTest(.{
        .filters = if (filter) |value| &.{value} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzz.zig"),
            .target = target,
            .optimize = .Debug,
            .imports = &.{
                .{ .name = "dns", .module = dns },
                .{ .name = "network", .module = network },
            },
        }),
    });
    const run = b.addRunArtifact(tests);
    const step = b.step("test", "Test and fuzz DNS messages and lookup grants");
    step.dependOn(&run.step);
    b.default_step = step;
}
