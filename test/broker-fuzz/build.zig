const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const module = b.createModule(.{
        .root_source_file = b.path("fuzz.zig"),
        .target = target,
        .optimize = .Debug,
    });
    module.addImport(
        "broker",
        b.createModule(.{ .root_source_file = b.path("../../lib/broker.zig"), .target = target }),
    );
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    const step = b.step("test", "Fuzz broker wire parsers without privileged operations");
    step.dependOn(&run.step);
    b.default_step = step;
}
