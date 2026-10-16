const std = @import("std");

pub fn build(b: *std.Build) void {
    const filter = b.option([]const u8, "filter", "Run one fuzz target");
    const tests = b.addTest(.{
        .filters = if (filter) |value| &.{value} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzz.zig"),
            .target = b.standardTargetOptions(.{}),
            .optimize = .Debug,
        }),
    });
    const run = b.addRunArtifact(tests);
    const step = b.step("test", "Test and fuzz local log input and archive recovery");
    step.dependOn(&run.step);
    b.default_step = step;
}
