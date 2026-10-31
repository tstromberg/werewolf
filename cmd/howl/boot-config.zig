const std = @import("std");
const forms = @import("form");
const howl = @import("howl.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Definition = struct {
    form: []const u8,
    interface: howl.Interface,
    ports: []const u16,
    dhcp: bool,
    ssh: enum { disabled, security_keys, files },
    lima_managed: bool,
    /// Read compatibility for signed images published before archive transfer.
    /// This field grants no operation and is never consulted at runtime.
    imports: []const []const u8 = &.{},
};

/// Present only during authenticated downloaded deployment; source builds use their form tree.
pub var current: ?Definition = null;

pub fn forForm(form: []const u8) ?Definition {
    const definition = current orelse return null;
    return if (std.mem.eql(u8, definition.form, form)) definition else null;
}

pub fn derive(
    io: Io,
    gpa: Allocator,
    ref: []const u8,
    name: []const u8,
    why: *howl.Why,
) !Definition {
    const chain = try howl.chain(io, gpa, ref, why);
    return .{
        .form = name,
        .interface = try howl.formInterface(io, gpa, ref, why),
        .ports = try howl.listens(io, gpa, ref, why),
        .dhcp = try howl.hasDhcp(io, gpa, ref, why),
        .ssh = if (!forms.runsSshd(chain))
            .disabled
        else if (try forms.takesKeyFiles(gpa, chain))
            .files
        else
            .security_keys,
        .lima_managed = try @import("local.zig").limaManages(io, gpa, ref, false, why),
    };
}

pub fn check(definition: Definition, form: []const u8) !void {
    if (!std.mem.eql(u8, definition.form, form) or definition.ports.len > 64 or
        definition.interface.files.len > 256 or definition.interface.settings.len > 256)
        return error.BadDeploymentDefinition;
    for (definition.ports, 0..) |port, i| {
        if (port == 0) return error.BadDeploymentDefinition;
        for (definition.ports[0..i]) |previous|
            if (port == previous) return error.BadDeploymentDefinition;
    }
    if (definition.lima_managed and
        definition.ssh == .disabled) return error.BadDeploymentDefinition;
    for (definition.interface.files) |file| {
        if (!howl.isTarName(file.path) or file.flag.len == 0 or file.service.len == 0)
            return error.BadDeploymentDefinition;
    }
    for (definition.interface.settings) |setting| if (!howl.isTarName(setting.path) or
        setting.service.len == 0)
        return error.BadDeploymentDefinition;
}

test "signed deployment identity refuses form substitution, bad paths and ambiguous ports" {
    const t = std.testing;
    const valid: Definition = .{
        .form = "playground",
        .interface = .{ .files = &.{}, .settings = &.{} },
        .ports = &.{22},
        .dhcp = true,
        .ssh = .files,
        .lima_managed = true,
    };
    try check(valid, "playground");
    try t.expectError(error.BadDeploymentDefinition, check(valid, "prod"));
    var changed = valid;
    changed.ports = &.{ 22, 22 };
    try t.expectError(error.BadDeploymentDefinition, check(changed, "playground"));
    changed = valid;
    changed.interface.files = &.{.{ .flag = "key", .path = "../authority/key", .service = "sshd" }};
    try t.expectError(error.BadDeploymentDefinition, check(changed, "playground"));
}
