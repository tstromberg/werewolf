//! Cloud identity stays on the owner host. Provider APIs deliver storage;
//! they never install a guest agent or authorize code from an archive.
const std = @import("std");
const howl = @import("howl.zig");
const Io = std.Io;
const A = std.mem.Allocator;
const mem = std.mem;

pub fn supported(on: howl.Platform) bool {
    return on == .aws or on == .gcp or on == .azure;
}

pub fn guard(io: Io, a: A, at: []const u8) !Io.File {
    try Io.Dir.cwd().createDirPath(io, at);
    try Io.Dir.cwd().setFilePermissions(io, at, .fromMode(0o700), .{});
    const file = try Io.Dir.cwd().createFile(io, try a.print("{s}/secure.lock", .{at}), .{ .truncate = false, .permissions = .fromMode(0o600) });
    errdefer file.close(io);
    try file.lock(io, .exclusive);
    return file;
}

pub const Context = union(enum) {
    aws: struct { region: []const u8, id: []const u8, form: []const u8 = "" },
    gcp: struct { project: []const u8, zone: []const u8, id: []const u8, form: []const u8 = "" },
    azure: struct { group: []const u8, location: []const u8, id: []const u8, form: []const u8 = "" },
};

pub const Machine = struct {
    id: []const u8,
    form: []const u8,
    running: bool,
    disk: []const u8,
};

pub fn capture(io: Io, a: A, name: []const u8, place: Context) !void {
    const on: howl.Platform = switch (place) {
        .aws => .aws,
        .gcp => .gcp,
        .azure => .azure,
    };
    const path = try a.print("{s}/authority/profile.json", .{try howl.machineDir(a, name)});
    var profile = try @import("local-secure.zig").parseProfile(a, try Io.Dir.cwd().readFileAlloc(io, path, a, .limited(256 << 10)));
    if (profile.provider != on) return error.TransferProvider;
    var context = place;
    const machine = try describe(io, a, name, context, false);
    const form = (profile.local orelse profile.spec).form;
    const expected = if (on == .gcp) std.fs.path.basename(mem.trimEnd(u8, form, "/")) else form;
    if (!mem.eql(u8, machine.form, expected) or machine.id.len == 0) return error.TransferMachineIdentity;
    switch (context) {
        inline else => |*c| {
            c.id = machine.id;
            c.form = machine.form;
        },
    }
    profile.cloud = context;
    try @import("data-image.zig").replaceRecord(io, a, path, try std.json.Stringify.valueAlloc(a, profile, .{}));
}

pub fn state(io: Io, a: A, name: []const u8, context: Context) !Machine {
    const machine = try describe(io, a, name, context, true);
    const id = switch (context) {
        inline else => |c| c.id,
    };
    const form = switch (context) {
        inline else => |c| c.form,
    };
    if (id.len == 0 or form.len == 0 or !mem.eql(u8, id, machine.id) or !mem.eql(u8, form, machine.form)) return error.TransferMachineIdentity;
    return machine;
}

pub fn load(io: Io, a: A, at: []const u8, on: howl.Platform) !Context {
    return try recorded(io, a, at, on) orelse error.TransferMachineIdentity;
}

pub fn recorded(io: Io, a: A, at: []const u8, on: howl.Platform) !?Context {
    if (!supported(on)) return error.TransferProvider;
    const bytes = Io.Dir.cwd().readFileAlloc(io, try a.print("{s}/authority/profile.json", .{at}), a, .limited(256 << 10)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const profile = try @import("local-secure.zig").parseProfile(a, bytes);
    if (profile.provider != on) return error.TransferMachineIdentity;
    const context = profile.cloud orelse return null;
    if (!mem.eql(u8, @tagName(context), @tagName(on))) return error.TransferMachineIdentity;
    return context;
}

pub fn address(io: Io, a: A, name: []const u8, context: Context) ![]const u8 {
    _ = try state(io, a, name, context);
    const host = switch (context) {
        .aws => |c| @import("aws.zig").address(io, a, .{ .region = c.region }, c.id),
        .gcp => |c| @import("gcp.zig").address(io, a, .{ .project = c.project, .zone = c.zone }, name),
        .azure => |c| @import("azure.zig").address(io, a, .{ .group = c.group, .location = c.location }, name),
    } orelse return error.TransferSshAddress;
    if (!howl.isIp4(host)) return error.TransferSshAddress;
    return host;
}

fn describe(io: Io, a: A, name: []const u8, context: Context, power: bool) !Machine {
    const argv: []const []const u8 = switch (context) {
        .aws => |c| &.{ "aws", "--region", c.region, "--output", "json", "--no-cli-pager", "ec2", "describe-instances", "--filters", try a.print("Name=tag:Name,Values={s}", .{name}), "Name=instance-state-name,Values=pending,running,stopping,stopped" },
        .gcp => |c| &.{ "gcloud", "--quiet", "--project", c.project, "compute", "instances", "describe", name, "--zone", c.zone, "--format=json(id,status,labels,disks)" },
        .azure => |c| &.{ "az", "vm", "show", "-g", c.group, "-n", name, "--show-details", "--query", "{id:vmId,status:powerState,labels:tags,disk:storageProfile.osDisk.managedDisk.id}", "-o", "json" },
    };
    const result = try std.process.run(a, io, .{ .argv = argv, .stdout_limit = .limited(64 << 10), .stderr_limit = .limited(4096) });
    if (!result.term.success()) return error.TransferMachineState;
    if (context == .aws) return parseAws(a, result.stdout, power);
    return parseMachine(a, result.stdout, std.meta.activeTag(context) == .gcp, power);
}

fn parseAws(a: A, bytes: []const u8, power: bool) !Machine {
    const Response = struct {
        Reservations: []const struct {
            Instances: []const struct {
                InstanceId: []const u8,
                State: struct { Name: []const u8 },
                RootDeviceName: []const u8,
                Tags: []const struct { Key: []const u8, Value: []const u8 } = &.{},
                BlockDeviceMappings: []const struct { DeviceName: []const u8, Ebs: ?struct { VolumeId: []const u8, Status: []const u8 } = null },
            },
        },
    };
    const response = try std.json.parseFromSliceLeaky(Response, a, bytes, .{ .ignore_unknown_fields = true });
    var found: ?Machine = null;
    for (response.Reservations) |reservation| for (reservation.Instances) |vm| {
        if (found != null or vm.InstanceId.len == 0) return error.TransferMachineIdentity;
        const running = if (!power) false else if (mem.eql(u8, vm.State.Name, "running")) true else if (mem.eql(u8, vm.State.Name, "stopped")) false else return error.TransferMachineState;
        var form: ?[]const u8 = null;
        for (vm.Tags) |tag| if (mem.eql(u8, tag.Key, howl.form_tag)) {
            if (form != null or tag.Value.len == 0) return error.TransferMachineIdentity;
            form = tag.Value;
        };
        var disk: ?[]const u8 = null;
        for (vm.BlockDeviceMappings) |mapping| if (mem.eql(u8, mapping.DeviceName, vm.RootDeviceName)) {
            if (disk != null) return error.TransferStorageState;
            const ebs = mapping.Ebs orelse return error.TransferStorageState;
            if (!mem.eql(u8, ebs.Status, "attached") or ebs.VolumeId.len == 0) return error.TransferStorageState;
            disk = ebs.VolumeId;
        };
        found = .{ .id = vm.InstanceId, .form = form orelse return error.TransferMachineIdentity, .running = running, .disk = disk orelse return error.TransferStorageState };
    };
    return found orelse error.TransferMachineIdentity;
}

pub fn parse(a: A, bytes: []const u8, gcp: bool) !Machine {
    return parseMachine(a, bytes, gcp, true);
}

fn parseMachine(a: A, bytes: []const u8, gcp: bool, power: bool) !Machine {
    const value = try std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{});
    if (value != .object) return error.TransferMachineState;
    const object = value.object;
    const id = try string(object.get("id"));
    const labels = object.get("labels") orelse return error.TransferMachineIdentity;
    if (labels != .object) return error.TransferMachineIdentity;
    const form = try string(labels.object.get(howl.form_tag));
    const status = if (power) try string(object.get("status")) else "";
    const running = if (!power) false else if (mem.eql(u8, status, if (gcp) "RUNNING" else "VM running")) true else if (mem.eql(u8, status, if (gcp) "TERMINATED" else "VM deallocated") or (!gcp and mem.eql(u8, status, "VM stopped"))) false else return error.TransferMachineState;
    var disk: ?[]const u8 = null;
    if (gcp) {
        const disks = object.get("disks") orelse return error.TransferStorageState;
        if (disks != .array or disks.array.items.len > 64) return error.TransferStorageState;
        for (disks.array.items) |entry| {
            if (entry != .object) return error.TransferStorageState;
            const boot = entry.object.get("boot") orelse continue;
            if (boot != .bool) return error.TransferStorageState;
            if (!boot.bool) continue;
            if (disk != null) return error.TransferStorageState;
            disk = try string(entry.object.get("source"));
        }
    } else disk = try string(object.get("disk"));
    return .{ .id = id, .form = form, .running = running, .disk = disk orelse return error.TransferStorageState };
}

fn string(value: ?std.json.Value) ![]const u8 {
    const v = value orelse return error.TransferMachineState;
    if (v != .string or v.string.len == 0 or v.string.len > 4096) return error.TransferMachineState;
    return v.string;
}

test "cloud power state is authoritative and ambiguous boot storage refuses" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const gcp = "{\"id\":\"123\",\"status\":\"TERMINATED\",\"labels\":{\"werewolf-form\":\"plex\"},\"disks\":[{\"boot\":true,\"source\":\"disk\"}]}";
    try t.expect(!(try parse(a, gcp, true)).running);
    const azure = "{\"id\":\"uuid\",\"status\":\"VM running\",\"labels\":{\"werewolf-form\":\"plex\"},\"disk\":\"disk\"}";
    try t.expect((try parse(a, azure, false)).running);
    try t.expectError(error.TransferMachineState, parse(a, "{}", true));
    try t.expectError(error.TransferMachineState, parse(a, "{\"id\":\"1\",\"status\":\"STAGING\",\"labels\":{\"werewolf-form\":\"plex\"}}", true));
    try t.expectError(error.TransferStorageState, parse(a, "{\"id\":\"1\",\"status\":\"RUNNING\",\"labels\":{\"werewolf-form\":\"plex\"},\"disks\":[{\"boot\":true,\"source\":\"a\"},{\"boot\":true,\"source\":\"b\"}]}", true));
}

test "cloud context is recorded locally and cannot change provider" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const at = try tmp.dir.realPathFileAlloc(t.io, ".", a);
    try t.expect(try recorded(t.io, a, at, .gcp) == null);
    try t.expectError(error.TransferMachineIdentity, load(t.io, a, at, .gcp));
    try tmp.dir.createDir(t.io, "authority", .fromMode(0o700));
    var profile: @import("local-secure.zig").Profile = .{
        .spec = .{ .form = "plex", .arch = .aarch64 },
        .managed = false,
        .provider = .gcp,
        .cloud = .{ .gcp = .{ .project = "owner-project", .zone = "owner-zone", .id = "123", .form = "plex" } },
    };
    try tmp.dir.writeFile(t.io, .{ .sub_path = "authority/profile.json", .data = try std.json.Stringify.valueAlloc(a, profile, .{}) });
    const context = try load(t.io, a, at, .gcp);
    try t.expectEqualStrings("owner-project", context.gcp.project);
    try t.expectEqualStrings("123", context.gcp.id);
    try t.expectError(error.TransferMachineIdentity, load(t.io, a, at, .azure));
    profile.cloud = .{ .azure = .{ .group = "rg", .location = "westus", .id = "uuid", .form = "plex" } };
    try tmp.dir.writeFile(t.io, .{ .sub_path = "authority/profile.json", .data = try std.json.Stringify.valueAlloc(a, profile, .{}) });
    try t.expectError(error.TransferMachineIdentity, load(t.io, a, at, .gcp));
}
