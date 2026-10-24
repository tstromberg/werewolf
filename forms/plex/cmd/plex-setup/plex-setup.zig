const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const mem = std.mem;
const Io = std.Io;
const Dir = Io.Dir;
const jobs = "/run/svc/plex-transcode/jobs";

pub fn main(init: std.process.Init) void {
    setup(init.io, init.arena.allocator(), init.minimal.environ) catch |err| {
        std.debug.print("plex-setup: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn setup(io: Io, a: mem.Allocator, environ: std.process.Environ) !void {
    const root = "/data/svc/plex";
    const token_text = try Dir.cwd().readFileAlloc(
        io,
        "/run/svc/plex/plex-token",
        a,
        .limited(4096),
    );
    const token = mem.trim(u8, token_text, "\r\n");
    const domain = try environ.getAlloc(a, "PLEX_DOMAIN");
    if (domain.len == 0 or domain.len > 253) return error.BadDomain;
    for (domain) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and
        c != '.') return error.BadDomain;
    if (token.len < 16) return error.BadToken;
    for (token) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and
        c != '_') return error.BadToken;
    try Dir.cwd().createDirPath(io, root ++ "/Plex Media Server");
    var random: [16]u8 = undefined;
    if (try sandbox.sys(
        linux.getrandom(&random, random.len, 0),
        "machine identifier",
    ) != random.len)
        return error.ShortRandom;
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    const id = std.fmt.bytesToHex(random, .lower);
    // CodecManager's device id is mutable data, not code. Its fixed link
    // in the immutable codec tree points here; create it before Plex starts
    // so the manager never needs its adjacent atomic temporary file.
    const uuid = try a.print(
        "{s}-{s}-{s}-{s}-{s}",
        .{ id[0..8], id[8..12], id[12..16], id[16..20], id[20..32] },
    );
    Dir.cwd().writeFile(io, .{ .sub_path = root ++ "/codec-device-id", .data = uuid, .flags = .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    } }) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const prefs = root ++ "/Plex Media Server/Preferences.xml";
    if (Dir.cwd().access(io, prefs, .{})) return else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    var digest: [20]u8 = undefined;
    var hash = std.crypto.hash.Sha1.init(.{});
    hash.update(&id);
    hash.update("- Plex Media Server");
    hash.final(&digest);
    const processed = std.fmt.bytesToHex(digest, .lower);
    const xml = try a.print(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Preferences AcceptedEULA=\"1\" " ++
            "MachineIdentifier=\"{s}\" ProcessedMachineIdentifier=\"{s}\" " ++
            "PlexOnlineToken=\"{s}\" " ++
            "FriendlyName=\"Werewolf Plex\" GdmEnabled=\"0\" DlnaEnabled=\"0\" EnableIPv6=\"0\" " ++
            "EnableRelay=\"0\" PublishServerOnPlexOnlineKey=\"1\" allowedNetworks=\"\" " ++
            "customConnections=\"https://{s}\" " ++
            "ManualPortMappingMode=\"1\" ManualPortMappingPort=\"443\" " ++
            "sendCrashReports=\"0\" TranscoderTempDirectory=\"" ++ jobs ++ "\"/>\n",
        .{ id, processed, token, domain },
    );
    try Dir.cwd().writeFile(
        io,
        .{
            .sub_path = prefs,
            .data = xml,
            .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) },
        },
    );
}
