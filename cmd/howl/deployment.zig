//! deployment packs the caller's image declaration as local-NAME. Its
//! repository is signed with ~/.howl/packages.rsa; only its public key
//! reaches the image. See docs/design/manifest.md.
const std = @import("std");
const forms = @import("form");
const compose = @import("compose");
const package = @import("package");
const native = @import("build.zig");
const howl = @import("howl.zig");
const locks = @import("lock.zig");
const packages = @import("packages.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const key_name = "howl-local.rsa.pub";
pub const prefix = "usr/share/werewolf/local";
pub const Prepared = struct {
    repository: []const u8,
    key: []const u8,
    name: []const u8,
    version: []const u8,
    apk: []const u8,
    from: []const u8,
};

const Revision = struct { hash: []const u8, version: []const u8, time: u64 };

/// prepare builds a local repository before apko resolves. The package
/// holds isolated staged forms and app files; compose lays them in the
/// image, and the updater takes the next package's copies in the same way.
pub fn prepare(b: *native.B, config: forms.Node) !?Prepared {
    const from = forms.updates(b.chain).from orelse return null;
    if (!b.spec.published) return b.fail("updates.from needs published forms; omit --build", .{});
    const dir = try b.path("{s}/deployment", .{b.p.out});
    const tree = try b.path("{s}/tree", .{dir});
    try Dir.cwd().deleteTree(b.io, tree);
    var staged = try Dir.cwd().createDirPathOpen(
        b.io,
        try b.path("{s}/{s}", .{ tree, prefix }),
        .{},
    );
    defer staged.close(b.io);
    for (b.chain) |fm| {
        const from_repo = for (b.from_repo) |name| {
            if (mem.eql(u8, name, fm.name)) break true;
        } else false;
        if (!from_repo) try compose.stage(b.io, b.gpa, Dir.cwd(), fm, staged);
    }
    if (b.spec.app) |app| {
        try staged.createDirPath(b.io, "overlay");
        try b.run(
            &.{
                "cp",
                "-R",
                try b.path("{s}/.", .{app}),
                try b.path("{s}/{s}/overlay", .{ tree, prefix }),
            },
            .{},
        );
    }
    try staged.writeFile(b.io, .{ .sub_path = "form", .data = b.name });
    var deps: std.ArrayList([]const u8) = .empty;
    for (config.get("contents").?.get("packages").?.list) |p|
        try deps.append(b.gpa, p.scalar.text);
    try staged.writeFile(
        b.io,
        .{ .sub_path = "depends", .data = try mem.join(b.gpa, "\n", deps.items) },
    );
    const hash = try locks.tree(b.io, b.gpa, Dir.cwd(), tree);
    try staged.writeFile(b.io, .{ .sub_path = "inputs", .data = &hash });

    const home = howl.environ.get("HOME") orelse return b.fail(
        "no HOME for ~/.howl's signing key",
        .{},
    );
    const state = try b.path("{s}/.howl", .{home});
    try Dir.cwd().createDirPath(b.io, state);
    try Dir.cwd().setFilePermissions(b.io, state, .fromMode(0o700), .{});
    const guard = try Dir.cwd().createFile(
        b.io,
        try b.path("{s}/packages.lock", .{state}),
        .{ .truncate = false },
    );
    defer guard.close(b.io);
    try guard.lock(b.io, .exclusive);
    defer guard.unlock(b.io);
    const private = try b.path("{s}/packages.rsa", .{state});
    const public = try b.path("{s}/{s}", .{ state, key_name });
    if (Dir.cwd().access(b.io, private, .{})) |_| {} else |err| switch (err) {
        error.FileNotFound => {
            // A missing private key with a public half is a lost identity,
            // not permission to silently replace the machine's trust anchor.
            if (Dir.cwd().access(b.io, public, .{})) |_|
                return b.fail(
                    "{s}: private key lost; restore it or create a new machine",
                    .{private},
                )
            else |_| {}
            const tmp = try b.tmp(private);
            try b.run(&.{ "openssl", "genrsa", "-out", tmp, "4096" }, .{});
            try Dir.cwd().setFilePermissions(b.io, tmp, .fromMode(0o600), .{});
            try b.rename(tmp, private);
        },
        else => return err,
    }
    const pub_tmp = try b.tmp(public);
    try b.run(&.{ "openssl", "rsa", "-in", private, "-pubout", "-out", pub_tmp }, .{});
    const pem = try b.read(pub_tmp, 64 << 10);
    const previous_key = Dir.cwd().readFileAlloc(
        b.io,
        public,
        b.gpa,
        .limited(64 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => pem,
        else => return err,
    };
    if (!mem.eql(
        u8,
        previous_key,
        pem,
    )) return b.fail("{s}: public and private signing keys disagree", .{state});
    try packages.keep(b, public, pem);
    Dir.cwd().deleteFile(b.io, pub_tmp) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    var repo_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(from, &repo_hash, .{});
    const repo_id = std.fmt.bytesToHex(repo_hash, .lower);
    const repo = try b.absolute(try b.path(
        "{s}/repositories/{s}/{s}",
        .{ state, &repo_id, b.name },
    ));
    var result: Prepared = undefined;
    for (std.enums.values(howl.Arch)) |arch| {
        const arch_dir = try b.path("{s}/{t}", .{ repo, arch });
        try Dir.cwd().createDirPath(b.io, arch_dir);
        const history_path = try b.path("{s}/revisions.json", .{arch_dir});
        const history_text = Dir.cwd().readFileAlloc(
            b.io,
            history_path,
            b.gpa,
            .limited(4 << 20),
        ) catch |err| switch (err) {
            error.FileNotFound => "[]",
            else => return err,
        };
        const history = try std.json.parseFromSliceLeaky(
            []const Revision,
            b.gpa,
            history_text,
            .{},
        );
        const now: u64 = @intCast(@divTrunc(
            Io.Clock.real.now(b.io).nanoseconds,
            std.time.ns_per_s,
        ));
        const revision = chooseRevision(b.gpa, history, &hash, now) catch |err| {
            if (err == error.OlderDeclaration) try b.write(try b.path("{s}/older", .{dir}), &hash);
            return err;
        };
        const name = try b.path("local-{s}", .{b.name});
        var entries: std.ArrayList(package.Entry) = .empty;
        var root = try Dir.cwd().openDir(b.io, tree, .{ .iterate = true });
        defer root.close(b.io);
        try walk(b.io, b.gpa, root, "", &entries);
        const built = try package.pack(b.gpa, .{
            .name = name,
            .version = revision.version,
            .arch = @tagName(arch),
            .time = revision.time,
            .description = "The operator's machine " ++
                "declaration",
            .depends = deps.items,
        }, entries.items);
        const apk = try b.path("{s}/{s}-{s}.apk", .{ arch_dir, name, revision.version });
        try packages.keep(b, apk, built.bytes);
        const index_path = try b.path("{s}/APKINDEX", .{arch_dir});
        const old = Dir.cwd().readFileAlloc(b.io, index_path, b.gpa, .limited(16 << 20)) catch "";
        const index = try package.index(b.gpa, old, &.{built.stanza});
        try packages.keep(b, index_path, index);
        const member_path = try b.path("{s}/APKINDEX.member", .{arch_dir});
        try packages.keep(b, member_path, try package.indexMember(b.gpa, name, index));
        const sig = try b.path("{s}/signature", .{arch_dir});
        try b.run(
            &.{ "openssl", "dgst", "-sha256", "-sign", private, "-out", sig, member_path },
            .{},
        );
        const signed = try package.signed(
            b.gpa,
            key_name,
            try b.read(sig, 64 << 10),
            try b.read(member_path, 16 << 20),
        );
        try packages.keep(b, try b.path("{s}/APKINDEX.tar.gz", .{arch_dir}), signed);
        if (history.len == 0 or !mem.eql(u8, history[history.len - 1].hash, &hash)) {
            var all: std.ArrayList(Revision) = .empty;
            try all.appendSlice(b.gpa, history);
            try all.append(b.gpa, revision);
            try packages.keep(
                b,
                history_path,
                try std.json.Stringify.valueAlloc(b.gpa, all.items, .{ .whitespace = .indent_2 }),
            );
        }
        const prepared: Prepared = .{
            .repository = repo,
            .key = public,
            .name = name,
            .version = revision.version,
            .apk = apk,
            .from = from,
        };
        if (arch == b.spec.arch) result = prepared;
    }
    const record = try b.path("{s}/prepared.json", .{dir});
    try packages.keep(b, record, try std.json.Stringify.valueAlloc(b.gpa, result, .{}));
    return result;
}

fn chooseRevision(gpa: Allocator, history: []const Revision, hash: []const u8, now: u64) !Revision {
    if (history.len > 0) {
        const last = history[history.len - 1];
        if (mem.eql(u8, last.hash, hash)) return last;
        for (history) |r| if (mem.eql(u8, r.hash, hash)) return error.OlderDeclaration;
        const time = @max(now, last.time + 1);
        return .{ .hash = hash, .version = try package.version(gpa, time), .time = time };
    }
    return .{ .hash = hash, .version = try package.version(gpa, now), .time = now };
}

/// configure gives apko the local package and its local repository. The
/// image's metadata later substitutes the public HTTPS repository.
pub fn configure(gpa: Allocator, config: forms.Node, p: Prepared) !forms.Node {
    var contents: std.ArrayList(forms.Entry) = .empty;
    for (config.get("contents").?.map) |e| {
        if (mem.eql(u8, e.key, "packages")) {
            try contents.append(
                gpa,
                .{
                    .key = e.key,
                    .value = .{ .list = try gpa.dupe(forms.Node, &.{
                        scalar(p.name), scalar(compose.format_package),
                    }) },
                },
            );
        } else if (mem.eql(u8, e.key, "repositories") or mem.eql(u8, e.key, "keyring")) {
            const extra = if (mem.eql(u8, e.key, "repositories")) p.repository else p.key;
            var list: std.ArrayList(forms.Node) = .empty;
            try list.appendSlice(gpa, e.value.list);
            try list.append(gpa, scalar(extra));
            try contents.append(gpa, .{ .key = e.key, .value = .{ .list = list.items } });
        } else try contents.append(gpa, e);
    }
    var top: std.ArrayList(forms.Entry) = .empty;
    for (config.map) |e| try top.append(gpa, if (mem.eql(u8, e.key, "contents"))
        .{ .key = e.key, .value = .{ .map = contents.items } }
    else
        e);
    return .{ .map = top.items };
}

fn scalar(text: []const u8) forms.Node {
    return .{ .scalar = .{ .raw = text, .text = text } };
}

fn walk(
    io: Io,
    gpa: Allocator,
    dir: Dir,
    prefix_: []const u8,
    entries: *std.ArrayList(package.Entry),
) !void {
    var paths: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |e| try paths.append(gpa, try gpa.dupe(u8, e.name));
    mem.sort([]const u8, paths.items, {}, native.lessThan);
    for (paths.items) |name| {
        const path = if (prefix_.len == 0) name else try gpa.print("{s}/{s}", .{ prefix_, name });
        const st = try dir.statFile(io, name, .{ .follow_symlinks = false });
        switch (st.kind) {
            .directory => {
                try entries.append(
                    gpa,
                    .{
                        .path = path,
                        .kind = .dir,
                        .mode = @intCast(st.permissions.toMode() & 0o777),
                    },
                );
                var child = try dir.openDir(io, name, .{ .iterate = true });
                defer child.close(io);
                try walk(io, gpa, child, path, entries);
            },
            .file => try entries.append(gpa, .{
                .path = path,
                .kind = .file,
                .mode = @intCast(st.permissions.toMode() & 0o777),
                .data = try dir.readFileAlloc(io, name, gpa, .limited(1 << 30)),
            }),
            .sym_link => {
                var buf: [4096]u8 = undefined;
                const n = try dir.readLink(io, name, &buf);
                try entries.append(
                    gpa,
                    .{ .path = path, .kind = .link, .data = try gpa.dupe(u8, buf[0..n]) },
                );
            },
            else => return error.UnsupportedPackageInput,
        }
    }
}

test "revisions: a retry is identical, a changed input advances, an older declaration is refused" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const first = try chooseRevision(gpa, &.{}, "one", 100);
    const retry = try chooseRevision(gpa, &.{first}, "one", 200);
    try t.expectEqualStrings(first.version, retry.version);
    const next = try chooseRevision(gpa, &.{first}, "two", 50);
    try t.expectEqual(@as(u64, 101), next.time);
    try t.expectError(error.OlderDeclaration, chooseRevision(gpa, &.{ first, next }, "one", 300));
}

test "local package: both architectures, signed index, stable retry and people excluded" {
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    var env = std.process.Environ.Map.init(gpa);
    try env.put("HOME", root);
    try env.put("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
    howl.environ = &env;
    defer howl.environ = undefined;
    try tmp.dir.createDirPath(io, "minimal/rootfs/etc");
    try tmp.dir.writeFile(io, .{ .sub_path = "minimal/rootfs/etc/example", .data = "example" });
    try tmp.dir.writeFile(io, .{ .sub_path = "minimal/form.yam" ++
        "l", .data = "packages: [busybox]\nrepositories: [https://example.invalid]\nkeyring: " ++
        "[]\n" ++
        "users:\n  alice:\n    keys: [sk-ssh-ed25519@openssh.com AAAA]\n" ++
        "updates:\n  from: https://example.invalid/apk\n" });
    var why: howl.Why = .{};
    var steps = try @import("progress.zig").Steps.init(io, gpa, &why, .{
        .verbose = true,
        .command = "test local package",
        .log = "",
        .first = howl.start_phase,
    });
    var b = try native.prepare(io, gpa, &steps, .{
        .form = try gpa.print("{s}/minimal", .{root}),
        .arch = .aarch64,
        .build = try gpa.print("{s}/build", .{root}),
    });
    b.spec.published = true;
    var failure: forms.Failure = .{};
    const config = try compose.apko(io, gpa, Dir.cwd(), b.chain, &.{}, &failure);
    const first = (try prepare(&b, config)).?;
    const configured = try configure(gpa, config, first);
    const world = configured.get("contents").?.get("packages").?.list;
    try t.expectEqual(@as(usize, 2), world.len);
    try t.expectEqualStrings("local-minimal", world[0].scalar.text);
    try t.expectEqualStrings(compose.format_package, world[1].scalar.text);
    const pem = try b.read(first.key, 64 << 10);
    const verify = @import("apk");
    const trusted = [_]verify.Trusted{.{ .name = key_name, .key = try verify.parseKey(gpa, pem) }};
    for (std.enums.values(howl.Arch)) |arch| {
        const index = try b.read(
            try b.path("{s}/{t}/APKINDEX.tar.gz", .{ first.repository, arch }),
            16 << 20,
        );
        const records = try verify.records(gpa, &trusted, index);
        try t.expectEqual(@as(usize, 1), records.len);
        try t.expectEqualStrings("local-minimal", records[0].name);
    }
    const staged = try b.read(
        try b.path("{s}/deployment/tree/{s}/forms/minimal/form.yaml", .{ b.p.out, prefix }),
        64 << 10,
    );
    try t.expect(mem.find(u8, staged, "alice") == null);
    const again = (try prepare(&b, config)).?;
    try t.expectEqualStrings(first.version, again.version);
    try tmp.dir.writeFile(io, .{ .sub_path = "minimal/rootfs/etc/example", .data = "changed" });
    const next = (try prepare(&b, config)).?;
    try t.expect(mem.order(u8, first.version, next.version) == .lt);
    try Dir.cwd().deleteTree(io, b.p.out);
    const rebuilt = (try prepare(&b, config)).?;
    try t.expectEqualStrings(next.version, rebuilt.version);
    try tmp.dir.writeFile(io, .{ .sub_path = "minimal/rootfs/etc/example", .data = "example" });
    try t.expectError(error.OlderDeclaration, prepare(&b, config));
    _ = try steps.finish();
}
