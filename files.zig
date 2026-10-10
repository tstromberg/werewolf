//! files are this tree's files that howl puts in what it builds, embedded,
//! so a howl binary builds with no checkout beside it. See
//! cmd/howl/README.md.

/// tiers_pub is the key an image checks the CVE tiers feed with;
/// advisories are werewolf's own fixes (docs/releases.md).
pub const tiers_pub = @embedFile("release/tiers.pub");
pub const advisories = @embedFile("release/advisories");

/// posture_known are the posture checks every form of a kind fails.
pub const posture_known = @embedFile("test/posture-known");

/// stage0_mtree is stage0's device nodes.
pub const stage0_mtree = @embedFile("cmd/stage0/stage0.mtree");

/// boot are the apko configs of the kernel and the boot loader, with the
/// Alpine keys kernel.yaml names, each by its path under boot/.
pub const boot = [_]struct { path: []const u8, data: []const u8 }{
    .{ .path = "kernel.yaml", .data = @embedFile("boot/kernel.yaml") },
    .{ .path = "boot.yaml", .data = @embedFile("boot/boot.yaml") },
    .{
        .path = "alpine-keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
        .data = @embedFile("boot/alpine-keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"),
    },
    .{
        .path = "alpine-keys/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub",
        .data = @embedFile("boot/alpine-keys/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub"),
    },
};
