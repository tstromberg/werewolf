//! files are this tree's files that howl puts in what it builds, embedded,
//! so a howl binary builds with no checkout beside it. See
//! cmd/howl/README.md.

/// tiers_pub is the key an image checks the CVE tiers feed with;
/// advisories are werewolf's own fixes (docs/releases.md).
pub const tiers_pub = @embedFile("release/tiers.pub");
pub const advisories = @embedFile("release/advisories");
pub const enroll_boot = @embedFile("tools/enroll-boot");
pub const build_helper = @embedFile("tools/build-helper");
pub const build_helper_template = @embedFile("boot/build-helper.yaml");
pub const native_firmware = @embedFile("tools/native-firmware");
pub const firmware_requirements = @embedFile("boot/firmware-requirements.txt");
pub const local_tpm = @embedFile("tools/local-tpm");
pub const local_publisher = @embedFile("tools/local-publisher");
pub const verify_boot_disk = @embedFile("tools/verify-boot-disk");

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

/// Pinned security builders are available even when howl runs without its checkout.
pub const secure_sources = [_]struct { path: []const u8, data: []const u8 }{
    .{ .path = "local-prerequisites", .data = @embedFile("tools/local-prerequisites") },
    .{ .path = "build-helper", .data = build_helper },
    .{ .path = "boot/build-helper.yaml", .data = build_helper_template },
    .{ .path = "boot/ipe-kernel.melange.yaml", .data = @embedFile("boot/ipe-kernel.melange.yaml") },
    .{ .path = "boot/tpm-stub.melange.yaml", .data = @embedFile("boot/tpm-stub.melange.yaml") },
    .{ .path = "boot/kernel-source", .data = @embedFile("boot/kernel-source") },
    .{ .path = "boot/build-kernel", .data = @embedFile("boot/build-kernel") },
    .{ .path = "boot/ipe-boot.policy", .data = @embedFile("boot/ipe-boot.policy") },
    .{ .path = "boot/stub-source", .data = @embedFile("boot/stub-source") },
    .{ .path = "tools/build-tpm-stub", .data = @embedFile("tools/build-tpm-stub") },
};
