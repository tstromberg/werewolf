//! files are this tree's files that howl puts in what it builds, embedded,
//! so a howl binary builds with no checkout beside it. See
//! cmd/howl/README.md.

/// tiers_pub is the key an image checks the CVE tiers feed with;
/// advisories are werewolf's own fixes (docs/releases.md).
pub const tiers_pub = @embedFile("release/tiers.pub");
pub const advisories = @embedFile("release/advisories");
pub const enroll_boot = @embedFile("tools/enroll-boot");
pub const build_helper_template = @embedFile("boot/build-helper.yaml");
pub const firmware_requirements = @embedFile("boot/firmware-requirements.txt");
/// microsoft_uefi_cas sign other vendors' loaders; Azure's UEFI CA
/// template trusts them and howl revokes them (boot/microsoft/README.md).
pub const microsoft_uefi_cas = [_][]const u8{
    @embedFile("boot/microsoft/microsoft-corporation-uefi-ca-2011.der"),
    @embedFile("boot/microsoft/microsoft-uefi-ca-2023.der"),
    @embedFile("boot/microsoft/microsoft-option-rom-uefi-ca-2023.der"),
    @embedFile("boot/microsoft/azure-services-linux-kmod-pca.der"),
};
pub const protected_trust = @embedFile("release/protected/trust.json");
pub const protected_boot_certificate = @embedFile("release/protected/boot.crt");
pub const protected_image_certificate = @embedFile("release/protected/image.crt");
pub const verify_boot_disk = @embedFile("tools/verify-boot-disk");
pub const forms_catalog = @embedFile("docs/forms-catalog.md");
pub const dev_ssh_form = @embedFile("boot/dev-ssh/form.yaml");
pub const dev_ssh_config = @embedFile("boot/dev-ssh/sshd_config");

/// posture_known are the posture checks every form of a kind fails.
pub const posture_known = @embedFile("test/posture-known");

/// stage0_mtree is stage0's device nodes.
pub const stage0_mtree = @embedFile("cmd/stage0/stage0.mtree");

/// boot are the apko configs of the kernel, the boot loader and melange's
/// QEMU guest, with the Alpine keys melange-guest.yaml names, each by its
/// path under boot/.
pub const boot = [_]struct { path: []const u8, data: []const u8 }{
    .{ .path = "kernel.yaml", .data = @embedFile("boot/kernel.yaml") },
    .{ .path = "boot.yaml", .data = @embedFile("boot/boot.yaml") },
    .{ .path = "melange-guest.yaml", .data = @embedFile("boot/melange-guest.yaml") },
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
    .{ .path = "boot/build-helper.yaml", .data = build_helper_template },
    .{ .path = "boot/kernel-build", .data = @embedFile("boot/kernel-build") },
    .{ .path = "tools/test-kernel", .data = @embedFile("tools/test-kernel") },
    .{ .path = "boot/tpm-stub.melange.yaml", .data = @embedFile("boot/tpm-stub.melange.yaml") },
    .{ .path = "boot/stub-source", .data = @embedFile("boot/stub-source") },
    .{ .path = "tools/build-tpm-stub", .data = @embedFile("tools/build-tpm-stub") },
};
