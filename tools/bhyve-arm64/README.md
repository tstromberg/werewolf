# Private ARM64 bhyve runtime

Experimental: these fixes restore RTC and EFI rename behavior, not sustained-network
reliability. On 2026-10-18 smaug passed signed A/B recovery through normal howl, but
its half-hour TAP soak failed after about 12 minutes and 286 verified transfers
(17.875 GiB): a virtio TX descriptor error led to a soft-lockup panic. The exact cause
is unresolved. Secure Boot and TPM were off; do not treat A/B success as production
qualification. See [current validation](../../docs/testing-live.md#bhyve).

Run `python3 tools/bhyve-arm64/build OUTPUT --packages PACKAGE_CACHE` on native
FreeBSD 15.1-RELEASE-p5 ARM64. OUTPUT must not exist. The recipe pins FreeBSD and
U-Boot commits, the upstream RTC patch, the FreeBSD bhyve board port, and the
hashes of all privately extracted build packages. It requires installed `git`,
`python3`, `gmake`, and the base compiler; their versions are recorded in the
output manifest. This is a repeatable source/dependency recipe, not a claim of
bit-identical output across different host toolchains.
Build time and the patched U-Boot version string are fixed so source archives
and Git checkouts do not introduce metadata-only binary differences.

The cache must contain the `.pkg` archives listed in
`tools/bhyve-arm64/packages.sha256`; missing or changed packages are refused.
Keep that cache with the build evidence because rolling package repositories may
drop those versions. Packages are extracted under OUTPUT, never installed.
Optional `--freebsd-cache REPO` and `--uboot-cache REPO` export the pinned committed
trees from local repositories without copying worktree modifications. Otherwise
the recipe fetches the pinned commits from their upstream GitHub repositories.

Source `OUTPUT/runtime.env` before normal unprotected howl launches on that host;
it exports `BHYVE_BINARY` and `BHYVE_ARM64_FIRMWARE` pointing to the private binaries.
Keep the output directory in place while VMs use it. No system bhyve or firmware
is replaced; a new build uses a new output directory. The retained source trees,
patches, configuration and `manifest.json` describe the resulting binaries.
Both overrides must be absolute paths without commas or newlines. Invalid overrides
or missing selected files fail without fallback; unset overrides use the installed
defaults, not the fixed private runtime. The supervisor
retains the resolved paths across guest reboots; set them again on subsequent
create/reconfigure calls. ARM64 Secure Boot remains unsupported.

For an A/B test through normal `howl create` and `howl delete`, set
`BHYVE_LAUNCH=howl`, `BHYVE_BRIDGE=bridgeN`, `BHYVE_TEST_IP` and `BHYVE_TEST_GW`,
plus the two runtime overrides and `AB_MODE=plain`. Omit `BHYVE_TAP`: howl creates
and cleans up its own TAP; the caller owns the existing bridge. This mode seeds
an existing-machine record around the prebuilt signed fixture so the host does
not rebuild it. The test still requires verified root, IPE, a correct clock and
all recovery phases. The direct launch mode remains available for isolation.

`test/check-bhyve-lifecycle` forwards both runtime overrides and checks guest time.
Its duration argument controls sustained checksum-verified 64 MiB transfers;
use `1800` for a half-hour soak, followed by three reboots, stop/start, and an
offline filesystem check. It uses a separate disposable disk, not the A/B disk.

Independent clean builds on smaug produced byte-identical bhyve and firmware
binaries; this was checked on one host/toolchain, not across platforms.
Local evidence (not checked in):

- `build/bhyve-validation/results-smaug-normal-runtime-20261018.json`: A/B pass,
  soak failure, cleanup and retained disk paths.
- `build/bhyve-validation/runtime-recipe/reproducibility.json`: build comparisons.
- `build/bhyve-validation/wwlife-f7ac486c01/console.log`: virtio TX failure and panic.
