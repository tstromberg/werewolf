# tools

Build-host programs, never in an image. Most build into build/host/.

## form

`form VERB FORM ...` answers make's questions about a form (howl reads forms
itself): its chain of bases, form.yaml keys, ports, weaknesses, kernel
arguments, modules, merged apko config, and the files the chain derives
(lib/form.zig, lib/compose.zig, forms/README.md). `form tree` prints every
form and its chain, and `form released` the forms CI publishes
(lib/compose.zig's `release_forms`). Run it with no arguments for the usage.
A form that cannot be read fails with file and line.

## package

Packs werewolf's programs as apk packages and indexes and signs their
repository (lib/package.zig). `make packages` runs the first two for ARCH.

- `package pack DIR TREE NAME VERSION ARCH TIME DESCRIPTION [depend:D|provide:P]...`
  packs the files under TREE as NAME into `DIR/NAME-VERSION.apk`, with its
  index stanza beside it. TIME is when the source was committed, in seconds
  since the epoch; a VERSION of `-` derives the version from it.
- `package index DIR OLD` writes `DIR/APKINDEX` from OLD, an APKINDEX
  already published (or `-`), and DIR's stanzas, and `DIR/APKINDEX.member`,
  the bytes to sign: `openssl dgst -sha256 -sign KEY`.
- `package sign DIR KEYNAME SIGNATURE` writes `DIR/APKINDEX.tar.gz`. KEYNAME
  is the key's file name in /etc/apk/keys.
- `package open INDEX KEYNAME SIGNATURE MEMBER` splits a published index into
  its signature and the member it signs, for `openssl dgst -verify` to check
  before the index is trusted (release/packages).

A file goes in as 0755 if it is executable and 0644 if not, as the build
lays files; directories are 0755 and links stay links. The tree is read in
sorted order, so the same tree packs the same bytes. The tool never holds a
key and never uploads.

## verity

`verity IMAGE PARAMS` appends IMAGE's dm-verity hash tree and writes the line
stage0 opens it with to PARAMS (lib/verity.zig). It needs no veritysetup and
gives the same tree on macOS as on Linux. `make check-updater` uses it;
howl's build calls lib/verity.zig itself.

## doc-check

`doc-check FILE.md...` runs for `make lint`. It fails on a relative link or
`#anchor` that leads nowhere (anchors as GitHub makes them from headings), a
program README over 100 lines, a design doc over 120, or a line that starts
with TODO: the limits in CONTRIBUTING.md's Style section.

## zigfix

`zigfix [--check] [--max N] FILE...` runs for `make fix` and `make lint`. It
rewrites deprecated std calls, breaks lines longer than N bytes (default 100)
where zig fmt keeps the break, then formats as zig fmt does. It fails on lines
it cannot break, except multiline string lines and comments that overflow by
one unbreakable word, such as a URL. `--check` writes nothing and also fails
on any file it would change.

## cve-tiers

`cve-tiers KERNEL ORIGINS CACHE WORK OUT` (`make cve-tiers`) builds the CVE
tiers feed (docs/design/update-policy.md) for the packages in ORIGINS and
KERNEL's stable branch. It reads Wolfi's security.json, the kernel CNA's
records, CISA's KEV catalog and NVD scores, which it caches in CACHE so later
runs fetch only changes. A CVE is urgent if in KEV or scored 9.0+ over the
network, high at 7.0, medium at 4.0 or unscored, else low. Output is sorted
and has no time, so the same sources give the same bytes; release/sign-tiers
adds the time and signs it. It needs NVD_API_KEY. A missing, short or
malformed source fails the run and leaves OUT alone.

## test-sk

An OpenSSH security key provider (sk-api.h) for `make check`, which logs in
to machines that accept only security keys. It never asks for a touch, so
anyone who reads its key file can log in: it is built only for the host.

## install-deps

`tools/install-deps [-y] [apko] [zig]` installs what building, booting and
checking need, pinned by version and checksum, after asking. It is a shell
script because it installs Zig.

## git-hooks

`make hooks` points git here. pre-commit runs the unit tests, lint and check-sshd.
