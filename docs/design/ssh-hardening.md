# SSH hardening

## Summary

Build OpenSSH without PAM, SELinux, zlib or PKCS#11, narrow sshd's protocols,
capabilities, pledge and writes, and hold each key to what its authenticator can
attest. sshd loads four fewer libraries, and Apple's Touch ID keys log in.

## Background

sshd is prod-ssh's only root daemon on the network; every root session runs in its
leash ([su.md](su.md)). Of ~30 server-side OpenSSH bugs since 2016, ~20 needed a
feature werewolf leaves off (GSSAPI, X11, tunnels, compression); the rest, such as
regreSSHion (CVE-2024-6387), are in code every build has. Wolfi's sshd loads libpam,
libselinux, libpcre2 and libz, unused here, as liblzma reached it (CVE-2024-3094).
Apple's Secure Enclave keys never report verification; `verify-required` refuses
them.

## Goals

- `net/openssh`'s probe: sshd, sshd-session, sshd-auth, ssh, ssh-agent and ssh-keygen
  load no PAM, SELinux, PCRE2 or zlib; sshd refuses `Compression yes`.
- `sshd -T`: post-quantum key exchange, AES-GCM, ed25519 host keys, no compression.
- A root SSH session's CapBnd is `4004404ed` (was `4254404ff`); capset, seccomp,
  Landlock, netlink and AF_PACKET fail with ENOSYS; it writes only where listed
  below.
- prod-ssh takes Touch ID keys; ed25519 keys still need a PIN; no one edits their
  keys.

## Non-Goals

Removing uid 0 from sshd's monitor
([privilege-separation.md](privilege-separation.md)) and attesting Secure Enclave
keys.

## Detailed design

**Package.** `../packages/net/openssh` derives Wolfi's recipe with `--without-pam
--without-selinux --without-zlib --disable-pkcs11` and two patches: sshd skips
reopening a pty as root once `TIOCSCTTY` made it the controlling tty (refused without
DAC_OVERRIDE), and sshd-session, which never listens, resolves no default listen
address (glibc asked netlink to sort it). It keeps Wolfi's names and outranks Wolfi's
build; a changed option, step or subpackage stops derivation. Published, it takes
`unix_chkpwd` away.

**Configuration** (`forms/sshd/.../werewolf.conf`): mlkem768x25519 and
sntrup761x25519 key exchange; AES-GCM alone, which Terrapin cannot attack with any
client; `HostKeyAlgorithms ssh-ed25519`, `Compression no` (the bastion's too),
`PermitUserRC no`, `PerSourceMaxStartups 3`, `UnusedConnectionTimeout 60`,
`TCPKeepAlive no`, and `ListenAddress` 0.0.0.0 and :: apart, each a one-result
lookup. `UsePAM` is gone.

**Keys.** werewolf's `sshd: verify-required-keys` names the security key types to
verify, or none: ssh-su names `sk-ssh-ed25519@openssh.com` beside `PubkeyAuthOptions
touch-required`; playground, none. The build writes them to
`/usr/share/werewolf/sshd-verify-required`; init and cloud-metadata put
`verify-required` before each such key. The Secure Enclave makes no ed25519 key, so
FIDO ed25519 keys keep their PIN. A person's keys file is `root:PERSON 0640`: sshd
reads it as them, and they cannot add a key or `no-touch-required`.

**Privileges.** No process regains a capability its parent dropped, or leaves a
Landlock or seccomp domain, so sshd's leash is every root session's ceiling.
`login_set` loses DAC_OVERRIDE (root changes only what it owns, never a service's
data), FSETID (nothing is setuid), SYS_RESOURCE (sshd only lowers limits),
SYS_TTY_CONFIG (vhangup is never allowed) and AUDIT_WRITE (no audit or PAM). The
pledge loses `packet` (login lacks NET_RAW), `caps`, `landlock`, `seccomp` (OpenSSH's
sandbox uses prctl) and `netlink` (no ip or ss); operators keep `reboot` and `syslog`
(dmesg). Sessions share sshd's `memory: 512`. Production sshd's Landlock layer also
handles writes, granting only /data, /tmp, /var/tmp, /dev/shm, /dev/pts, /run/runit
(sv, reboot), /run/ssh-agent, /dev/ptmx, tty and null: never /run/werewolf,
/run/cgroup or the TPM, whose PCR 11 a session could extend. It goes on after
`before`, which publishes ssh-su's host-key pin. Developer SSH (`--dev=ssh`,
sshd-dev) keeps the old pledge, DAC_OVERRIDE, SYS_RESOURCE, SETPCAP and a bind-only
layer, which the services its nested leashes test inherit. Posture in a session takes
boot's result, named `(cached)`, for what it cannot ask (netlink, leashing, its
attack lock), `--no-cache` skipping them; ab-status reads stage0's TPM floor record.

## Drawbacks

Another overlay follows Wolfi; a CVE fix waits for its next build. Clients before
OpenSSH 8.5 cannot connect; hosts without AES instructions lose ChaCha20. P-256 keys,
YubiKeys' too, need no PIN on prod-ssh. Sessions share 512 MiB; three su callers can
authenticate at once. Root cannot fix a service's files, kill a cgroup or run ip.
Until the package is published, Wolfi's sshd logs both refusals it patches.

## Alternatives Considered

- **`--without-openssl`**: drops libcrypto and Brotli too, but refuses Touch ID keys.
- **Global `verify-required`, touch alone, or a per-key flag in `users:`**: refuses
  Apple's keys, drops YubiKey PINs, or changes the schema for what the type says.
- **Later, operator verbs behind a broker**, leaving sshd CHOWN, FOWNER, KILL,
  SETUID, SETGID, NET_BIND_SERVICE and SYS_CHROOT.

## Security Considerations

Theo would delete code rather than configure it off: PAM, SELinux, zlib and PKCS#11
are gone; GSSAPI was never built. sshd-auth runs chrooted as `sshd` under OpenSSH's
filter, but the listener and monitor hold every operator power. macOS software
reports a Touch ID key's presence; only the enclave policy (`-t bio`) enforces it.

## Reliability Considerations

Derivation fails closed; the probe proves each removal. OpenSSH 10.4+ exits if its
seccomp sandbox fails; prctl stays in `stdio`. An out-of-memory kill stays in sshd's
cgroup; a write rule leash cannot add parks sshd rather than widen it.
