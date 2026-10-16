# ARMORY CASTLE prevention review

Werewolf would break several independent steps in this intrusion when the affected
workload is packaged as a confined Werewolf service. Its immutable system and service
boundaries remain useful after application code execution. PHP runtime protection
requires the hardened package; the existing native PHP forms request an older stream.

[Mandiant's October 15 report][incident] describes file operations through
CVE-2026-102764, SAWFLY PHP execution, a root-owned SUID shell, vault access,
startup and sudoers persistence, log removal, administrator abuse, file transfers,
and a WebSocket tunnel exposed through HAProxy. [BeyondTrust's advisory][vendor]
identifies missing origin validation in an internal messaging component. Werewolf
has no BeyondTrust form: the conclusions below map implemented controls to those
operations, rather than claim a reproduction of the proprietary exploit.

## Protection at each step

| Operation | Werewolf boundary | Remaining condition |
| --- | --- | --- |
| Arbitrary file operations | EROFS, verity, service write grants | Own state writable |
| Webshell in document root | Code on read-only image | Writable code unsafe |
| Encrypted PHP evaluation | Hardened PHP inline gate | Legacy PHP excluded |
| Copy shell and set SUID | Immutable `/usr`, nosuid, no_new_privs | No new privilege |
| Dump credential vault | Distinct users, read and exec grants | Own secrets exposed |
| Startup persistence | Image-defined runit services | State survives updates |
| Change sudoers template | Image configuration read-only | No mutable sudo policy |
| Remove evidence | Locked kernel audit, captured console | App logs writable |
| Administrator login | Application identity controls | Valid sessions usable |
| Change Jump roles | Application authorization | Own database writable |
| Transfer files | Application and endpoint permissions | Allowed data exposed |
| Start native tunneler | noexec, Landlock, IPE | JIT grants weaken W^X |
| Publish proxy route | Service isolation and TCP port grants | Allowed routes usable |

The relevant implementations are [fence](../../cmd/fence/fence.zig),
[leash](../../cmd/leash/leash.zig), [seal](../../lib/seal.zig),
[init mounts](../../cmd/init/init.zig), [audit](../../lib/audit.zig),
and the PHP policy in `../glibc-build/packages/php/patches/`.

**File operations and code.** The web service cannot alter its image's document root,
programs, interpreter allowances or startup policy. Its writable service directories
remain available for legitimate data. Native execution from those directories is
refused by mount flags and Landlock; protected images add IPE verification of native
code and file-backed executable mappings. These kernel controls do not authenticate
PHP input. An include vulnerability or interpreter evaluation needs runtime guards.

**Privilege escalation.** Services start without root, with a bounded capability set
and `no_new_privs`; writable mounts are nosuid and the image contains no setuid files.
Changing a file owner to root already needs authority: the report's SUID sequence
does not establish how the actor first obtained that authority. Werewolf's inherited
seal, Landlock and capability limits continue to apply even after an effective-root
compromise. A trusted helper or kernel compromise remains outside that claim.

**Persistence.** A file written to a data directory does not become a runit startup
script. Service definitions and native programs come from the image. Fixed broker
operations do not let a service remount or rewrite the root. Signed boot and update
verification protect replacement system images in the protected profile; deployments
with protections explicitly disabled retain the documented weaker boot guarantees.
Application configuration, accounts, sessions and data on `/data` survive updates and
must be reviewed separately; rebooting or installing a clean slot does not clean them.

**Vault and lateral movement.** A web service cannot open another service's private
secrets, control its processes or execute an undeclared credential utility. It can
still read secrets deliberately delivered to it and operate its own database and
application APIs. The OS cannot distinguish an attacker using an authorized support
session from a legitimate operator solely by the session's process identity.

**Tunneling.** The PHP form has no Internet socket promise, TCP listener or outbound
port grant. A PHP implant therefore cannot bind port 19800 or connect to downstream
TCP services. HAProxy's separate identity cannot be controlled by PHP; its permitted
backend ports omit 19800. HAProxy's generated configuration is in its own writable
service directory: compromise of HAProxy itself can change that configuration and
misuse already permitted destinations. An implant could also use an existing HTTP
response channel; prohibiting new listeners does not stop that communication.

**Evidence.** A service cannot unlock the kernel audit policy or remove console data
already captured outside the guest. It can delete its own writable application logs,
stop emitting useful events or forge its own output. The default nginx access log is
off. Host retention and external request logging are deployment requirements, not a
guarantee that every request is durably recorded by the guest.

## Gaps repaired in this review

Hardened PHP previously checked only primary scripts with a path-based `statvfs`
lookup. A failed lookup permitted execution; includes, generated streams and stdin
were incompletely covered. Its compiler hook installed before OPcache's startup hook,
allowing a warm cache to precede the check. PHP string compilation remained permitted.

The PHP policy revision now:

- Checks every compiled file by its actual descriptor, including includes and
  automatic prepends. A regular file on a read-only mount is required by default;
  metadata failures refuse execution and symlinks are checked by the opened target.
- Installs the compiler guard after OPcache startup so cache hits cross the guard;
  the stream opener also protects preload compilation during startup.
- Requires `php:inline` for `eval`, argv/stdin and generated stream code, including
  filters and user-defined stream wrappers. `@eval` cannot suppress the refusal.
- Keeps `php:writable-source` separate: permitting writable files does not permit
  evaluated strings, stdin or generated streams, and inline does not permit ordinary
  files on writable mounts. The existing exec and native floors remain independent.

All six native FPM pool configurations disable `.user.ini`, PATH_INFO fallback and
`dl`. Pool settings are image-owned. These controls also apply to the current older
PHP stream, but they do not provide the newer runtime's provenance or eval guards.
The base PHP service also places OPcache's startup lock in its own service directory,
so PHP 8.5 can start without granting access to the machine-wide `/tmp`.

The package probes cover refusal and explicit grants, failed descriptor metadata,
non-regular files, include variants, include_path, source symlinks, wrappers, stdin,
suppressed eval and OPcache revocation in a persistent process. The PHP supplied-code
VM fixture exercises the actual FPM identity's writable state, immutable paths,
privilege restrictions, network refusals, configuration isolation and fixed settings.
Validation passed the hardened-packages unit suite, arm64 PHP compilation
and package probes, and both the stock PHP and candidate hardened-FPM Werewolf VM
checks. The candidate VM overlay uses the locally built FPM binary; it does not test
migration or package resolution for existing application forms. No release was
published, and x86_64 package compilation remains for CI.

To repeat the candidate VM checks, set `PHP_FPM_APK` to the locally built FPM APK
for the host architecture, then use a disposable overlay:

```sh
test/app-fixture php build/php-security-overlay
mkdir -p build/php-security-overlay/usr/bin
bsdtar -xf "$PHP_FPM_APK" -C build/php-security-overlay usr/bin/php-fpm
make FORM=php DEV=1 APP=build/php-security-overlay image
make FORM=php DEV=1 APP=build/php-security-overlay \
  FORM_CHECKS=test/checks-php-hardened CHECK_NAME=php-hardened _check-form
```

## Remaining work and deployment requirements

1. **Migrate the native PHP forms before crediting runtime protection.** `php`,
   WordPress, WordPress on MariaDB, MediaWiki, LimeSurvey, Moodle and Nextcloud request
   PHP 8.4; hardened PHP currently follows 8.5. Merely adding the feed does not replace
   them. WordPress salts and MediaWiki secrets are currently loaded as writable PHP;
   Nextcloud uses writable configuration and apps; Moodle and LimeSurvey generate
   template code. Convert secrets and configuration to parsed data and precompile
   templates into the image where possible. Compatibility tests must cover upgrades
   of existing data. Blanket writable-source and inline grants would restore the
   webshell risk. Current runtime grants are image-wide, so isolate any required
   exceptions on separate machines until service-specific grants are available.
2. **Keep privileged credentials outside the web process.** Use a separate broker
   with fixed operations or an external vault with credential injection; do not hand
   the web service a reusable vault export credential. Scope secrets to a service.
   After suspected compromise, rebuild first, then revoke sessions, rotate exposed
   credentials and inspect application data and downstream endpoints.
3. **Constrain destinations beyond ports.** A permitted HTTPS port is not a host
   allowlist. `public` excludes private destinations where declared, and DNS grants
   constrain resolvers, but neither binds HTTPS to a particular service. Use perimeter
   destination restrictions and separate broker identities for sensitive operations.
   Keep `netadmin`, `packet`, `jit`, exec and interpreter grants to demonstrated need.
4. **Protect the application control plane.** Patch the origin-validation flaw, use
   phishing-resistant administrator authentication and least-privilege roles, audit
   role changes, and restrict endpoint file transfers. Filesystem immutability does
   not prevent changes through legitimate application storage or APIs.
5. **Retain evidence outside the guest.** Capture serial output and proxy requests
   with URI and WebSocket metadata in an independently administered store; alert on
   forwarding gaps and review session and file-transfer records. Application-owned
   log files alone cannot establish the absence of compromise.

[incident]: https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust
[vendor]: https://www.beyondtrust.com/trust-center/security-advisories/bt26-05
