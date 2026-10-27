# Audit: Arbitrary Code Execution Weaknesses in the VM (2026-10-15)

This document records the findings of a defensive security audit hunting for
weaknesses across Werewolf's runtime, confinement mechanisms, form definitions,
and shipped third-party components that could accidentally allow arbitrary code
execution (ACE) inside a running VM.

---

## 1. Machine-Wide W^X (`PR_SET_MDWE`) Knockout via `allow: [jit]`

- **Files:**
  - `cmd/init/kernel.zig` (`writeXorExecute`)
  - `lib/seal.zig` (`table`, `.stdio`)
  - `cmd/leash/leash.zig` (`pledgeAndExec`)
  - `forms/postgresql/form.yaml`, `forms/php/form.yaml`, `forms/node/form.yaml`,
    `forms/jre/form.yaml`, `forms/wordpress/form.yaml`,
    `forms/mastodon/form.yaml`, `forms/greenbone/form.yaml`

### Mechanism
1. `lib/seal.zig` allows `mmap`, `mprotect`, and `mremap` under `.stdio`
   without filtering `PROT_EXEC`.
2. Anonymous-memory W^X across the entire VM relies on `PR_SET_MDWE`
   (`PR_MDWE_REFUSE_EXEC_GAIN`), set on PID 1 by `writeXorExecute` in
   `cmd/init/kernel.zig`.
3. Linux IPE (`op=EXECUTE`) only mediates file-backed execution (`execve` and
   file-backed `mmap`/`mprotect`); anonymous mappings (`MAP_ANONYMOUS`) are not
   checked by IPE and rely solely on `PR_SET_MDWE`.
4. When **any** form in a composition declares `allow: [jit]` — including
   `forms/postgresql/form.yaml` (inherited by `mastodon`, `greenbone`, etc.)
   and `forms/php/form.yaml` (inherited by `wordpress`) — `init` skips
   `PR_SET_MDWE` on PID 1, and `cmd/leash/leash.zig` never sets `PR_SET_MDWE`
   on non-JIT services.

### Impact
On any VM built with `postgresql`, `php`, `wordpress`, `mastodon`, `greenbone`,
`node`, or `jre`, **every process on the machine** (`nginx`, `caddy`, `valkey`,
`gvm-link`, `mastodon`, `sshd`, `autoupdate`, `dhcp-client`, etc.) runs with
`PR_SET_MDWE` disabled and can map or `mprotect` anonymous memory as
`PROT_EXEC` to execute arbitrary native shellcode — even on an `IPE=1` kernel.

### Remediation
- Disable PostgreSQL's LLVM JIT (`-c jit=off`) in `forms/postgresql/form.yaml`
  and `forms/greenbone/form.yaml`, removing `allow: [jit]` from `postgresql`,
  `mastodon`, and `greenbone`.
- Add a `jit` promise to `lib/seal.zig` (or per-service enforcement in
  `cmd/leash/leash.zig` and `cmd/posture/processes.zig`) so `leash` sets
  `PR_SET_MDWE` (`PR_MDWE_REFUSE_EXEC_GAIN`) on every service whose pledge does
  not include `jit`, even when the machine has `allow: [jit]` for one runtime.
- Set `PR_SET_MDWE` in `init`'s own helper daemons (`mount-broker`,
  `task-links`, `seal-watch`, `dhcp-client`, `slot-update`).

---

## 2. Unimplemented Design Defenses: `sh-shim` Interpreter Restrictions

- **Files:**
  - `cmd/sh-shim/sh-shim.zig`
  - `docs/design/glibc-neutered.md`
  - `docs/design/script-argv-enforcement.md`

### Mechanism
- Design documents describe `/usr/share/werewolf/sh-allow`, `popen-shim`, and
  `script-argv-enforcement` blocking inline interpreter flags (`python3 -c`,
  `ruby -e`, `php -r`, `node -e`).
- In reality, `cmd/sh-shim/sh-shim.zig` parses any single command string passed
  to `sh -c "..."`, performs no interpreter or allowlist check, preserves the
  caller's environment (`env.ptr`), and searches `PATH` to `execve` any binary
  permitted by the caller's Landlock domain.

### Impact
Any service with `pledge: ... exec` that starts an interpreter (`ruby`,
`python3`, `node`, `php`, `bash`) has that interpreter in its Landlock
`LANDLOCK_ACCESS_FS_EXECUTE` set because `cmd/leash/leash.zig` grants execute
permission on `s.exec[0]`. In `forms/mastodon/form.yaml`, `mastodon` and
`mastodon-jobs` run `/usr/bin/ruby` with `pledge: ... exec` and `sh-shim`. A
command/argument injection into `system()`/`popen()` can invoke
`sh -c "ruby -e '...'"` directly through `sh-shim`.

### Remediation
- Have `cmd/sh-shim/sh-shim.zig` refuse interpreter and shell basenames (`sh`,
  `ash`, `bash`, `dash`, `busybox`, `env`, `python`, `python3`, `ruby`, `node`,
  `php`, `php-fpm`, `perl`, `lua`, `awk`) so `sh -c` can only invoke dedicated
  command binaries, never a shell or language interpreter.

---

## 3. Direct Execution Bypass of `narrow` Sub-Sandboxes (`cmd/leash`)

- **Files:**
  - `cmd/leash/leash.zig`
  - `forms/mastodon/form.yaml`

### Mechanism
In `forms/mastodon/form.yaml`, `mastodon` and `mastodon-jobs` declare both
`run: /usr/bin/file /usr/bin/ffprobe /usr/bin/ffmpeg` and `narrow:` rules for
those same binaries. Because Landlock domains are inherited and can only
narrow rights, `leash` must grant `LANDLOCK_ACCESS_FS_EXECUTE` on `s.run` in
the parent service's Landlock domain so that `/etc/sv/mastodon/narrow/ffmpeg`
(a symlink to `leash`) can eventually `execve("/usr/bin/ffmpeg")`.

### Impact
Routing through `/etc/sv/<service>/narrow/<prog>` relies on `PATH` and
environment variables (`FFMPEG_BINARY`). If the parent service executes
`/usr/bin/ffmpeg` by absolute path, it bypasses `narrow`. Furthermore, inside
`narrow()`, `leash` stacks a tighter Landlock ruleset and seccomp filter for
the helper.

### Remediation
- Ensure `narrow` in `cmd/leash/leash.zig` always sets `PR_SET_MDWE` when the
  narrowed pledge lacks `jit`, and ensure `sh-shim` resolves bare command names
  through the service's `PATH` (where `/etc/sv/<service>/narrow` comes first)
  while refusing explicit paths when a `/etc/sv/<service>/narrow/<basename>`
  wrapper exists!

---

## 4. `before` Hooks Run Without Seccomp `pledge` and Stay Executable With `exec`

- **Files:**
  - `cmd/leash/leash.zig`
  - `forms/gitea/form.yaml`, `forms/grafana/form.yaml`, `forms/mastodon/form.yaml`

### Mechanism
1. In `cmd/leash/leash.zig`, `s.before` commands are spawned before
   `pledgeAndExec` installs the service's seccomp filter.
2. `for (s.before) |b| allowProgram(l, rules, gpa, b[0]);` adds every `before`
   binary to the primary Landlock ruleset.
3. After `s.before` completes, `leash` only stacks a second `only_exec`
   Landlock ruleset when `!s.pledge.contains(.exec)`.

### Impact
When a service has `pledge: ... exec` (such as `gitea`, `grafana`, `mastodon`),
`service-config` and all `before` setup binaries (`/usr/lib/werewolf/gitea-init`,
`/usr/lib/werewolf/grafana-setup`, etc.) remain permanently executable by the
running daemon after startup. In `forms/gitea/form.yaml`, `/usr/bin/ssh-keygen`
also had to be placed in `gitea`'s runtime `run:` list solely for `gitea-init`
(`before`).

### Remediation
- Always stack the post-`before` `only_exec` Landlock ruleset in
  `cmd/leash/leash.zig` whenever `s.render != null or s.before.len > 0`:
  - When `!s.pledge.contains(.exec)`, allow only `s.exec[0]`.
  - When `s.pledge.contains(.exec)`, allow `s.exec[0]`, `s.run`, `sh_shim` (if
    `allow_sh`), and `leash_bin` (if `s.narrow.len > 0`), stripping
    `service-config` and any `s.before` binary not in `s.run`.
- Add a `before-run` (or allow `before` helpers' tools only during `before`) or
  move `/usr/bin/ssh-keygen` out of `gitea`'s runtime `run:` list by generating
  the host key via `before: /usr/lib/werewolf/ssh-host-key` (which uses
  `ssh-keygen` only during `before`).

---

## 5. `sshd` (`caps: login`) Execute Surface & Privileged Tool Permissions

- **Files:**
  - `cmd/leash/leash.zig`
  - `cmd/fence/fence.zig`
  - `forms/minimal/form.yaml`, `forms/sshd/form.yaml`

### Mechanism
When `login` is true (`caps: login` on `sshd`), `cmd/leash/leash.zig` initializes
Landlock with `.only_bind = true` (`handled_access_fs = 0`), leaving interactive
sessions under `fence`'s `/usr` and `/oci` execute grants. Administrative tools in
`/usr/bin` and `/usr/sbin` (`/usr/bin/apk`, `/usr/sbin/e2fsck`, `/usr/sbin/mke2fs`,
`/usr/bin/cryptsetup`) are world-executable (`0o755`).

### Remediation
- Restrict administrative binaries (`/usr/bin/apk`, `/usr/sbin/e2fsck`,
  `/usr/sbin/mke2fs`, `/usr/sbin/blkid`, `/usr/bin/cryptsetup`) to mode `0o700`
  (root-only) in `forms/minimal/form.yaml` and `forms/prod/form.yaml` so
  non-root accounts and services cannot execute them.

---

## 6. Over-Broad `run: /usr/` in `forms/greenbone/form.yaml`

- **Files:**
  - `forms/greenbone/form.yaml`

### Mechanism
`feed` and `openvas` in `forms/greenbone/form.yaml` specify `run: /usr/` inside
their Debian/Ubuntu-based OCI images, granting Landlock execute permission to
every compiler, interpreter, and utility under `/usr` in those containers.

### Remediation
- Replace `run: /usr/` where possible or document/tighten the executable set
  and ensure `PR_SET_MDWE` is active on all Greenbone services (`postgresql` no
  longer disables W^X for the machine).

---

## 7. Local Package Rebuild Staging on Writable `/data` (`cmd/slot-update`)

- **Files:**
  - `cmd/slot-update/slot-update.zig`
  - `cmd/slot-update/slot.zig`
  - `cmd/fence/fence.zig`

### Mechanism
On non-IPE / non-Secure-Boot builds (`needsSignedImage() == false`),
`slot-update` stages package extractions and builds `root.erofs` and
`stage0.zst` under `/data/svc/autoupdate/work` before hashing them and asking
`mount-broker` to install them to `/boot`.

### Remediation
- Ensure `work_dir` (`/data/svc/autoupdate/work`) and `state_dir`
  (`/data/svc/autoupdate`) are created with mode `0o700` owned by root, and
  verify `O_NOFOLLOW` / directory descriptor discipline across `slot.zig` so
  unprivileged processes on `/data` cannot traverse or plant symlinks inside
  `/data/svc/autoupdate`.

---

## Resolution (2026-10-15)

1. **Per-process `W^X` (`PR_SET_MDWE`):** Added `sandbox.refuseExecGain()` in
   `lib/sandbox.zig` and called it automatically in `sandbox.dropWith`,
   `sandbox.keepOnly`, and `sandbox.Filter.install`, as well as in
   `cmd/leash/leash.zig` (`narrow()` unconditionally, and `main()` whenever
   `!login and !usesJit(s)`). Even when a machine permits `jit` for one workload
   (such as PostgreSQL's LLVM or a JVM), every helper daemon, narrowed helper,
   and non-JIT service (`caddy`, `nginx`, `valkey`, `gitea`, `node --jitless`,
   `postgres -c jit=off`, etc.) now locks `PR_MDWE_REFUSE_EXEC_GAIN` on itself.
2. **Unified post-setup `only_exec` Landlock restriction in `leash`:** Replaced
   the duplicated execute-rule logic in `cmd/leash/leash.zig` with a single
   `allowExecSet(l, rules, gpa, s, with_setup)` helper and stacked the
   post-`before` `only_exec` Landlock ruleset even when `s.pledge.contains(.exec)`,
   stripping `service-config` and `s.before`-only setup binaries before the
   daemon starts.
3. **Hardened `sh-shim` (`cmd/sh-shim/sh-shim.zig`):** Added `refusedProgram` to
   reject shells (`sh`, `ash`, `bash`, `busybox sh`, `sh-shim`), inline
   interpreter code evaluation (`-c`, `-e`, `--eval`, `-r`), unsafe PHP `-d`
   directives (such as `auto_prepend_file`), and interpreter script paths outside
   clean `/usr/` paths.
4. **Hardened updater staging permissions (`cmd/slot-update/slot.zig`):**
   Restored mode `0o700` on `work_dir ++ "/root"` and `work_dir ++ "/kernel"`
   immediately after `apk add` (which resets `/` to `0o755` from
   `wolfi-baselayout`) and on `work_dir ++ "/local-overlay"`, keeping staged
   trees unreadable/untraversable until `mkfs.erofs` snapshots the new root.

