# Script arguments

Proposed, 2026-10-10. Not built. The command line of an interpreter,
not what a running interpreter later reads.

## Summary

An interpreter runs only the argv its service file names, and that file
is on the verity root. Nothing we run today keeps it from starting
itself again with a different argv: the execute right leash needed is
inherited. Closing self-re-exec is a same-inode check in the phase-4
kernel. Closing every other argv is the recorded list beside it. It is
not auditd, and it is not a regular expression.

## Background

`noexec`, Landlock and IPE judge the file that is executed
([shell-free.md](shell-free.md), [pledge.md](pledge.md)). For
`/usr/bin/php /data/evil.php` that file is `/usr/bin/php`. The script
is an argument. seccomp is handed a pointer, not the string. `python
-c`, `ruby -e`, `node -e` and `php -r` have no path.

A service that does not pledge `exec` cannot `execve` a path. It can
still `execveat` a descriptor (`AT_EMPTY_PATH`). That is how leash
becomes the service, the filter is inherited, and Landlock grants
execute on that binary so the first exec works
([lib/seal.zig](../../lib/seal.zig), [cmd/leash/leash.zig](../../cmd/leash/leash.zig)).
Opening `/proc/self/exe` and `execveat` of it runs the same binary with
a new argv. php-fpm, the `*-app` forms, Home Assistant, Open WebUI,
Mastodon's streaming server and the JVMs can all do this. A shebang on
`/data`, `/run`, `/tmp` or `/dev/shm` already fails: those mounts are
`noexec`.

These pledge `exec` and can execute the interpreter, so a compromised
process chooses the next argv. Landlock allows the binary because leash
executed it to start the service. Flags on the first command are simply
absent from the second.

| Service | Can exec |
| --- | --- |
| Mastodon web, jobs, cron | `ruby` |
| Moodle cron, Nextcloud cron | `php` |
| Immich, Overleaf web | `node` |
| Overleaf compiler | `perl` |
| Bugsink | `python3.12` |
| Pi-hole | `bash` |

## Goals

- An interpreter cannot execute its own binary. Leash still can.
- On a command line, the environment variables an interpreter treats as
  code are absent.
- Once the phase-4 kernel exists, an interpreter argv that the form's
  check boot did not record is refused.
- `make check` of the services in the table records each argv, and a
  boot that execs another fails.

## Non-Goals

- Code a running interpreter reads or evaluates: `include`, `require`,
  `import`, `eval`, a class loader, `SCRIPT_FILENAME`, Valkey `EVAL`,
  TeX, an Open WebUI function, a Home Assistant integration, Nextcloud's
  PHP under `/data`. None is an `exec`. Seeing them means patching the
  interpreter, which images we do not build would not carry.
- auditd. init's audit rule is the log
  ([lib/audit.zig](../../lib/audit.zig)): one refused exec, the EXECVE
  record dropped, the configuration locked.
- Matching argv with a regular expression.

## Detailed design

**Not re-executing itself.** If the file being executed is the caller's
own executable, refuse. Leash starting `ruby` is allowed: leash's
executable is leash. `ruby` starting `ruby`, including through
`/proc/self/exe`, is refused. `ruby` starting ffmpeg is allowed. A
different program starting the interpreter is not this rule.
supercronic can still run `php -r`.

The pledge and Landlock cannot say this. Both are inherited across
exec and both are judged on the way in, so the right that starts the
interpreter is the right that starts it again. The check is the same
phase-4 hook, one comparison of inodes, on by default.

Boot breaks where a process is expected to re-exec, and each of those
has a form change rather than an exception:

- Mastodon runs `bundle exec`, which re-execs Ruby. Start puma and
  sidekiq with `ruby -rbundler/setup`, so Bundler stays in the process.
- Bugsink's monofy is Python and execs Python for gunicorn and
  snappea. Two services, the two commands that line already names.
- Overleaf's starter `spawn`s `process.execPath` for each service
  (`overleaf-start.mjs`). Each long-running process is its own service.
  Immich's `run` line names `node` for its workers; those are services
  too, or a recorded exception if a worker cannot be split out.
- php-fpm re-execs on a binary reload. runit starts the new process.
- `python-app`, `node-app` and `ruby-app` lose `multiprocessing` spawn,
  `child_process.fork` and `bundle exec`. A worker is a second service.
  haproxy already chose this: no master-worker, because a reload
  re-executes haproxy
  ([service-forms.md](service-forms.md)).

**Frozen command lines.** `run:` names the binaries a service may
start. It does not name their arguments. A form that adds `exec` to an
interpreter says so beside that pledge.

**Environment of that line.** leash builds the environment from the
service file. The file does not set `RUBYOPT`, `PYTHONPATH`,
`PYTHONSTARTUP`, `PYTHONHOME`, `NODE_OPTIONS`, `NODE_PATH`,
`PHP_INI_SCAN_DIR`, `BASH_ENV`, `ENV`, `JDK_JAVA_OPTIONS`,
`JAVA_TOOL_OPTIONS` or `_JAVA_OPTIONS`. Absence is the value. An empty
`PHP_INI_SCAN_DIR` is a different setting from an unset one, and the
service file sets neither.

Two flags harden the frozen argv against the process's own working
directory, which leash sets to the service's data directory:

- `python -m` with a writable cwd gets `-P`, so that directory is not
  prepended to `sys.path`. Home Assistant is the case (`dir: /data`).
  `-I` implies `-P` and also drops user site-packages; use it where the
  form's check still passes. `python-app` takes `-I`. Open WebUI
  already passes `-P`.
- `ruby-app` and Mastodon's Ruby lines pass `--disable=rubyopt`.

`--disallow-code-generation-from-strings` refuses Node's `eval` and
`new Function`. It says nothing about paths. Measure it on Mastodon's
streaming server, which pledges no `exec` and does not read `/data`.
It is not a default for Immich, Overleaf or `node-app`.

`open_basedir` remains a list of trees PHP may read. It cannot mean
"compile only a read-only mount": the applications read `/data`, and
`php -d` overrides it.

**A second argv.** The phase-4 kernel
([verified-boot.md](verified-boot.md)) gets one BPF LSM hook,
`bprm_check_security`, in the same build as IPE. Alpine's `linux-virt`
does not put the BPF LSM in `CONFIG_LSM`
([lockdown.md](lockdown.md)). Lockdown stays at confidentiality, which
refuses kprobes and tracepoints; this hook is neither. It runs after
`copy_strings`, so it reads the kernel's copy of argv and env, not the
caller's memory.

The policy is those recorded vectors, matched as exact strings, for
the interpreter paths a form actually execs: `/usr/bin/php`,
`/usr/bin/ruby`, `/usr/bin/node`, `/usr/local/bin/node`,
`/usr/bin/python3`, `/usr/local/bin/python3.12`, `/usr/bin/perl`,
`/bin/bash` and `java`. Bundler
re-execs Ruby with a different argv; the recording allows that vector
and refuses `ruby -e`. A code variable above may only be absent or the
recorded value. A relative path, or an extra `-e`, `-c`, `-r`, `-d` or
`--eval`, fails the match. The call returns `EACCES`, which is the
refused-exec record init already asks for.

ffmpeg and the other native helpers are not in the list. Their
arguments are data. Landlock already decides which binary runs.

init loads the policy from the verity root and pins it before `CAP_BPF`
leaves, as it activates IPE before `CAP_MAC_ADMIN` leaves. An enforcing
root (`/usr/share/werewolf/enforce`) with no policy does not boot.

## Drawbacks

- The BPF LSM is ours to get right, which is why verified-boot.md set
  it aside. This is one hook and a list of strings, generated from
  check boots, not a general policy language.
- A re-exec the check boot never made is refused in production. The
  recording comes from that form's check.
- Alpine's kernel and a bitten machine do not enforce it. There, a
  command line stays frozen only where the pledge has no `exec`.

## Alternatives Considered

- **auditd, or an audit rule on argv.** Audit does not deny. A
  userspace program that killed the process would be late: the script
  has started. lockdown.md left auditd out for that cost, and init
  already locks the audit configuration.
- **kprobe or tracepoint eBPF.** Confidentiality lockdown refuses both.
  Reading the syscall's pointer with `bpf_probe_read_user` also races
  the caller, who can change the bytes before the kernel copies them.
- **seccomp user-notify.** The same race, and the seal refuses a
  listener ([narrow.md](narrow.md)).
- **A regular expression.** `php -d open_basedir=/ /usr/share/moodle/admin/cli/cron.php`
  matches "a path under `/usr`" and honors the attacker's `-d`. An
  exact vector does not match.
- **execveat of a descriptor leash opened.** That fixes the binary.
  The caller still chooses argv.
- **Patching interpreters** so a file on a writable mount is not
  compiled. That is the design that would see `include` and `require`.
  It is not this one.

## Security Considerations

The hook binds root only while nothing after init can unload it.
`CAP_BPF` leaves the bounding set when the policy is pinned. A policy
that allowed any argv under `/usr` would admit `-d` and `-e`; the
policy is whole vectors from the check boot.

Everything reached without `exec` is as it was. Nextcloud still
includes the PHP in its data directory.

## Reliability Considerations

- Fails closed on an enforcing image. A missing policy, or one that
  rejects the service file's own argv, falls back to the last good slot.
- The service file is the argv, so a recording stays valid until that
  line changes. A release that changes it without a new recording does
  not boot the form; the check is what writes the recording.
