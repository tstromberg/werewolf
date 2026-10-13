# Script argv enforcement

Proposed details for [script arguments](script-argv.md). Not built.

## Interpreter-specific flags

Two flags harden the frozen argv against the process's own working directory,
which leash sets to the service's data directory:

- `python -m` with a writable cwd gets `-P`, so that directory is not prepended
  to `sys.path`. Home Assistant is the case (`dir: /data`). `-I` implies `-P`
  and also drops user site-packages; use it where the form's check still passes.
  `python-app` takes `-I`. Open WebUI already passes `-P`.
- `ruby-app` and Mastodon's Ruby lines pass `--disable=rubyopt`.

`--disallow-code-generation-from-strings` refuses Node's `eval` and
`new Function`. It says nothing about paths. Measure it on Mastodon's streaming
server, which pledges no `exec` and does not read `/data`. It is not a default
for Immich, Overleaf or `node-app`.

`open_basedir` remains a list of trees PHP may read. It cannot mean "compile
only a read-only mount": the applications read `/data`, and `php -d` overrides
it.

## A second argv

The phase-4 kernel ([verified-boot.md](verified-boot.md)) gets one BPF LSM hook,
`bprm_check_security`, in the same build as IPE. Alpine's `linux-virt` does not
put the BPF LSM in `CONFIG_LSM` ([lockdown.md](lockdown.md)). Lockdown stays at
confidentiality, which refuses kprobes and tracepoints; this hook is neither.
It runs after `copy_strings`, so it reads the kernel's copy of argv and env,
not the caller's memory.

The policy is recorded vectors, matched as exact strings, for interpreter paths
a form actually execs: `/usr/bin/php`, `/usr/bin/ruby`, `/usr/bin/node`,
`/usr/local/bin/node`, `/usr/bin/python3`, `/usr/local/bin/python3.12`,
`/usr/bin/perl`, `/bin/bash` and `java`. Bundler re-execs Ruby with a different
argv; the recording allows that vector and refuses `ruby -e`. A code variable
may only be absent or the recorded value. A relative path or an extra `-e`,
`-c`, `-r`, `-d` or `--eval` fails the match. The call returns `EACCES`, which
is the refused-exec record init already asks for.

ffmpeg and other native helpers are not in the list. Their arguments are data.
Landlock already decides which binary runs.

init loads the policy from the verity root and pins it before `CAP_BPF` leaves,
as it activates IPE before `CAP_MAC_ADMIN` leaves. An enforcing root
(`/usr/share/werewolf/enforce`) with no policy does not boot.

## Drawbacks

- The BPF LSM is ours to get right, which is why verified-boot.md set it aside.
  This is one hook and a list of strings, generated from check boots, not a
  general policy language.
- A re-exec the check boot never made is refused in production. The recording
  comes from that form's check.
- Alpine's kernel and a bitten machine do not enforce it. There, a command line
  stays frozen only where the pledge has no `exec`.

## Alternatives considered

- **auditd, or an audit rule on argv.** Audit does not deny. A userspace
  program that killed the process would be late: the script has started.
  lockdown.md left auditd out for that cost, and init already locks the audit
  configuration.
- **kprobe or tracepoint eBPF.** Confidentiality lockdown refuses both.
  Reading the syscall's pointer with `bpf_probe_read_user` also races the
  caller, who can change the bytes before the kernel copies them.
- **seccomp user-notify.** The same race, and the seal refuses a listener
  ([narrow.md](narrow.md)).
- **A regular expression.** `php -d open_basedir=/ /usr/share/moodle/admin/cli/cron.php`
  matches a path under `/usr` and honors the attacker's `-d`. An exact vector
  does not match.
- **execveat of a descriptor leash opened.** That fixes the binary. The caller
  still chooses argv.
- **Patching interpreters** so a file on a writable mount is not compiled. That
  design would see `include` and `require`; it is not this one.

## Security considerations

The hook binds root only while nothing after init can unload it. `CAP_BPF`
leaves the bounding set when the policy is pinned. A policy that allowed any
argv under `/usr` would admit `-d` and `-e`; the policy is whole vectors from
the check boot.

Everything reached without `exec` is as it was. Nextcloud still includes the
PHP in its data directory.

## Reliability considerations

- Fails closed on an enforcing image. A missing policy, or one that rejects the
  service file's own argv, falls back to the last good slot.
- The service file is the argv, so a recording stays valid until that line
  changes. A release that changes it without a new recording does not boot the
  form; the check is what writes the recording.
