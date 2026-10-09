# sh-shim

## Summary

sh-shim is not a shell. Programs that insist on `sh -c COMMAND` get it in
its place: it runs COMMAND's one program with sh's words and refuses
anything a shell would have to read. The `sh-shim` form makes it
`/bin/sh` where nothing else is, and lets every leashed service run it.

## Background

supercronic runs each job as `$SHELL -c COMMAND`; libc's `system` and
`popen`, Ruby's and Python's run `/bin/sh -c`. werewolf ships no shell,
and posture checks there is none. Most such commands are one program and
its arguments, which needs no shell, only the words a shell would make.
sh-shim is an adapter, not a security control. Landlock decides what a
leashed service, and all it starts, may execute: the programs its service
file names. The `sh` allowance adds sh-shim's file, which starts only
those programs, so it hands no service anything new.

## Goals

- A command of one program runs as under sh; one written for a shell
  fails loudly instead of running mangled.
- A form that brings a real shell keeps it as `/bin/sh`.

## Non-Goals

- Being a shell: no pipes, redirections, variables, globs, `;`, `&&`,
  builtins, scripts or `exec`. A command that needs them is a program,
  or a form with busybox, which names it in a `run` line and a weakness.
  Nor confining the program it runs: leash does.

## Detailed design

- **Where:** `/usr/lib/werewolf/sh-shim`, in forms that take the
  `sh-shim` form. The build lays `/bin/sh` as a link to it first, under
  the packages, so a package's `sh` (busybox's, in every DEV build) or a
  later form's replaces it; the updater links it last, only if absent.
  The form's `allow: [sh]` grants its file, by inode: never busybox.
- **Called** only as `sh -c [--] COMMAND [NAME [ARG...]]`; glibc and musl
  pass `--`. NAME and ARGs, sh's `$0`, `$1`..., expand nowhere. Alone, as
  a login, with an option (`-e`, `-s`) or a script, as a `#!/bin/sh`
  line runs it: `sh-shim: not a shell` and exit 1. Run set-user-ID or
  with gained capabilities (AT_SECURE): 126, since PATH is a caller's.
- **Words** split on spaces and tabs. A single-quoted piece is literal; a
  double-quoted one too, but may not hold `$`, a backtick or `\`, which
  sh would expand there. Touching pieces are one word: `a'b c'` is `ab c`.
- **Refused**, with one line on stderr and exit 126: unquoted ``| & ; <
  > ( ) $ ` \ * ? [ ] ~ #`` or a control character but tab; an unquoted
  `NAME=` first word; a first word sh never looks for on PATH, however
  quoted: POSIX's reserved words, special built-ins and intrinsic
  utilities (`if`, `!`, `exec`, `exit`, `cd`, `kill`...); an unterminated
  quote. An empty COMMAND exits 0, as `sh -c ''` does.
- **Running:** a first word with a `/` is executed as given; any other is
  looked for along `PATH` (`/usr/sbin:/usr/bin:/sbin:/bin` when unset),
  skipping empty and relative entries, so never in the current
  directory. The environment passes unchanged. No program: 127. One that
  cannot run (Landlock's EACCES, a script with no `#!`): 126.
- **Logs** only on error, as `sh-shim: ...`, naming the refused character
  or word, never the command, which may hold a secret.

## Drawbacks

- A command that relied on a shell (`a && b`, `> file`, `$HOME`) must
  become a program, or one command each. sh-shim says what it refused.
- Where busybox is `/bin/sh` (DEV builds, forms with `sshd`), a leashed
  service calling `/bin/sh` is refused unless a `run` line names busybox.
  The cron form names the shim in `SHELL`, so its jobs run the same in both.

## Alternatives Considered

- **Busybox's shell:** a shell for every exploit, and an excuse for
  posture's `programs-no-shell` in every form with a timer.
- **A little more, `&&`, `>`, `$VAR`:** a parser almost sh's runs what sh
  would not. Refusing it all keeps the rule short.
- **popen-shim's parser:** it reads only the shapes initdb writes, inside
  initdb. One parser for both would widen it or narrow this one.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A command escapes into a shell | There is none; sh-shim interprets nothing. |
| A service runs what its form did not mean | Landlock: only `run` programs execute, so sh-shim, too, starts nothing else. |
| The allowance grants busybox | It grants sh-shim's file by inode, not the name `/bin/sh`. |
| A word read differently from sh | Random commands compared word for word against `/bin/sh` in its tests. |
| A program planted where a job runs | PATH's empty and relative entries are skipped. |
| A set-user-ID caller's PATH; forged console lines | Refused under AT_SECURE; control characters in a name shown as `?`. |

## Reliability Considerations

- **Fails loudly:** one line on stderr, which the caller logs, and a
  non-zero exit. **No state:** one parse into fixed buffers sized to
  Linux's largest argument, one `execve` per `PATH` entry.
- **Tested:** 14 unit tests: words and quotes, every refused byte and
  control character, sh's own words, assignments, the calls it accepts,
  the buffers' bounds, `PATH`, 2000 random commands against `/bin/sh` and
  100,000 of random bytes. `make check-sh-shim` runs it on a machine;
  `check-cron` runs a job through it, leashed, by the allowance alone.
