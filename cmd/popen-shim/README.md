# popen-shim

## Summary

popen-shim.so is a library that pg-init preloads into PostgreSQL's
`initdb`. It replaces `popen(3)`, `pclose(3)` and `system(3)` with versions
that need no shell and run only commands of the one shape `initdb` writes.

## Background

`initdb` starts the server it is setting up through `popen` and `system`,
which glibc runs as `/bin/sh -c COMMAND`. werewolf has no `/bin/sh`, and
posture checks that there is none. `initdb`'s commands all have one shape:

```
"/usr/libexec/postgresql17/postgres" --boot -F -c log_checkpoints=false
"/usr/libexec/postgresql17/postgres" --single -F -O -j template1 >/dev/null
"/usr/libexec/postgresql17/postgres" --check ... < "/dev/null" > "/dev/null" 2>&1
```

## Goals

- `initdb` works with no shell on the machine.
- Each command is run with exactly the words a shell would have given it.
- Anything a shell would read specially is refused, not interpreted.

## Non-Goals

- Being a shell. It has no pipes, variables, globs, or quoting beyond plain
  double quotes.
- Serving anything but `initdb` and the servers it starts.

## Detailed design

- **The shape**: an absolute program, then plain or double-quoted words,
  then `</dev/null`, `>/dev/null` and `2>&1` (only after `>`), each once.
  A plain word is printable ASCII without a backtick or any of
  `| & ; < > ( ) $ \ ' " * ? [ ] { } ~ # !`. A quoted word may not hold
  `"`, `$`, a backtick, `\` or a control character.
  At most 64 words and 4096 bytes.
- **Refused**: anything else. `popen` returns NULL and `system` -1, with
  errno `ENOEXEC`, and one line on stderr names the command with control
  characters shown as `?`. So `initdb` fails visibly, and a command cannot
  write escape sequences to the terminal.
- **Running**: it forks, and the child makes only system calls: it moves
  the pipe end onto stdin or stdout, opens `/dev/null` onto what is
  redirected, then calls `execve` with the caller's environment. If
  `execve` fails, the child exits 127, as a shell would.
- **`locale -a`**: the servers `initdb` starts keep the library, and one
  runs this to import the system's locales as collations. There are none
  (PostgreSQL's C and POSIX need no import), so it reads as empty and
  closes with success.
- **Bookkeeping**: at most eight streams are open at once. `pclose` of a
  stream it did not open fails with `ECHILD`, as in glibc. Its pipes are
  close-on-exec, so one child never holds another's.

## Drawbacks

- A future `initdb` that writes another shape fails until the shim learns
  it. The failure is loud and names the command.
- It is built against glibc, as `initdb` is, unlike werewolf's static
  programs.

## Alternatives Considered

### Ship a shell for initdb
One shell anywhere on the root is a shell for every exploit, and posture's
no-shell check would need an exception.

### Patch initdb
werewolf would have to carry a patched PostgreSQL across every release.
The library replaces three functions without touching the package.

### Any redirection target
`initdb` names only `/dev/null`. Taking any file would let the library
create and truncate files in every setup server, for nothing.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Shell injection | No shell: a command is words, or it is refused. |
| A word read differently from a shell | Random commands compared word for word against `/bin/sh` in its tests. |
| Writing files | Redirections only to `/dev/null`: it never creates or truncates a file. |
| A terminal attack through a refused command | Control characters shown as `?`. |
| The library in the running server | Only in `initdb` and its setup servers. The server leash starts has no `LD_PRELOAD`. |

## Reliability Considerations

- **Fails loudly**: a refused command is named on stderr, and `initdb`
  stops there.
- **A caller with stdin or stdout closed**: a pipe end or `/dev/null` that
  lands on its own descriptor is kept, not closed.
- **Tested**: 15 unit tests, 10 of them on Linux, including a
  word-for-word comparison against `/bin/sh` over thousands of random
  commands; `check-persist` runs `initdb` through it.
