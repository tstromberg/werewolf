# sh-shim(1)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

sh-shim — execute a single command using restricted shell word syntax

## SYNOPSIS

**sh-shim** **-c** [**--**] *command* [*name* [*argument ...*]]

## DESCRIPTION

The **sh-shim** utility adapts callers of sh -c to one direct program execution. Some
forms install it as /bin/sh. It is not an interactive shell and does not interpret
scripts. The optional name and arguments are accepted but never expanded.

Spaces and tabs separate words. Single quotes preserve literal text; double quotes do
likewise but refuse characters that a shell would expand. Adjacent quoted and
unquoted pieces form one word. Pipes, command chaining, substitutions, assignments,
globbing, shell builtins and reserved words are refused.

Only trailing redirections to the literal /dev/null are supported: one input and one
output redirection, and 2>&1 after output is redirected. No command word may follow a
redirection. Parsing finishes before any descriptor is changed.

A program name containing a slash is executed as given. Other names are searched on
PATH, skipping empty and relative entries. The environment passes through unchanged.
Execution with gained privileges is refused. The service's existing Landlock rules
decide which programs may run; this adapter grants no additional authority.

## ENVIRONMENT

- `PATH`

  Executable search path. The default is /usr/sbin:/usr/bin:/sbin:/bin.

## EXIT STATUS

An empty command exits 0. Unsupported invocation exits 1; refused syntax or an
executable that cannot run exits 126; a missing program exits 127. Otherwise the
executed program supplies the status.

## SEE ALSO

leash(8)
