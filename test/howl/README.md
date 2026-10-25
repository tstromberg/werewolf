# howl's command-line cases

## Summary
`run.zig` runs the cases in `cases.yaml` against `build/host/howl`, or make, and
checks what each run says, writes and runs. It is also the stub for every tool a
case stands in for.

## Background
howl's decisions are unit-tested where they live in `cmd/howl`: refusal order
(`howl.zig`), SSH logins and agents (`verbs.zig`, `ssh-agent.zig`), the local
account (`keys.zig`), form discovery (`discovery.zig`) and the lock (`lock.zig`).
What only shows from outside stays here: the exit status, a refusal said before any
provider tool ran or a machine was replaced, files left in a tree, and the tools
run, with their arguments.

## Goals

- Every case a line in a table; no case needs an interpreter or a VM.
- A stub records each call and answers only as its case says.
- A refusal that runs no tool shows as one: a case's `ran` defaults to none.

## Non-Goals

- A scripting language. Ordering, fixtures and checks beyond the table are Zig.
- Testing howl's decisions again; their unit tests do.

## Detailed design
`make test` runs `run HOWL cases.yaml SUITE...`: `_test/howl-smoke` takes all
suites but `lock`, which `_test/howl-lock` runs. The table is read with
`lib/form.zig`'s strict YAML; an unknown key, step, check or tool fails at once.

A suite runs its cases in order in one tree under `/tmp`, laid out by the `Step` of
its name, with `tools` linked to `run` in a `bin` first on `PATH`. A stub knows
its tool by its name, appends a call record (its arguments and the `record`
variables), and answers with the first `reply` whose `when` words its arguments all
hold; a case's replies come before its suite's. With no reply it exits 97.

| Suite key | Means |
| --- | --- |
| `program`, `cwd` | `make` instead of howl; `checkout` to run in the checkout |
| `tools`, `reply`, `record` | the stubs, their answers, variables they record |
| `env`, `unset` | variables set, or removed, for every case |
| `keep` | files no case may change |

| Case key | Checks |
| --- | --- |
| `args`, `env`, `cwd` | the line, with `{root}` the tree; variables; a subdirectory |
| `before`, `after` | a `Step` that changes the tree first; a `Check` in Zig after |
| `status`, `stdout`, `stderr` | the exit status (0 by default); strings said |
| `stdout-lacks` | strings not said |
| `ran` | the tools run, in order, a run of calls to one tool listed once |
| `calls` | `starts`, `ends`, `has` or `lacks` of a tool's last arguments |
| `files`, `absent` | a file's `lines` or what it `has`; what must not exist |
| `changed`, `unchanged` | files the run must change, or must leave as they were |

A path `TAR:ENTRY` is an entry of a tar. The `apko-lock` reply writes a lock bound
to its config's sha256; `dedicated-agent` checks that ssh-add and ssh shared one
new agent, which ended with the connection.

Run `make _test/howl-smoke _test/howl-lock _test/test/howl/run.zig`; `make -n
_test/howl-lock` shows the command, which takes suite names. A failed suite keeps
its tree and says where.

## Drawbacks
The `ssh` suite waits for real `ssh-agent`s to notice their command ended, up to
10 seconds each, twice.
