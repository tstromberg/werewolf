# rabbitmq-os-probe

## Summary

Answer Erlang's page-size query and RabbitMQ's disk-space query directly
from kernel data, without running a shell or any other program.

## Background

RabbitMQ's disk monitor starts `/bin/sh -s rabbit_disk_monitor` and sends
`df` commands followed by a carriage-return marker. Erlang wraps
`getconf PAGESIZE` with an end-of-transmission marker. A missing shell
can stall broker startup while a monitor waits for its output.

## Goals

- Preserve real page-size and free-disk-space reporting.
- Reject all requests except those two known upstream protocols.

## Non-Goals

Interpreting shell syntax, executing commands, probing another filesystem
or supporting administrative Erlang command evaluation.

## Detailed design

Inside RabbitMQ's immutable image, `/usr/bin/sh` and its `/bin/sh` alias name this
native program. Leash permits its inode alone. It accepts two exact
argument lists and bounded requests. Page size comes from `AT_PAGESZ`;
disk space comes from `statfs("/data")`. Disk requests must name a plain
path beneath `/data`, without parent traversal or shell metacharacters.
The replies retain upstream's control-character framing. Unknown
requests exit 126; no command is evaluated or passed to another process.

## Drawbacks

Upstream protocol changes require updating and testing the parser.

## Alternatives Considered

A shell grants command interpretation. Disabling disk monitoring loses
backpressure before the persistent disk fills.

## Security Considerations

The helper inherits the broker's restrictions and runs no other program.
Tests reject extra commands and paths outside the broker's data tree.

## Reliability Considerations

Free-space readings are real, rather than a constant that could hide a
full disk. A failed kernel query or unsupported request fails closed.
