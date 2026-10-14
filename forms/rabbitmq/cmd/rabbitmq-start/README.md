# rabbitmq-start

## Summary

Start RabbitMQ's native Erlang runtime without its shell wrappers, with a
local application user supplied through the boot configuration.

## Background

The official image's entrypoint, rabbitmq-server and erl are shell
scripts. Werewolf can run the same native erlexec and BEAM programs
directly, with their paths declared in the broker's leash.

## Goals

- Refuse a missing password, an unsafe username or a damaged Erlang cookie.
- Keep passwords out of the runtime's environment and arguments.
- Bind AMQP, epmd and Erlang distribution to loopback.

## Non-Goals

Clustering, management plugins, external listeners and arbitrary Erlang
startup options. A consuming form can explicitly change those policies.

## Detailed design

The program runs inside RabbitMQ's image, as its service user. Leash
copies `rabbitmq/password` to `/tmp/password`; settings supply an optional
username, `app` by default. It creates definitions with a salted SHA-256
password hash, a vhost and application permissions, and deletes the
plaintext copy. The user has no administrator tag. Definitions are
imported each start, so changing the configured password changes login.

The Erlang cookie is generated once under `/data`, mode 0600. A later
start preserves it. Configuration and definitions are written atomically
under `/run`. A random fallback user password prevents the vendor's
guest account from being created if definitions cannot be imported.

It starts native epmd on loopback, then returns to leash, which execs
erlexec. BEAM inherits a fixed environment, node name, distribution port and
immutable plugin list. The broker's whole process tree stays in its cgroup.

## Drawbacks

Runtime paths follow the pinned image's Erlang version. Upgrading that
image requires updating and testing these explicit paths.

## Alternatives Considered

Running the vendor scripts would grant a shell interpreter. A general
shell compatibility layer is unnecessary for startup arguments.

## Security Considerations

Username validation prevents configuration injection. Plaintext passwords
are neither logged nor passed to child processes. No arbitrary program,
plugin installer or privileged helper can run under this leash.

## Reliability Considerations

Initialization errors fail the service before it listens. Leash reaps
both epmd and the broker on shutdown. Boot checks exercise authenticated
AMQP delivery and reject the default guest login.
