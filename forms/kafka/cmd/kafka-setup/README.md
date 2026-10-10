# kafka-setup

## Summary

kafka-setup is Kafka's `before` step. It writes `server.properties` at
every start and formats the log directory once, with the config's users,
so the broker never serves without them.

## Background

The `kafka` form runs Kafka 4.3 as one KRaft node, broker and controller,
as the `kafka` user. KRaft keeps users, ACLs and topics in a metadata log
that Kafka's StorageTool must create before the first start; its SCRAM
credentials can be added only then or, later, through the running broker.
Kafka's scripts that do this are bash; werewolf has no shell. leash runs
kafka-setup as the service's user, under its Landlock rules, after
copying the config's files to `/run/svc/kafka` and rendering its settings
into the environment (forms/kafka/form.yaml).

## Goals

- No first start without the admin: its SCRAM credential is in the
  metadata before the broker listens.
- A log directory is formatted once, and never over another cluster's.
- No password on a command line, in a log line, or in `server.properties`.

## Non-Goals

- Changing users or ACLs on a running cluster: Kafka's admin API does that.
- More than one node.

## Detailed design

1. **Settings**: `KAFKA_DOMAIN`, the name clients reach the broker by;
   `KAFKA_ADMIN`, the super user; `KAFKA_CLUSTER_ID`, optional. A name is
   lower-case letters, digits, `.`, `-` and `_`, as SCRAM's arguments hold
   it; a cluster ID is Kafka's, 22 characters of URL-safe base64.
2. **TLS**: the certificate must be PEM and the key unencrypted PKCS#8,
   which is what Kafka's PEM keystore reads; anything else is refused with
   the `openssl` line that converts it. Both go into `tls.pem`, 0600.
3. **server.properties**: `/etc/kafka/server.properties` from the image,
   then `advertised.listeners`, `super.users` (the admin, and `_node`) and
   the controller listener's PLAIN login. `_node` is how this node's broker
   logs in to its controller on loopback; its password is 16 random bytes
   made at each start, so no other process on the machine can log in
   there. No config user can be named `_node`.
4. **Formatted**: with `log/meta.properties`, its cluster ID is kept, unless
   the settings name another: then kafka-setup says both and fails, rather
   than format over a cluster. A directory of another node ID fails too.
5. **Not formatted**: the admin from `admin-password`, then each line of
   `users` (`NAME PASSWORD`, the password the rest of the line, 12 to 1024
   bytes, no control characters). For each, a random 24-byte salt and the
   salted password, PBKDF2-HMAC-SHA-512 with 8192 iterations, as Kafka
   computes it; the formatter takes these, not the password, and splits its
   arguments at commas, which a password may hold. Then `java ...
   kafka.tools.StorageTool format --standalone` with the cluster ID (the
   setting's, or 16 random bytes). StorageTool writes `meta.properties`
   last, so a format cut short runs again at the next start.
6. **Logging**: one console line per start: what it wrote and kept or
   formatted, or why not. StorageTool's output lists the records it wrote,
   SCRAM keys among them, so only its error output reaches the console.

## Drawbacks

- Users are made once. A password changed in the config later changes
  nothing; the admin changes it through Kafka.
- The formatter is a JVM: the first start takes seconds more.

## Alternatives Considered

- **Passwords on the formatter's command line**: visible to root, and a
  comma in one would split it.
- **The controller listener in plain text**: every process on the machine
  could reach it on loopback, as a super user.
- **Static voters** (`controller.quorum.voters`): Kafka 4's own sample
  formats a standalone dynamic quorum, which a later controller can join.
