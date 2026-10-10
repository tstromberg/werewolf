# Kafka

The `kafka` form is an event stream for a corporation's applications:
Apache Kafka 4.3 as one KRaft node, broker and controller, on one leash,
for clients on TLS with SCRAM-SHA-512 alone, every request judged by ACLs
that deny what none allows
([design/corporate.md](../../docs/design/corporate.md)).

## Run your own

```sh
openssl rand -base64 24 >admin-password    # the admin's; keep it
printf 'orders %s\nbilling %s\n' "$(openssl rand -base64 24)" \
	"$(openssl rand -base64 24)" >users        # each application's
howl create events --with kafka --on gcp --allow-from 10.128.0.0/20 \
	--domain kafka.corp.example --tls-cert kafka.crt --tls-key kafka.key \
	--admin ops --admin-password admin-password --users users
```

Clients reach it at `kafka.corp.example:9093`, with `security.protocol=SASL_SSL`
and `sasl.mechanism=SCRAM-SHA-512`. The admin then makes topics and grants
each user its own, with Kafka's tools from any machine that holds them:

```sh
kafka-topics.sh --bootstrap-server kafka.corp.example:9093 \
	--command-config ops.properties --create --topic orders
kafka-acls.sh --bootstrap-server kafka.corp.example:9093 \
	--command-config ops.properties --add --allow-principal User:orders \
	--producer --consumer --topic orders --group orders
```

| Flag | |
| --- | --- |
| `--domain NAME` | required. The name clients reach it by, which its certificate names |
| `--tls-cert FILE`, `--tls-key FILE` | required. Its certificate chain and key, PEM; the key unencrypted PKCS#8 (`openssl pkcs8 -topk8 -nocrypt`) |
| `--admin NAME` | required. The super user, who makes topics, users and ACLs |
| `--admin-password FILE` | required. That user's password, 12 to 1024 bytes |
| `--users FILE` | users made with the cluster, a line each: `NAME PASSWORD` |
| `--cluster-id ID` | its cluster ID, as `kafka-storage.sh random-uuid` prints one; without it, one is made |

## How it is held

- **kafka-setup first.** [cmd/kafka-setup](cmd/kafka-setup/README.md)
  runs before Kafka, on its leash: it writes `server.properties` from the
  image's [/etc/kafka/server.properties](rootfs/etc/kafka/server.properties)
  and the settings, and on a blank disk formats `/data/svc/kafka/log` with
  the admin and the users, so none of them is missing when it first
  listens. It refuses a log directory holding another cluster's ID.
- **Logins over TLS alone.** :9093 takes SCRAM-SHA-512 inside TLS 1.2 or
  1.3; nothing plain, and no anonymous client.
- **ACLs deny by default.** `allow.everyone.if.no.acl.found=false`: a user
  may do only what an ACL grants. The admin is the one super user. Topics
  are made by the admin, never by a client asking for one.
- **The controller on loopback.** :9094 answers this node's own broker,
  which logs in with a password kafka-setup makes at each start, in a file
  only it and root read; no other service can log in there.
- **java, run directly.** Kafka's 43 scripts and bash are pruned; leash
  starts `java ... kafka.Kafka`, whose pledge has no exec.
- **The console, not files.** Kafka's log goes to the console alone, with
  its failed logins and denied requests.
- **Its own limits.** 2 GiB under leash, its heap 1 GiB.

## Drawbacks

- One node: no replication. A corporation's cluster is this node, repeated
  by a form of its own.
- Users from the config are made once, at format; after that the admin
  changes users and passwords through Kafka (`kafka-configs.sh`).
- The JVM is an interpreter's weight and compiles code as it runs (`jit`);
  both are its named weaknesses.

## Checked

`make check-kafka` boots it with its test config ([test/config](test/config)),
and Kafka's own client, run by `java` alone: the admin makes a topic and
grants it to `app`, whose message comes back; `server.properties` is the
kafka user's alone, 0600, without a password from the config; the
controller listens on loopback. Then the attacks: a client without a login
and the admin with a wrong password are refused, and `stranger`, logged
in but named by no ACL, is denied a produce; the topic holds one message.
`make check-shellfree-kafka` boots it as it ships, with no config: Kafka
parks, saying it has no certificate, before kafka-setup runs.
