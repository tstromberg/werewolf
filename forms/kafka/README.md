# Kafka

An event stream for applications inside a company: [Apache Kafka](https://kafka.apache.org) 4.3 as one KRaft node. Clients use TLS and SCRAM-SHA-512. What no ACL allows is denied.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
printf 'orders %s\n' "$(openssl rand -base64 24)" >users
howl create events --with kafka --on lima \
	--domain kafka.home.arpa --tls-cert kafka.crt --tls-key kafka.key \
	--admin ops --admin-password admin-password --users users
```

The key must be unencrypted PKCS#8: `openssl pkcs8 -topk8 -nocrypt`. Clients use port 9093, `security.protocol=SASL_SSL`, `sasl.mechanism=SCRAM-SHA-512`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
printf 'orders %s\nbilling %s\n' "$(openssl rand -base64 24)" \
	"$(openssl rand -base64 24)" >users
howl create events --with kafka --on gcp --allow-from 10.128.0.0/20 \
	--domain kafka.corp.example --tls-cert kafka.crt --tls-key kafka.key \
	--admin ops --admin-password admin-password --users users
```

`ops` is the one super user. From a machine that has Kafka's tools, `ops` creates a topic and grants `orders` that topic alone. Passwords are 12 to 1024 bytes. The log directory is formatted once; a directory that already holds another cluster's id is refused.

### Known Quirks

- No shell and no Kafka scripts on the machine. Administration is from outside.
- Users are created when the log is first formatted, not on a later start.
- One broker and one controller. A cluster would repeat this node.
- Bash that the package depends on is removed. Java is started directly.

### Network Exposure

- tcp/9093, TLS, for clients you allow. The controller is on loopback.

### Security Weaknesses

- Java runs Kafka, and the JVM compiles it as it runs. Both are named in `form.yaml`.
