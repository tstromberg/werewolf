# Kafka

An event stream for applications inside a company: [Apache Kafka](https://kafka.apache.org) 4.3 as one KRaft node. Clients use TLS and SCRAM-SHA-512. What no ACL allows is denied. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- Java runs Kafka, and the JVM compiles it as it runs. Both are named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
mkdir -p config/kafka
printf 'orders %s\n' "$(openssl rand -base64 18)" >config/kafka/users
openssl ecparam -name prime256v1 -genkey -noout -out kafka.pem
openssl req -new -x509 -key kafka.pem -out kafka.crt -days 30 -subj /CN=kafka.home.arpa
openssl pkcs8 -topk8 -nocrypt -in kafka.pem -out kafka.key
howl create kafka --with kafka --config config \
	--domain kafka.home.arpa --tls-cert kafka.crt --tls-key kafka.key \
	--admin ops --admin-password admin-password
```

Clients use `ADDRESS:9093`, `security.protocol=SASL_SSL`, `sasl.mechanism=SCRAM-SHA-512`. `ops` is the super user. Topics and ACLs are in [Kafka's documentation](https://kafka.apache.org/documentation/#security_sasl).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
mkdir -p config/kafka
printf 'orders %s\nbilling %s\n' "$(openssl rand -base64 18)" \
	"$(openssl rand -base64 18)" >config/kafka/users
openssl ecparam -name prime256v1 -genkey -noout -out kafka.pem
openssl req -new -x509 -key kafka.pem -out kafka.crt -days 30 -subj /CN=kafka.corp.example
openssl pkcs8 -topk8 -nocrypt -in kafka.pem -out kafka.key
howl create kafka --with kafka --on gcp --allow-from me --config config \
	--domain kafka.corp.example --tls-cert kafka.crt --tls-key kafka.key \
	--admin ops --admin-password admin-password
```

From a machine that has Kafka's tools, `ops` creates a topic and grants `orders` that topic alone. Passwords are 12 to 1024 bytes.

### Migrating data in

Topics start empty. Producers write to the address howl prints. This form does not import a log.

### Known Quirks

- No shell and no Kafka scripts on the machine. Administration is from outside.
- Users are created when the log is first formatted, not on a later start.
- One broker and one controller. A cluster would repeat this node.
- Bash that the package depends on is removed. Java is started directly.
- The accounts file is `config/kafka/users`. howl's `--users` is for ssh, which this form does not run.

### Network Exposure

- tcp/9093, TLS, for clients you allow. The controller listens on loopback.
