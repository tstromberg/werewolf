# OpenSearch

The `opensearch` form is one node of log search: OpenSearch 3.9 on one
leash, its data on `/data`, its security plugin on. It answers HTTPS on
:9200 with your certificate, to `admin` by the password you give and to
the users `admin` makes; its transport listens on loopback alone, in TLS
too ([design/corporate.md](../../docs/design/corporate.md)). No demo
certificate, demo user or anonymous access.

## Run your own

You need a CA your clients trust, such as your corporation's or a
[step-ca](../step-ca/README.md) machine's, and a certificate it signs for
the machine's name, usable by server and client (the node's transport
presents it to itself).

```sh
openssl rand -base64 24 >admin-password      # admin's; keep it
howl create search --with opensearch --on gcp --allow-from 10.128.0.0/20 \
	--admin-password admin-password \
	--tls-cert search.crt --tls-key search.key --tls-ca ca.crt
```

Shippers and dashboards reach `https://search.example.com:9200` as
`admin`, or better as users `admin` adds through the security plugin's
API (`_plugins/_security/api/internalusers`) with roles of their own.

| Flag | |
| --- | --- |
| `--admin-password FILE` | required. `admin`'s password, 12 to 72 bytes |
| `--tls-cert FILE` | required. The machine's certificate, PEM, its chain after it |
| `--tls-key FILE` | required. Its key, PEM (PKCS#8) |
| `--tls-ca FILE` | required. The CA that signed it, PEM |

## How it is held

- **No bash.** Wolfi's opensearch-3 stopped at 3.6 and brings bash and
  busybox, so [melange](melange/opensearch.yaml) lays upstream's release
  without its JDK or scripts, and the security plugin without its demo
  installer and tools. java starts OpenSearch directly with the options
  `bin/opensearch` would compute (`/usr/share/opensearch/java.args`), on
  Wolfi's openjdk-25-jre.
- **opensearch-setup first.** [cmd/opensearch-setup](cmd/opensearch-setup/opensearch-setup.zig)
  runs before it, on its leash: it copies `/etc/opensearch` into
  `/run/svc/opensearch`, OpenSearch's configuration directory, which it
  must write (its keystore), writes `internal_users.yml` with `admin`
  alone, by a bcrypt hash, and removes the password's copy.
- **The security index from those files.** On the first start the
  security plugin makes its index from them
  (`allow_default_init_securityindex`); `admin` holds `all_access`, and
  no other user exists. Basic auth against those users alone: no
  anonymous access, no proxy headers; an address with 10 failed logins
  in an hour waits 10 minutes.
- **TLS.** HTTPS 1.2 or 1.3 on :9200, nothing plain; transport TLS 1.3 on
  127.0.0.1:9300, which fence also holds to loopback. The plugin refuses
  its demo certificates, and the image has none.
- **Security events on the console.** Failed logins, refused requests
  and changes to the security configuration, by the audit log's log4j
  sink, beside OpenSearch's own log.
- **Its own limits.** 2 GiB under leash, a 1 GiB heap, 512 MiB of direct
  memory; 65536 files. It reaches nothing on the network and runs
  nothing; its pledge has no exec.

## Drawbacks

- One node: a corporation's OpenSearch is a cluster. This is the node a
  cluster form would repeat.
- `admin`'s password is the config's at the first start. After that the
  security index on `/data` holds it: change it with
  `PUT _plugins/_security/api/account`, and the config's file then says
  nothing.
- The JVM is `jit` and an interpreter: the form names both weaknesses.
- OpenSearch's own seccomp filter (`bootstrap.system_call_filter`) is
  not installed: JNA cannot load its library from a `noexec` directory.
  leash's pledge already refuses `execve`.
- `vm.max_map_count` is the kernel's 65530, not the 262144 OpenSearch
  asks for; the bootstrap check is not enforced on a single node bound
  to loopback for transport. Many shards may exhaust it.

## Checked

`make check-opensearch` boots it with its test config ([test/config](test/config)):
`admin`'s health over HTTPS, with the test CA; `admin` indexes a log
line and finds it; the security index holds `admin` alone, the rendered
file a bcrypt hash, and the password's copy is gone; transport listens
on loopback alone; and the attacks: plain HTTP on :9200 gets no answer,
a request without a login and one as the demo's `admin:admin` get 401,
and the image holds no demo certificate. `make check-shellfree-opensearch`
boots it as it ships, with no config: OpenSearch parks, saying it has no
password, before opensearch-setup writes anything.
