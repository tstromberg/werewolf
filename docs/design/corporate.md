# A corporation's machines: the top ten uses

Built, 2026-10-10. Each of the ten uses has a form. Kubernetes nodes
are the eleventh use, and are not built.

## Summary

The ten things a large company stands a VM or a dedicated machine up
for, behind its firewalls and beside its SaaS: its applications and
their data, and the shared services every team leans on. Each gets a
form whose defaults a stranger on the internal network cannot use.

## Background

[startup.md](startup.md) is for a few engineers; a corporation has
thousands of machines, many teams, and an internal network an attacker
reaches first by phishing, not the internet. Its breaches go through
what everyone trusts: a directory with anonymous reads, a broker with
no ACLs, an open egress proxy, a log cluster with its default password.
Its machines live for years, so updates and audit trails matter more.

By our reading of cloud and virtualization surveys, the ten below lead.
A form need not wait for Wolfi: melange builds from a pinned source,
and `image:` runs a project's OCI image ([oci.md](oci.md)).

## Goals

- Each use has a form or a bundle passing `make check-NAME` and
  `check-shellfree-NAME`, its check ending in the attack its defaults
  refuse.
- Each speaks TLS with the corporation's own CA (from `step-ca` or the
  config), and logs every refusal on the console.

## Non-Goals

- Proprietary servers (Oracle, SQL Server, Active Directory, Splunk).
- Clustering: one node of each; a cluster is the next form.
- CI runners: they run anyone's code (forms-catalog.md).

## Detailed design

| Use | Forms | State |
| --- | --- | --- |
| Application servers | `jre-app`, `node-app`, `python-app`, `ruby-app`, `php` | built |
| Relational databases | `postgresql`, `mariadb` | built |
| Load balancing and the edge | `haproxy`, `nginx`, `caddy`, `oauth2-proxy` | built |
| Cache | `valkey` | built |
| Messaging and event streams | `kafka`, `nats`, `mosquitto` | built |
| Directory and sign-on | `openldap`, `keycloak` | built; `keycloak` in [academic.md](academic.md) |
| Metrics, logs and traces | `prometheus`, `loki`, `grafana`, `otel-collector`, `opensearch` | built |
| Secrets and internal PKI | `openbao`, `step-ca` | built |
| Network services | `unbound`, `squid`, `bastion`, `tailscale` | built |
| Code, images and files | `gitea`, `zot`, `minio`, `sftpgo`, `restic-server` | built; `zot` in [startup.md](startup.md) |

| Form | Built by | Defaults; its check's attack |
| --- | --- | --- |
| `jre-app` | Wolfi | `java -jar /usr/lib/app/app.jar` on :8080, heap from `memory`; down until an app is laid; as `node-app` |
| `kafka` | Wolfi, bash pruned | KRaft, one broker and controller, `java` run directly; SASL/SCRAM over TLS, users from the config, made at format; ACLs deny what none allows, its admin the one super user; a produce without a login, and one by a user no ACL names |
| `openldap` | Wolfi | `slapd` on LDAPS alone, its suffix and admin from the config; no anonymous bind or search; passwords stored hashed and never read back; an anonymous search, a cleartext bind |
| `otel-collector` | Wolfi (contrib) | OTLP over TLS with a bearer token; exports to the endpoints the settings name; no debug or pprof extensions; a span sent without the token |
| `opensearch` | Wolfi or image | its security plugin on: TLS on 9200 and between nodes, the admin's password from the config, no demo certificates or users; a search without one |
| `unbound` | Wolfi | as [service-forms.md](service-forms.md): recursive, validating, private ranges alone; a query from a public address |
| `squid` | Wolfi | an egress proxy: sources from the settings' networks, destinations from its domain list, CONNECT to 443 alone, no cache, no `cachemgr`; a CONNECT to an unlisted domain, and to port 25 |

**Kubernetes nodes** (k3s, kubelet with containerd) are the eleventh
use, and the most common new one. They are not built: a kubelet starts
whatever its API server sends, as root, in namespaces it mounts, with
netfilter it writes, which is what werewolf takes away from every
machine ([lockdown.md](lockdown.md), [oci.md](oci.md)). A form for them
would be a `containers` allowance handing back mounts, user namespaces,
`CAP_SYS_ADMIN` and nftables to one service, fence stepping aside for
pod traffic, and posture expecting all of it: a host image, verified
and updated by werewolf, whose workloads werewolf does not hold. That is
worth doing (Bottlerocket and Talos are that), but as its own design.

## Drawbacks

- JVMs (Kafka, Keycloak, OpenSearch) are `jit` and an interpreter's
  weight; each names both as weaknesses.
- Single nodes: a corporation's Kafka and OpenSearch are clusters.
  Each form is the node a cluster form would repeat.

## Alternatives Considered

- **RabbitMQ** beside Kafka: Erlang's VM, and Wolfi's brings busybox;
  `nats` covers queues.
- **CoreDNS or BIND** for DNS: unbound resolves; authoritative zones
  belong to the corporation's DNS provider, and `nsd` when one is asked.
- **Samba as a domain controller**: Python and a shell; Keycloak and
  OpenLDAP serve Linux machines and web sign-on.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A directory or broker answers anyone inside | no anonymous binds; SCRAM and ACLs; TLS everywhere |
| An egress proxy reaches anywhere | listed destinations; CONNECT to 443 alone |
| A default password or demo certificate ships | every credential from the config; missing, the service parks |
| A telemetry endpoint takes forged data | a bearer token; TLS |

## Reliability Considerations

- Kafka formats its log directory once; a reformat would lose data, so
  its setup refuses a directory that already holds another cluster's id.
- Each JVM's heap is set from its `memory`, so it refuses work rather
  than being killed.
