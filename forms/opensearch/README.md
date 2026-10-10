# OpenSearch

One node of log search: [OpenSearch](https://opensearch.org) 3.9, TLS on, the security plugin on, no demo users.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

You need a CA and a certificate it signs for the machine's name, usable as both server and client. The node presents it to itself.

```sh
openssl rand -base64 24 >admin-password
howl create search --with opensearch --on lima \
	--admin-password admin-password \
	--tls-cert search.crt --tls-key search.key --tls-ca ca.crt
```

Then `curl --cacert ca.crt -u admin https://127.0.0.1:9200`. Give the machine 3 GB.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create search --with opensearch --on gcp --allow-from 10.128.0.0/20 \
	--admin-password admin-password \
	--tls-cert search.crt --tls-key search.key --tls-ca ca.crt
```

Use your corporation's CA, or a [step-ca](../step-ca/README.md) machine. Shippers use `https://search.example.com:9200`. Prefer users that `admin` creates in the security plugin over sharing `admin`.

### Known Quirks

- There is no demo certificate and no `admin` / `admin` login.
- The transport port 9300 listens on loopback only, still in TLS.
- One node. A cluster is the same form repeated, which this one is not.
- The heap follows the machine's memory, so it refuses work instead of being killed.

### Network Exposure

- tcp/9200, HTTPS, for clients you allow. tcp/9300 on loopback.

### Security Weaknesses

- Java runs OpenSearch, and the JVM compiles it as it runs. Both are named in `form.yaml`.
