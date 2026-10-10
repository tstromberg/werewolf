# OpenSearch

One node of log search: [OpenSearch](https://opensearch.org) 3.9, TLS on, the security plugin on, no demo users. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- Java runs OpenSearch, and the JVM compiles it as it runs. Both are named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 30 -subj /CN=ca
openssl ecparam -name prime256v1 -genkey -noout -out search.key
openssl req -new -key search.key -out search.csr -subj /CN=search
openssl x509 -req -in search.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
	-out search.crt -days 30
howl create opensearch --with opensearch \
	--admin-password admin-password \
	--tls-cert search.crt --tls-key search.key --tls-ca ca.crt
```

The certificate is the server's and the client's: the node presents it to itself. Then `curl --cacert ca.crt -u admin:$(cat admin-password) https://ADDRESS:9200`. Give the machine 3 GB. Indexes are in [OpenSearch's documentation](https://docs.opensearch.org/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 30 -subj /CN=ca
openssl ecparam -name prime256v1 -genkey -noout -out search.key
openssl req -new -key search.key -out search.csr -subj /CN=search
openssl x509 -req -in search.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
	-out search.crt -days 30
howl create opensearch --with opensearch --on gcp --allow-from me \
	--admin-password admin-password \
	--tls-cert search.crt --tls-key search.key --tls-ca ca.crt
```

Replace those files with your corporation's CA, or a [step-ca](../step-ca/README.md) machine, when you have one. Shippers use `https://ADDRESS:9200`. Prefer users that `admin` creates in the security plugin over sharing `admin`.

### Migrating data in

The cluster starts empty. Index through the HTTP API on the address howl prints. This form does not import a snapshot.

### Known Quirks

- There is no demo certificate and no `admin` / `admin` login.
- The transport port listens on loopback, still in TLS.
- One node. A cluster is the same form repeated, which this one is not.
- The heap follows the machine's memory, so it refuses work instead of being killed.

### Network Exposure

- tcp/9200, HTTPS, for clients you allow.
