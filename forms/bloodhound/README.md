# BloodHound - Hardened VM

Active Directory graphs: [BloodHound CE](https://bloodhound.specterops.io/), behind Caddy, with Neo4j on loopback Bolt and PostgreSQL. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/bloodhound/index.html).

## Security Posture

- BloodHound and its metrics listen on loopback. Neo4j's HTTP is off. Bolt requires a password.
- Cypher that writes is refused, and the complexity limit stays on. A collector's zip is ingested by the application.
- The administrator is `admin`, recreated from the config at each start. Neo4j's password is set once, before Neo4j's first start.
- PostgreSQL takes one role, over loopback, and only BloodHound may connect.

### Weaknesses

- Java runs Neo4j, and the JVM compiles it as it runs. Both are named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
openssl rand -base64 18 >neo4j-password
cp neo4j-password graph-password
howl create bloodhound --with bloodhound --domain bh.home.arpa \
	--admin-password admin-password --neo4j-password neo4j-password \
	--graph-password graph-password
```

`graph-password` is the same file as `neo4j-password`: Neo4j and BloodHound each take their own copy. Open `https://bh.home.arpa` and sign in as `admin`. Give the machine 6 GB. Collectors are in [BloodHound's documentation](https://bloodhound.specterops.io/home).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
openssl rand -base64 18 >neo4j-password
cp neo4j-password graph-password
howl create bloodhound --with bloodhound --on gcp --allow-from me \
	--domain bh.example.com --admin-password admin-password \
	--neo4j-password neo4j-password --graph-password graph-password
```

Sign in at `https://bh.example.com`. Upload a collector's zip there. The graph is not on the network.

### Importing data

The databases start empty. This form does not import a Neo4j dump.

### Known Quirks

- Neo4j's password is set once. Changing `neo4j-password` later does not change Neo4j, and `graph-password` must still match it.
- The administrator password is the config's at every start.
- Twelve characters at least, and the first character is not `-`.

### Network Exposure

- listen: tcp/80 tcp/443 *
- connect: tcp/443 * and udp/53 tcp/53 *
