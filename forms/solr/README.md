# Solr

## Summary

Apache Solr 10.0.0 on hardened OpenJDK 27, on loopback port 8983 at `/solr/`.
The application package contains no Bash, BusyBox, JVM, or shell entrypoint.
The JVM comes from the signed hardened-packages repository.

## Background

Wolfi's Solr package depends on Bash, BusyBox and OpenJDK 21. This form packages
Apache's distribution without its launchers and invokes Jetty through Java directly.

## Goals

- A usable Solr server, persistent cores, console logs, and no shell.
- A separate UID, a bounded heap and cgroup, and no outbound network.

## Non-Goals

SolrCloud and a public unauthenticated administrator endpoint.

## Detailed design

`howl create search --with solr --build` builds the package and machine. Port 8983
listens on loopback; expose it through an authenticated proxy or SSH forwarding.
The normal administrator UI is `/solr/`; the APIs keep their upstream paths.

`/usr/lib/solr/setup` initializes `/data/svc/solr/home` as the service user, preserving
existing configuration. Packaged configsets are copied into that private home so
managed schemas can evolve. Java starts the packaged `server/start.jar` directly.
Log4j writes to stdout. Data stays in the service's own persistent directory.

Use `howl test --with solr --iterate --driver test-solr` for a retained development
VM. `howl test --with solr` checks a clean seed, indexing, reboot persistence,
confinement, the hardened JVM, and a shell-free production boot.

## Drawbacks

The pinned application package must be updated when Solr publishes a release.

## Alternatives Considered

Wolfi's package and Apache's Docker entrypoint bring shell launchers and a different
JVM. Packaging the application separately keeps hardened Java as the only runtime.

## Security Considerations

The service has no exec promise or outbound connections. The root is verified and
read-only. Solr is reachable only on loopback until an administrator exposes it.

## Reliability Considerations

The JVM exits on an exhausted heap; runit restarts it. A missing data disk or failed
home initialization parks the service rather than starting with temporary storage.
