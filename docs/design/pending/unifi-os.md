# UniFi OS on Werewolf

**Status:** Pending as of 2026-10-27

## Summary

Run UniFi OS Server's applications on Werewolf, with a verified read-only
image and a leash per service. First prove the console and Network can
start without systemd or a container runtime; host management comes later.

## Background

Ubiquiti ships UniFi OS Server as an installer containing an OCI image.
The image runs UniFi Core, Network, identity services, PostgreSQL, MongoDB,
RabbitMQ and nginx under systemd. Werewolf already bakes OCI trees into
its verified root and starts their binaries directly.

## Goals

- Reusable [MongoDB](../../../forms/mongodb/README.md) and RabbitMQ forms,
  composed into UniFi OS with `with`, alongside PostgreSQL.
- Start the OS console and Network under individual leashes.
- Keep databases, keys and configuration on `/data`, application code in the image.
- Test onboarding, adoption, backup restore and retained data across reboot.

## Non-Goals

- Claim complete UniFi OS compatibility before those features are exercised.
- Install additional applications or replace executable files at runtime.
- Grant applications root, general service-control access or a writable system image.

## Detailed design

Inspect the pinned 5.1.42 vendor image, initially from the community mirror
`ghcr.io/lemker/uosserver`, index digest
`sha256:7b66869dacf35184d856a12dee146437abf725608b5cfad20e543e3f7742059b`.
The mirror's claim of vendor origin is not vendor authentication; an
official installer extraction and provenance check precede release.

Translate systemd units into explicit service manifests. Keep the vendor
users' names where applications depend on them. Replace privileged
pre-start scripts with confined helpers and declarative database setup.
Use separate MongoDB and RabbitMQ forms rather than duplicating their
startup and storage inside UniFi's form.

UniFi Core's pre-start hook creates a PostgreSQL role and database,
prepares configuration and timezone files, and restarts nginx. Network's
unit starts Java directly and uses helpers for paths and initialization.
Network also needs `-Dunifi-os.server=true` from the vendor's environment
file; otherwise its hardware-console identification path rejects this VM.
Keep inform port 8080 distinct from its local API port 8081. Its mandatory
support connector uses 28082; Werewolf restricts this and the other management
ports to local access even when vendor code binds all interfaces.
Network's bundled validator requires a version-5 UUID. Core's pre-start
hook hashes a random name in the DNS namespace, syncs a private temporary
file, then links it into place without replacing an existing identity.
Malformed or incompatible identities fail closed; upgrades never rotate them.
The native [unifi-systemd](../../../examples/unifi-os/cmd/unifi-systemd/README.md)
adapter implements Subscribe, LoadUnit and property queries. It reports
real runit state and emits PropertiesChanged. StatusText remains empty
until actual application readiness notifications are integrated. Bundled
but unstarted identity and agent units are explicitly inactive; unknown
units and unsupported actions return errors.

Core mounts a dedicated shared socket directory into its OCI root. The
adapter checks both SO_PEERCRED and the EXTERNAL handshake against Core's
UID. It can read two supervisor directories and write its socket directory;
it cannot execute programs or write supervisor control pipes. Core's own
application data stays private. No general system bus is exposed.

Core's generated configuration uses a second declared mount at
`/werewolf/config`. Its HTTP and authentication sockets live there; the
generic private data mount does not allow socket creation. The supported
configPath override preserves generated files across reboot without making
the application image writable. Console logging exposes startup failures.

The native [nginx supervisor](../../../examples/unifi-os/cmd/unifi-nginx/README.md)
specializes the inherited nginx form's service and configuration. Its private
Unix endpoint accepts only Core's fixed reload packet after SO_PEERCRED
authentication. It tests
the fixed configuration before signalling its unreaped nginx child; callers
cannot select a command, path or PID. nginx reads shared configuration and
TLS files, and has no access to Core's private data. Vendor authentication,
CSRF, traversal and header filtering rules remain in place. Template overlays
adapt paths, logs and IPv4 listeners. The two HTML entry pages bake in the
same model metadata Core would otherwise inject at runtime; its patcher
recognizes that marker and leaves the verified application image read-only.

Deliver application updates by rebuilding and signing Werewolf images.
Determine how the OS console reports unsupported update and host actions;
a successful-looking no-op is not acceptable.

## Drawbacks

Vendor updates can change initialization, service interfaces and schemas.
The integration needs a version-specific validation gate. UI and cloud
features may depend on services outside the first prototype.

## Alternatives Considered

- Standalone Network: simpler, but omits the requested UniFi OS experience.
- Run vendor systemd inside Podman: retains runtime mount and service
  management authority that Werewolf deliberately removes.
- Reimplement UniFi applications: far beyond this integration's scope.

## Security Considerations

Each service gets only declared programs, writable directories and ports.
Dependency services listen on loopback; no default external database or
broker listener. Java, Node and Erlang JIT allowances must be declared.
Any compatibility helper fails closed on unknown actions and cannot
weaken policy or modify the verified image.

## Reliability Considerations

Startup tests must include real application readiness, not merely live
processes. Reboot, backup restore and database migration checks precede
production use. Software rollback does not itself roll back database
schema changes; migrations need explicit compatibility and recovery tests.
