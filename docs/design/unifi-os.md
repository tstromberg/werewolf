# UniFi OS on Werewolf

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

- Reusable [MongoDB](../../forms/mongodb/README.md) and RabbitMQ forms,
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
UniFi Core also imports a D-Bus client: service control may need a small
compatibility service with a fixed vocabulary. Never expose arbitrary
commands, package installation or a general systemd control interface.

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
