# unifi-systemd

## Summary

Expose UniFi Core's read-only systemd D-Bus vocabulary using runit's real
service state. It has no service-control or command-execution authority.

## Background

Core crashes without a system bus and uses systemd's unit properties to
watch applications. Werewolf supervises them with runit instead.

## Goals

- Answer Subscribe, Unsubscribe, LoadUnit and two property queries.
- Report actual process state and send PropertiesChanged notifications.
- Reject management operations, unknown units and malformed messages.

## Non-Goals

A general message bus, service control, sd_notify readiness, installation,
reboot, name ownership and inter-client message routing.

## Detailed design

The helper runs as its own unprivileged user. Core mounts the shared
`/data/share/unifi/bus` directory at `/werewolf/bus` and admits the adapter
through its group. Its application data remains private. The adapter's
socket is mode 0660. Core sets DBUS_SYSTEM_BUS_ADDRESS to that socket.
The helper requires Core's UID in both SO_PEERCRED and the EXTERNAL
handshake; a claimed UID alone cannot authenticate another process.

The fixed unit table maps unifi.service to unifi-network's runsv status
and unifi-core.service to Core's. The bundled but unstarted ulp-go and
uos-agent units are explicitly inactive. Other names return NoSuchUnit.
It reads only the two supervisor directories granted in the manifest.
Malformed or unavailable status is failed, never active.

Subscribe enables state-change delivery; AddMatch and RemoveMatch track
bounded subscriptions for the fixed unit paths. It polls status each
second. StatusText is empty because runsv receives no application STATUS
notifications. Process state does not establish application readiness;
the integration checks require real HTTP responses separately.

wire.zig handles bounded D-Bus framing and string arguments. It accepts
both byte orders, validates lengths, terminators, types and duplicate
headers, and refuses file descriptors. There are eight clients, 32 KiB
input and output buffers per client, and five-second deadlines for
authentication, partial frames and stalled output. Idle authenticated
connections stay open. Unknown methods return explicit errors.

## Drawbacks

This is version-specific compatibility code. The inactive identity and
agent services and absent readiness notifications still limit the console.

## Alternatives Considered

Running systemd preserves unnecessary host-management interfaces. An
unrestricted D-Bus daemon adds routing and name ownership this adapter
does not need. Abstract Unix sockets cannot cross leash's Landlock domains.
TCP does not provide Unix peer credentials.

## Security Considerations

The helper has no exec, connect, Internet or privilege capability. Its
writable paths hold its socket and its own service files. It reads a fixed
set of root-owned supervisor files and never writes their control pipes.
It has no network listener.
Peer-supplied sender headers cannot set outgoing message identities.

## Reliability Considerations

Tests cover actual state decoding, authentication, rejected control calls,
unknown units, bounded matches, signal framing and malformed inputs.
VM tests must exercise the bundled D-Bus client and both application APIs.
