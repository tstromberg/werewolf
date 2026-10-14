# unifi-host-info

## Summary

Answer UniFi Core's fixed hardware identity request without root or a shell.

## Background

Core invokes `sudo -E -n ubnt-tools id`. The vendor's ubnt-tools is a shell
script that reads the model and persistent UUID. This experiment replaces
the sudo executable with a native helper for that one read-only call.

## Goals

- Preserve the UniFi OS Server model and a stable instance identity.
- Refuse all host-management actions and never elevate privileges.

## Non-Goals

Software installation, reboot, service control, backup commands and network
configuration. These remain explicit compatibility work.

## Detailed design

Leash runs the helper as UniFi Core's user. It accepts the exact metadata
argument list, reads the service's persistent UUID, and emits the vendor's
board fields. A locally administered serial address is derived from that
UUID. The model and system ID are fixed to UniFi OS Server.

## Drawbacks

This is a partial adapter. Other sudo calls fail with exit status 126.

## Alternatives Considered

Allowing sudo would retain privileged host actions. Granting the vendor's
shell script would introduce command interpretation for a fixed response.

## Security Considerations

The helper runs no command and changes no file or privilege. UUID
validation prevents newlines or other data from injecting board fields.

## Reliability Considerations

Unknown actions and damaged identity files fail explicitly. Tests cover
metadata, rejected management calls and malformed identities.
