# unifi-host-info

## Summary

Answer UniFi Core's fixed metadata queries and request a confined nginx
reload without root or an interpreter.

## Background

Core invokes `sudo -E -n ubnt-tools id`. The vendor's ubnt-tools is a shell
script that reads the model and persistent UUID. This experiment replaces
the sudo executable with a native helper for fixed calls.

## Goals

- Preserve the UniFi OS Server model and a stable instance identity.
- Permit only the separate nginx supervisor's fixed reload operation.
- Refuse other host-management actions and never elevate privileges.

## Non-Goals

Software installation, reboot, general service control, backup commands and network
configuration. These remain explicit compatibility work.

## Detailed design

Leash runs the helper as UniFi Core's user. It accepts the exact metadata
identity argument list, reads the service's persistent UUID, and emits the vendor's
board fields. A locally administered serial address is derived from that
UUID. The model and system ID are fixed to UniFi OS Server.
Its second argument list is the exact awk query Core uses for
`VERSION_CODENAME` in the bundled `/etc/os-release`. It reads that field
directly and never interprets awk source.
The exact `sudo -E -n nginx -s reload` argument list sends `reload\n` to
the [nginx supervisor](../unifi-nginx/README.md). It waits for successful
validation and signal delivery; rejection, disconnection and timeout fail.

## Drawbacks

This is a partial adapter. Other sudo calls fail with exit status 126.

## Alternatives Considered

Allowing sudo would retain privileged host actions. Granting the vendor's
shell script would introduce command interpretation for a fixed response.

## Security Considerations

The helper runs no command and changes no file or privilege. Its only
control request reloads the separately confined nginx service. UUID
validation requires a version-5 UUID and prevents board-field injection.

## Reliability Considerations

Unknown actions and damaged identity files fail explicitly. Tests cover
metadata, rejected management calls and malformed identities.
