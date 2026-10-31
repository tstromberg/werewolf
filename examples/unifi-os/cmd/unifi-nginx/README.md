# unifi-nginx

## Summary

Supervise the console's nginx master and accept Core's one reload request.

## Background

Core generates HTTP routes and TLS files, then invokes
`sudo -E -n nginx -s reload`. The integration replaces that fixed call with
a Unix socket request, without sudo or access to other services.

## Goals

- Perform real configuration validation and nginx reloads.
- Preserve the vendor's authentication and header filtering rules.
- Keep nginx outside Core's leash and private application data.

## Non-Goals

General service management, arbitrary commands, caller-selected processes
or configuration files, and a public control endpoint.

## Detailed design

The integration inherits the nginx form and specializes its `nginx` service.
The native supervisor starts nginx with the fixed `/etc/nginx/nginx.conf`.
Master and workers run as `nginx` under one leash. The supervisor retains
the unreaped child's PID, so reuse cannot redirect a reload to another
process. Master exit ends the service.

Its sequenced-packet socket is `/data/share/unifi/reload/nginx.sock`, mode
0660. SO_PEERCRED must identify the declared Core UID. The only accepted
packet is `reload\n`; oversized packets and other actions are rejected.
Each connection has one second to send a request. The helper screens Core's
HTTP fragments into `/run/svc/nginx/http` (`0700`, owned by `nginx`) and
validates the staged configuration with nginx before delivering SIGHUP to its
own child; on any screening or validation failure, the previous staged tree
stays in place. Success acknowledges validation and signal delivery; VM checks
also verify that workers actually change.

Core owns the shared configuration and TLS directories. nginx has read
access and joins Core's group; it cannot rewrite generated configuration.
The separate shared reload directory holds control and internal sockets.
Core's normal data directory stays mode 0700. nginx reads verified vendor
templates and static assets through explicit paths into Core's baked tree.

Packaging overlays adjust configuration paths, logs and IPv4 listeners in
the pinned image's HTTP templates. Authentication, CSRF, traversal guards
and internal-header filtering are retained. The nginx configuration comes
from that image's `etc/nginx/nginx.conf.disabled`, with its temporary files
and PID placed in the service's own runtime directory.
The two HTML entry pages contain the exact model payload Core's patcher
would inject, derived from the pinned `unifi-assets/manifest.json`. Its
existing marker prevents runtime writes to those verified pages.

## Drawbacks

The configuration overlays must be checked against each vendor upgrade.
nginx needs CAP_NET_BIND_SERVICE for its declared ports below 1024.

## Alternatives Considered

Letting Core signal nginx would cross leash signal boundaries. Pretending
reload succeeded would conceal failures and leave stale routing rules.

## Security Considerations

No caller provides arguments, paths or PIDs. No privilege changes occur.
The socket is neither TCP nor a system bus; root and foreign peers are
rejected. Landlock and port rules still confine nginx after reload.

## Reliability Considerations

Invalid configuration returns failure without signalling the master. Tests
exercise real reloads, denied commands, peer identity and private data.
