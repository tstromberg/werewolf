# Private host permit transport

## Summary

Protected QEMU and Lima machines must coexist with unrelated host listeners and
with other isolated Werewolf consumers. A published image must not reserve TCP
port 9443 on its host.

## Background

The local publisher currently binds a fixed loopback TCP port. An unrelated
listener or another isolated consumer can occupy that port before deployment.

## Goals

QEMU and Lima consumers run concurrently with occupied host permit ports, without
changing the signed guest endpoint or replacing existing enrolled authority.

## Non-Goals

Migrate existing TCP enrollments or change bhyve's TAP transport.

## Detailed design

Keep the signed guest endpoint, TLS certificate pinning, machine signatures,
TPM state and verified image bytes. QEMU's user network forwards that one guest
TCP endpoint to a private host Unix socket. Lima's protected QEMU backend uses
the same forwarding helper. The forwarding rule opens no host TCP listener.
Move slirp's host alias to the subnet's `.254` address so older libslirp versions
allow forwarding on the signed `.2` endpoint. That endpoint still answers ARP.

The existing publisher serves HTTPS on a Unix socket in an owner-only directory.
Its socket directory has a short name derived from the user's ID and the full
service state path, so distinct XDG state roots coexist. Reject symlinks, foreign
owners and unexpected socket objects; remove a stale socket only under the
service's existing process lock. TLS and the authenticated control token still
protect health checks and shutdown.

Each guest connection starts a bounded-buffer byte bridge to that service socket.
The bridge accepts no guest-supplied destination or command. It transports the
existing TLS stream without interpreting or changing permits. The QEMU wrapper
adds exactly one forwarding rule to its user network and refuses ambiguous
network configurations. Quote command arguments and escape QEMU's comma syntax.

New QEMU and Lima enrollments use a separate private service namespace. Existing
configured TCP publishers retain their enrolled certificates and behavior; an
unrelated listener is never stopped or adopted to make a test pass.

Lima probes accelerators by invoking only the executable in `QEMU_SYSTEM_*`.
Write a private executable wrapper containing the fixed forwarding arguments so
those probes and the final VM launch use the same QEMU executable.

## Drawbacks

Each active guest connection needs a small native relay process. Eight file-lock
leases limit admitted relays; each direction uses fixed 16 KiB buffers.

## Alternatives Considered

A different fixed host port has the same conflict. A random host port requires
changing the guest endpoint or a forwarding listener with another global port.
QEMU's user network already provides forwarding without either host listener.

## Security Considerations

The relay accepts only the fixed service socket in its user's private directory.
TLS certificate pinning, signed permits and authenticated control remain in use.
No shell interprets guest connection data or the relay command.

## Reliability Considerations

Exercise HTTPS issuance, authenticated shutdown, restart, parallel consumers,
stale socket recovery, hostile socket paths and occupied TCP ports. Verify QEMU
argument handling, including spaces, quotes and commas in paths. Boot an actual
guest to prove that the unchanged guest endpoint reaches its Unix socket while
the host's TCP port remains occupied. Run protected lifecycle acceptance with the
private transport and verify that retained authority survives repeated commands.
