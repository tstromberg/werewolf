# gvm-link

## Summary

gvm-link copies bytes between gsad and gvmd. The two images do not share a directory,
and gsad talks to the manager only over a Unix socket.

## Background

gvmd and gsad are separate images. Each one's `/run` is its own directory on the
host. gsad has no TCP address for the manager, only `GSAD_MANAGER_UNIX_SOCKET`. A
mode 0666 socket would let every local user speak GMP to gvmd.

## Goals

- gsad can open the manager socket. No other user can.
- gvm-link can open gvmd's socket, and holds no other privilege while it does.
- The check `greenbone-bind` sees mode 0660, and `greenbone-link` sees `_oci-gvmd` in
  gvm-link's groups.

## Non-Goals

- Scanning, or the Greenbone feed.
- A shared writable volume between the two images. werewolf does not have one.

## Detailed design

Leash runs gvm-link as `_glink` with supplementary groups `_oci-gvmd` and `_oci-gsad`
and no capabilities. Because gsad declares `share: group`, leash creates
`/run/svc/gsad/run` with mode `02770` and group `_oci-gsad`. `/etc/werewolf/gvm-link`
names the two host paths. gvm-link binds the listen socket inside
`/run/svc/gsad/run`, where it inherits group `_oci-gsad`, sets mode 0660, and then
accepts, connects to gvmd's socket, and copies. A GMP command still needs the
administrator password.

## Drawbacks

The forwarder is a program we maintain. It is the cost of two images that must share
one socket.

## Alternatives Considered

- Mode 0666. Any local user could then open gvmd.
- One image for both programs. The published images do not ship both binaries.
