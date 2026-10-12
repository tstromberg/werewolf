# A security team's machines

Built, 2026-10-10. Nine of the ten have forms. Wazuh does not: its
programs are mode 0750, root only, on a read-only tree, and the leash
has dropped root before a service runs.

## Summary

The ten appliances a security team stands up for itself: collection,
detection, deception, vulnerability, intel, casework and identity
graphs. Where a form has an administrator, the published password
does not work. Iris, MISP and Greenbone start from the image's bash,
which is an ELF, on one script. The host has no shell. Elastic is not
one of them. OpenSearch already is.

## Background

[corporate.md](corporate.md) is the company's shared services. A
security team adds machines that watch the rest. The ones that get
people breached are the sensor that is also a shell, the SIEM with
`admin/admin`, and the graph database with its HTTP open. A form here
is one leashed process, or a few, on one machine.

## Goals

- Each built form passes `make check-NAME` and `check-shellfree-NAME`.
- Its check ends in the login, or the socket, the defaults refuse.
- The packet capabilities stay on the sensor process, and off every other service.

## Non-Goals

- Fleet beside Velociraptor, and any C2 or malware sandbox.
- Elastic Security, Security Onion, OpenCTI, TheHive, Cortex.
- Wazuh, until the service user can execute its programs.

## Detailed design

Suricata and Zeek each capture `eth0` with `AF_PACKET`. The service keeps `CAP_NET_RAW` and `CAP_NET_ADMIN`; leash drops both from every other service. `packet` allows that socket family and no other. `listen` is the `bind()` the socket needs, and neither form declares a TCP port, so Landlock refuses a TCP bind. Suricata has no `inet` and no `netlink`. Zeek still has both, for the resolver. A packet socket can inject. `packet` and `netadmin` stay in the bounding set so those two services can open the socket.

Iris, MISP and Greenbone exec `/usr/bin/bash` or `/bin/bash` with one
script as the argument. sh-shim is the host's mini-shell and runs one
program; these scripts need the loops and variables it refuses.
Landlock still names what that bash may run. The shell is inside the
image, so the host's programs-no-shell check still passes.

| Form | State | Defaults; its check's attack |
| --- | --- | --- |
| `velociraptor` | built | keys generated on the machine; `admin` from the config at each start; GUI on loopback behind Caddy; clients on :8000 with mutual TLS; the server may run only its own binary; `admin`/`admin` and a stranger |
| `suricata` | built | AF_PACKET on eth0; Emerging Threats Open cached on `/data` by rules-fetch; the engine has no inet and does not own the cache; no unix socket |
| `zeek` | built | AF_PACKET on eth0, Zeek's `local` scripts, JSON logs on `/data`; the process not root |
| `dependency-track` | built | bundled jar, PostgreSQL on loopback, Caddy; `admin`/`admin` replaced before Caddy opens |
| `bloodhound` | built | CE behind Caddy; Neo4j Bolt on loopback, HTTP off; Cypher mutations off; the community-edition password refused |
| `wazuh` | not built | the manager's programs are mode 0750, root only; the tree is read-only, and the leash has dropped root |
| `opencanary` | built | Python on twistd, not the image's shell; FTP, SSH, HTTP, Telnet, RDP and VNC only; SMB and the host's logs off; a banner on :21, nothing on :445 |
| `misp` | built | PHP on loopback behind Caddy; misp-serve starts a fixed list, with no Python and no supervisor; published passwords are not set; modules are not started |
| `greenbone` | built | gvmd's socket is mode 0660, group `_oci-gvmd`, carried by gvm-link; both behind Caddy; `admin`/`admin` refused; the scanner alone holds the packet capabilities; the feed owns the cache and gvmd may only read it |
| `iris` | built | gunicorn on loopback behind Caddy, via the image's bash; the administrator from the config; no worker |

## Drawbacks

Two passwords for BloodHound, because
two services cannot share one config key. Neo4j's password is set
once; Dependency-Track's administrator is too. Greenbone's first
feed sync is large; the UI is up while it runs. MISP's PHP listens on loopback.

## Alternatives Considered

- Copying packets through a fifo so the analyzer never holds `CAP_NET_RAW`. The copy adds a trip through userspace, and a packet socket is what these sensors are for. A service may name `net_raw` and `net_admin`; Suricata, Zeek and Greenbone's scanner do, and only those processes keep them.
- Elastic as a form. It is a licensed cluster. OpenSearch is the
  search node.
- Running Wazuh's `/init`, or its bash, as root. The programs are not
  executable by the service user, and a read-only tree cannot be
  chmodded. A shell does not change that.
- sh-shim for these entrypoints. It runs one program and refuses the
  loops and variables the scripts use.

## Security Considerations

Suricata and Zeek hold the packet capabilities; every other service on those machines drops them. A packet socket can inject, and Zeek's netlink socket can change routes. Velociraptor
can run VQL that would exec; the leash allows only the server binary.
BloodHound's metrics port is loopback. Neo4j sends no usage report.
The bash these three forms run is the image's, and it is not on the
host. gvmd's socket is mode 0660 and its group is `_oci-gvmd`;
gvm-link keeps that group. A command still needs the password.
The scanner alone keeps the packet capabilities; gvmd reads the feed and cannot open PostgreSQL.

## Reliability Considerations

A sensor that exits is restarted by runit. Velociraptor's keys are kept on `/data`; a second boot does not
regenerate them. BloodHound waits out Neo4j by exiting until Bolt
answers, and runit starts it again. IRIS and gvmd do the same for
PostgreSQL.
