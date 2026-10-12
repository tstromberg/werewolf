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
- Capture is not a capability of the analyzer.

## Non-Goals

- Fleet beside Velociraptor, and any C2 or malware sandbox.
- Elastic Security, Security Onion, OpenCTI, TheHive, Cortex.
- Wazuh, until the service user can execute its programs.

## Detailed design

pcap-feed opens one interface, writes a pcap header to a fifo,
drops to `_pcap` (uid 70) and keeps `read`, `write`, `poll`, `ppoll`,
`clock_gettime` and `exit_group`. A reader that opens after the
previous one closed gets a new header. Suricata and Zeek read the fifo. `packet` and
`netadmin` stay in the bounding set so pcap-feed can open the socket; the
analyzers never have them.

Iris, MISP and Greenbone exec `/usr/bin/bash` or `/bin/bash` with one
script as the argument. sh-shim is the host's mini-shell and runs one
program; these scripts need the loops and variables it refuses.
Landlock still names what that bash may run. The shell is inside the
image, so the host's programs-no-shell check still passes.

| Form | State | Defaults; its check's attack |
| --- | --- | --- |
| `velociraptor` | built | keys generated on the machine; `admin` from the config at each start; GUI on loopback behind Caddy; clients on :8000 with mutual TLS; the server may run only its own binary; `admin`/`admin` and a stranger |
| `suricata` | built | pcap-feed's fifo; Emerging Threats Open cached on `/data` by rules-fetch; the engine has no network and does not own the cache; no unix socket |
| `zeek` | built | the same fifo, Zeek's `local` scripts, JSON logs on `/data`; the process not root |
| `dependency-track` | built | bundled jar, PostgreSQL on loopback, Caddy; `admin`/`admin` replaced before Caddy opens |
| `bloodhound` | built | CE behind Caddy; Neo4j Bolt on loopback, HTTP off; Cypher mutations off; the community-edition password refused |
| `wazuh` | not built | the manager's programs are mode 0750, root only; the tree is read-only, and the leash has dropped root |
| `opencanary` | built | Python on twistd, not the image's shell; FTP, SSH, HTTP, Telnet, RDP and VNC only; SMB and the host's logs off; a banner on :21, nothing on :445 |
| `misp` | built | PHP on loopback behind Caddy; misp-serve starts a fixed list, with no Python and no supervisor; published passwords are not set; modules are not started |
| `greenbone` | built | gvmd's socket is mode 0660, group `_oci-gvmd`, carried by gvm-link; both behind Caddy; `admin`/`admin` refused; the scanner alone holds the packet capabilities; the feed owns the cache and gvmd may only read it |
| `iris` | built | gunicorn on loopback behind Caddy, via the image's bash; the administrator from the config; no worker |

## Drawbacks

pcap-feed is a program we maintain. Two passwords for BloodHound, because
two services cannot share one config key. Neo4j's password is set
once; Dependency-Track's administrator is too. Greenbone's first
feed sync is large; the UI is up while it runs. MISP's PHP listens on loopback.

## Alternatives Considered

- Leashing Suricata with `CAP_NET_RAW`. pcap-feed is how capture stays
  outside the analyzer. A service may name `net_raw` and `net_admin`;
  only Greenbone's scanner does, and only that process keeps them.
- Elastic as a form. It is a licensed cluster. OpenSearch is the
  search node.
- Running Wazuh's `/init`, or its bash, as root. The programs are not
  executable by the service user, and a read-only tree cannot be
  chmodded. A shell does not change that.
- sh-shim for these entrypoints. It runs one program and refuses the
  loops and variables the scripts use.

## Security Considerations

The fifo is mode 0400 after the header is written, so the reader
cannot see a partial header and cannot write the feed. Velociraptor
can run VQL that would exec; the leash allows only the server binary.
BloodHound's metrics port is loopback. Neo4j sends no usage report.
The bash these three forms run is the image's, and it is not on the
host. gvmd's socket is mode 0660 and its group is `_oci-gvmd`;
gvm-link keeps that group. A command still needs the password.
The scanner alone keeps the packet capabilities; gvmd reads the feed and cannot open PostgreSQL.

## Reliability Considerations

A sensor that exits is restarted by runit. pcap-feed writes a new
pcap header when that next reader opens the fifo. Velociraptor's keys are kept on `/data`; a second boot does not
regenerate them. BloodHound waits out Neo4j by exiting until Bolt
answers, and runit starts it again. IRIS and gvmd do the same for
PostgreSQL.
