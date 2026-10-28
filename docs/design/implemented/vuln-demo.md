# Vulnerable application forms

**Status:** Implemented
[2026-10-17](https://github.com/werewolf-linux/werewolf/commit/168643df)

## Summary

Package current Solr, n8n and Langflow as usable shell-free services on hardened
interpreters, then compose pinned vulnerable counterparts into `vuln-demo`.

## Background

`webshell-example` demonstrates containment with a Flask command runner and
`sh-shim`. Real applications at their normal URLs make a more useful target for
existing scanners.

## Goals

- Current application forms and separate, explicitly named `-vuln-demo` forms.
- Hardened OpenJDK 27, Node.js and Python; no OCI interpreter or shell fallback.
- Separate service UIDs; normal public ports and paths; no app outbound network.
- A read-only Go dashboard for requests, exec audit records and containment
  violations.
- An exec-only SSH daemon accepting any password for `root`, without a shell.

## Non-Goals

Shipping an attacker workstation, shell interpreter, container daemon or LDAP server.
Syslog ingestion will use the machine's collector when available; kernel log capture
and seal-watch's refusal table provide the initial event sources.

## Detailed design

`solr`, `n8n` and `langflow` package application code separately from their runtimes.
Their current releases listen on loopback until deliberately exposed. Each vulnerable
counterpart pins application code and keeps the same runtime, paths and confinement.
Dependency ports retain vulnerable endpoint implementations and have their own locks.
Solr 8 uses its supported NIO directory factory and LRU caches so Unsafe stays
closed. n8n's SQLite/expression native allowance is scoped to its cgroup; Code has
its own user. Langflow shares the source-built Python 3.15 ONNX runtime. A
hash-pinned MiniLM model and tokenizer in `onnx-minilm` provide offline local
embeddings.

`vuln-demo` composes those vulnerable forms. Each app listens on a private loopback
port; the Go console proxies its expected public port without path prefixing. It logs
method, URL, headers, source and up to 8 KiB of body, preserving the forwarded
request. Only a headerless, bodyless `GET / HTTP/1.0` probe is omitted. The dashboard
uses SSE, so live updates do not generate a polling request for every event.

The image's `/etc/werewolf/audit-exec-all` marker requests successful and refused
exec auditing, retaining EXECVE and PROCTITLE. Other forms keep refused-exec
auditing. Init starts `vuln-kmsg` before dropping privileges: it opens `/dev/kmsg`
and a bounded RAM log, forks, drops to a dedicated UID with no capabilities, then
installs a filter allowing only reads and writes on those descriptors. The dashboard
cannot open the kernel device or change audit policy. It deduplicates records by
kernel sequence.

SSH runs as a distinct unprivileged service. Only the protocol username `root`
accepts password authentication; it still executes as the confined `vuln-sshd`
service UID. Exec sessions parse argv quoting and run the requested program directly
under the service's leash; shell, PTY, forwarding and subsystem requests are refused.
Only the three exposed command names map to narrow leash links, so their children
cannot read the daemon's private host key. Alternate coreutils aliases are refused.
Commands, authentication results and exit statuses enter the event journal. Offered
public keys are rejected and journaled in authorized-keys form with their algorithm
and SHA-256 fingerprint. The journal also records the requested SSH user, remote and
local addresses, client and server version strings, and session ID. Password contents
are never journaled.

## Drawbacks

Langflow's native dependencies require Python 3.15 ports. Full products make the
combined image substantially larger than the original command-runner demonstration.

## Alternatives Considered

Upstream images simplify old application dependencies but bypass hardened
interpreters and bring shells. Small framework examples avoid dependency ports but do
not provide the full products requested. Changing production audit globally adds
unnecessary noise.

## Security Considerations

Vulnerable forms are explicitly named and never inherited by production forms.
Runtime allowances needed by an application must be declared, including native
addons; shell launchers and upstream interpreters are not packaged. Application
compromise retains the UID's filesystem, execution, network and cgroup restrictions.

The dashboard renders attacker text as text, bounds history and request capture, and
has no command submission endpoint. SSH passwords are accepted but never recorded.

Native vulnerability regressions use contained canaries: Solr checks the vulnerable
lookup implementation and unmitigated message layout, n8n exposes only the Node
version through the escaped expression context, and Langflow returns a fixed value
from injected component code through the unauthenticated public-build path. Current
forms run the corresponding negative checks. None of the probes writes a file,
launches a shell or requires outbound network access.

## Reliability Considerations

Buffers are bounded; kernel overruns are reported. Kmsg is finite evidence, not a
lossless audit archive. An unavailable capture file is visible in the dashboard.
Services restart through runit; persistent data remains in their own directories.
