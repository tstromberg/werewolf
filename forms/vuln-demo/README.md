# Vulnerable application demonstration

Three full vulnerable products on hardened interpreters, with a read-only live
console and exec-only SSH. See [form.yaml](form.yaml).

## Security Posture

- No shell, Bash, BusyBox, npm installer, or bundled upstream interpreter.
- Each application, n8n runner, dashboard and SSH daemon has its own user.
- The dashboard permits only its packaged script/style and never caches captured logs.
- Writable files, TCP ports, child executables and memory are confined per service.
- Applications have no outbound network. Only the console reaches their backends.
- Versions are deliberately pinned and automatic updates are disabled.

This is an intentionally vulnerable demonstration. Its public administrator
interfaces and any-password SSH account are part of the exercise.

## Getting Started

See [image availability](../../docs/forms-catalog.md#images-and-downloads).
The combined image needs about 12 GiB for builds and test boots.

```sh
howl run --with vuln-demo --build
```

The demo supplies its own internal n8n runner coordination token. It needs no
configuration files. The broker listens only on loopback, and the service
network policy permits only the isolated runner to connect to it.

Open port 8080 for the live journal. Application ports preserve upstream paths:

| Product | Version | Port | Entry |
| --- | --- | --- | --- |
| Solr | 8.11.0, Log4j 2.14.1 | 8983 | `/solr/` |
| n8n | 1.120.0 | 5678 | `/` |
| Langflow | 1.8.1 | 7860 | `/` and `/api/v1/` |

Set `--editor-url` and `--webhook-url` to n8n's public URL on port 5678 when
using OAuth or generated webhook links. Its backend port 15678 stays private.

n8n's owner setup runs on first use. Its expression vulnerability requires an
account. Langflow deliberately enables auto-login. Both retain the full editor
and API; Langflow includes CPU ONNX inference. Current versions have their own
`solr`, `n8n` and `langflow` forms.

SSH accepts any password for `root` on port 22. It runs argv directly: for example,
`ssh root@HOST /usr/bin/id`. The protocol username does not grant OS root: commands
run as the confined `vuln-sshd` service UID. Shells, PTYs, forwarding and subsystems
are refused.
Offered public keys are rejected and recorded in authorized-keys form with their
algorithm and SHA-256 fingerprint. The record also identifies the requested SSH
user, remote and local addresses, client and server version strings, and session ID;
submitted passwords are never recorded.

Those values use searchable `SSH_USER`, `SSH_REMOTE`, `SSH_LOCAL`, `SSH_CLIENT`,
`SSH_SERVER`, `SSH_SESSION`, `SSH_KEY_ALGORITHM`, `SSH_KEY_FINGERPRINT` and
`SSH_PUBLIC_KEY` fields.
Only `id`, `uname`, and `cat` are exposed, each through a narrower leash that
cannot read the daemon's host key or private data.

The console shows bounded request headers and body prefixes, application output,
kernel violations and exec audit records. Malformed HTTP gets a wire record when
the connection closes. Only a bare `GET / HTTP/1.0` probe is quiet. SSH passwords
are never logged. HTTP capture includes submitted headers and body prefixes.
Service messages use a `service/` label prefix; protected kernel records keep
their own source. Logs contain attacker-controlled text and render as text.

### Known Quirks

- Backend ports 18983, 15678 and 17860 listen only on loopback.
- n8n's task broker and runner health ports stay private.
- Kernel buffering and the bounded journal can lose old records; this is no audit
  archive.
- Hardened interpreters can refuse an exploit before its command starts. Solr's old
  Log4j also runs under Java 27's modern JNDI restrictions.
- The default MiniLM model is packaged for offline embeddings. Other model and
  integration downloads are blocked; provision them through a verified image or
  the application's data directory.

The host-side appliance check exercises the shipping image without adding guest
programs or permissions. After building with `BUILD=build/vuln-demo-check`, run
`forms/vuln-demo/test/appliance --build build/vuln-demo-check`. It checks the
normal HTTP endpoints, two arbitrary SSH passwords, direct commands, refusal
refusal of non-root users, shell/PTY/forwarding/private-key reads, and
request/exec/violation logs.
