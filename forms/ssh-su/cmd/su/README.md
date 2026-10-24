# su

## Summary

Open a fresh root SSH login through the forwarded agent. The program has no
privileges; the existing SSH server authenticates the key and starts the shell.

## Background

Operator shells inherit Werewolf's confinement. A setuid program cannot undo
it. A separate SSH login lets the existing privileged listener create a session.

## Goals

- Reauthenticate for every root shell, with server-enforced key policy.
- Use one listener and OpenSSH's authentication protocol.
- Ignore caller-supplied SSH configuration, identity files and commands.

## Non-Goals

Password authentication, arbitrary target accounts, command execution, and
preserving the caller's directory or environment.

## Detailed design

`su`, `su -`, `su root` and `su - root` open the same root login shell.
SSH_CONNECTION and SSH_TTY must look like an interactive SSH session, and both
input and output must be terminals. Otherwise it reports `unauthenticated
session`. These are diagnostic hints, not credentials. A missing or invalid
SSH_AUTH_SOCK instead explains that agent forwarding is required. The program
refuses execution with gained privileges.

It replaces itself with `/usr/bin/ssh`, reading only `/etc/ssh/su_config`.
The destination is root at 127.0.0.1:22. The environment contains only PATH,
TERM and SSH_AUTH_SOCK. Connection sharing, further forwarding, local identity
files, password prompts and SSH escape commands are disabled.

Before sshd starts, ssh-host-key publishes its public key in a root-owned
known-hosts file. Strict host verification uses that file and no user file.
Missing or mismatched pins fail authentication; there is no trust prompt.

## Drawbacks

The client must forward an agent. A compromised operator session can request
signatures or interfere with its terminal. A fresh root login from the laptop
avoids routing the root terminal through that session.

## Security Considerations

The wrapper is not an authorization boundary. Bypassing it still encounters
sshd's root key list and authentication policy. It grants no capability and
does not read, verify or store credentials. A forged agent cannot authenticate
without signing with an authorized key.

The su form requires FIDO presence and verification for all SSH logins. A
composing form may explicitly relax this for local VMs. Client-side agent
confirmation and destination constraints are recommended; the server cannot
enforce a local confirmation dialog or prove the user's understanding.

## Reliability Considerations

Missing agent, missing client, denied network access and authentication errors
fail closed. SSH's exit status becomes su's. No persistent process or session
cache is introduced.
