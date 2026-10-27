# SSH-backed su

**Status:** Implemented
[2026-10-24](https://github.com/werewolf-linux/werewolf/commit/803df082)

## Summary

The ssh-su form opens a root shell through the existing SSH listener.
An unprivileged wrapper uses the caller's forwarded agent for a fresh login.

## Background

prod-ssh already authorizes each declared admin's keys for root. Operator
sessions currently need a second connection from the client to become root.
Werewolf's confinement also makes a traditional setuid su inappropriate.

## Goals

- Reuse OpenSSH authentication and its privileged session creation.
- Require signed FIDO presence and verification by default.
- Make client installation, agent forwarding and loopback access explicit.

## Non-Goals

New authentication protocols, another daemon, password elevation, arbitrary
target accounts, and proving that a user understood a hardware-key touch.

## Detailed design

`with: [ssh-su]` brings sshd and openssh-client, a native wrapper linked at
/usr/bin/su, and fixed client configuration. Both prod-ssh and playground include it;
playground explicitly admits software keys and omits required verification. Builds
and updates prune package su entries before installing the form overlays. Only ssh-su
then restores /usr/bin/su; BusyBox's compiled-in applet stays unprivileged. The su
form explicitly selects FIDO algorithms. AuthenticationMethods is a publickey
fallback in sshd's default file; a form's stronger requirement wins.

The wrapper accepts only a root login, requires a terminal and an agent socket,
and execs the client with a small environment. It ignores user client settings,
uses no guest private keys, and disables connection sharing and forwarding.

The existing ssh-host-key startup helper accepts an optional known-hosts output
path. It atomically publishes only its public key for the fixed alias
werewolf-local, readable by all users but writable only by the service owner.
The su form runs this helper as root before starting its existing sshd service.
Forwarded sockets live in private directories under a sticky /run/ssh-agent,
where fence already permits socket creation, rather than in persistent homes.
The wrapper refuses unknown or changed keys, with no trust-on-first-use prompt.

The form permits connection to loopback TCP 22 for runtime users. Their names
may come from boot metadata, so the image cannot enumerate their UIDs. The
existing per-service Landlock restrictions still apply. No external connect
permission is added. SSH's root key list remains the authorization boundary.
Only 127.0.0.1/32 is exempt from source penalties: all local callers share it.
External penalties and connection limits remain enabled. This exemption avoids
shared authentication lockouts, but cannot prevent listener resource exhaustion.

## Alternatives Considered

A setuid helper or privileged approval service would duplicate account and
authentication handling. A custom client would improve approval context but
exclude ordinary SSH users. A second sshd would duplicate an existing service.

## Security Considerations

Root authorization is controlled by provisioning, never the caller's key file.
The default form requires touch and verification on every new authentication.
PIN entry freshness depends on the client and authenticator. Client confirmation
and destination constraints help but cannot be required by the SSH server.
The documented client setup uses a separate agent with only short-lived,
confirmed, destination-constrained admin credentials and no connection sharing.

The operator session can request competing signatures and controls the terminal
through which the new shell runs. Direct root SSH from a trusted client remains
the stronger option when that session may be compromised. Enrollment must bind
keys to people; the key algorithm alone does not attest trusted hardware.

## Reliability Considerations

All failures leave the caller unprivileged. Public pin publication precedes
listener startup and uses rename so readers never see partial contents. The
feature adds no persistent state beyond the existing host and authorized keys.
