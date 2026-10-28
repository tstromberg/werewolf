# ssh-su

Root reauthentication using the existing SSH server and a forwarded
agent. [The form](form.yaml) installs the OpenSSH client and an unprivileged
`su` command. It adds no daemon, setuid binary or password database.

## Configuration

Both prod-ssh and playground include this form. Other SSH forms can add
`with: [ssh-su]`. For production, declare the machine's admins:

```yaml
base: prod-ssh
users:
  alice:
    keys: ["sk-ssh-ed25519@openssh.com PUBLIC_KEY alice-admin"]
    admin: true
```

Use the complete public key from an enrolled authenticator. Admin keys are
authorized for root as well as the named account. `admin: true` also manages
`wheel` membership, required for local reauthentication even with a root key.
Every SSH login requires
presence; ed25519 security keys also require verification (PIN or biometric),
which `sshd: verify-required-keys` names and init writes before each such key.
There is no software-key or password fallback. Generate a credential with
`ssh-keygen -t ed25519-sk -O verify-required` on the client.

Apple Secure Enclave P-256 keys cannot report verification; enroll them with
Touch ID. Inherited authentication requirements, including two distinct keys,
remain in force. See the SSH connection guide for host agent configuration.

The local SSH listener checks the client socket owner against current `wheel`
membership before returning root keys. Calling ssh directly cannot bypass this
check. The network grant permits local reauthentication without external SSH.

## Use

On the client, start a separate agent containing only the admin credential.
Replace `alice` and `server` below with the login name and known host name.
The server's host key must already be verified and recorded in known_hosts.

```sh
ssh-agent sh -eu -c '
  ssh-add -c -t 20h -h alice@server -h "server>root@server" \
    "$HOME/.ssh/id_ed25519_sk"
  exec ssh -S none -o IdentityAgent=SSH_AUTH_SOCK \
    -o StrictHostKeyChecking=yes -A alice@server
'
```

The agent exits when SSH exits; its key expires after 20 hours. The connection
uses that agent explicitly and cannot reuse an existing SSH master. For a
two-key policy, supply both enrolled key paths to `ssh-add`. Each permitted hop
needs compatible OpenSSH. Do not forward an everyday agent holding other keys.

For a local machine, `howl ssh alice@NAME` discovers FIDO keys in `~/.ssh` and
performs this setup. On first use it pins the host key with an authentication-free
handshake. `--identity KEY` selects keys explicitly; repeat it for additional
credentials. `--no-agent` skips forwarding. Lima's login key can still authenticate
locally but is not auto-forwarded.

Inside the session, run `su`. Approve the local agent request and complete the
authenticator's verification and presence checks. `exit` returns to the
original session. The client needs working ssh-askpass for agent confirmation
and PIN prompts. Agent confirmation is client policy, not server-enforced.

Outside an interactive SSH session, `su` exits with `su: unauthenticated
session`. In an SSH session without an agent, it reports
`su: agent forwarding required; reconnect with ssh -A`.

## Local VMs

Playground includes ssh-su with these explicit local-VM exceptions:

```yaml
sshd:
  pubkey-accepted-algorithms: sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519
  verify-required-keys: none
```

Lima must forward a host agent containing a key authorized for root. Lima's
own login key is not automatically a root key. The wrapper never loads a
private key from the guest or chooses a weaker policy after a failure.

## Limits

`su [-] [root]` opens a new login shell; it accepts no other user or command.
The form uses the existing SSH listener on port 22. Client options and user
known_hosts are ignored; its host pin is published locally before sshd starts.
Builds and updates prune the package's `su` entry before installing the wrapper.
BusyBox's compiled-in applet remains unprivileged and cannot elevate a user.
If forwarding is unavailable, open a fresh `ssh root@server` from the client.
Use a fresh direct root connection when the original guest session is suspect.
Only 127.0.0.1 is exempt from SSH source penalties, so failed local attempts do
not penalty-block other administrators. External penalties and connection
limits remain enabled; the shared listener can still suffer resource exhaustion.
All su callers share one source, so at most three can be authenticating at once
(`PerSourceMaxStartups 3`).
