# Bastion

Ordinary operator SSH with controlled outbound SSH destinations. Bastion shares the
`sshd` and `ssh-su` service used by SSH variants; `--ssh` adds no second listener.

## Configuration

Define the destinations in a form based on bastion:

```yaml
base: bastion
bastion:
  destinations: [10.20.0.10:22, "[fd00::10]:2222"]
weaknesses:
  network-no-login: SSH provides operator access
  programs-no-shell: mksh provides operator shells and /bin/sh
  network-ssh-config: SSH forwards only to the declared destinations
```

Destinations are literal IP addresses and ports. The allowlist applies to all
people on the machine, both SSH forwards and connections from their processes.
An empty list allows no outbound forwarding. Metadata destinations are refused.

Supply ordinary `users` through the deployment configuration. For example:

```yaml
users:
  alice:
    keys: ["sk-ssh-ed25519@openssh.com PUBLIC_KEY alice"]
```

Alice may log in and jump to a permitted destination:

```sh
ssh -J alice@BASTION you@10.20.0.10
```

Remote root login is refused, including when a valid root key is offered.
Administrators log in as themselves before using local SSH-backed `su`.
Login does not grant administration. Only people declared with `admin: true`
join `wheel` and may use SSH-backed `su`, with fresh root-key authentication.
Security-key and boot-protection defaults remain in force.

## Migration

The former bastion used a shared forwarding-only account and per-key destinations.
Those declarations are refused with a migration diagnostic. Create a new deployment,
move keys to ordinary users, and explicitly choose the shared destination allowlist.
Do not update an existing private bastion channel to this account model without
planning that migration.
