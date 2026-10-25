# Howl SSH connections

**SSH.** `howl ssh` and `howl ssh NAME` log in as your local username, including
on GCP. `run` and `create` default to `--add-current-user=auto`: when `users`
is absent, an SSH-enabled form gets your local account and the public keys in
`~/.ssh` its SSH policy accepts. `--add-current-user=yes` adds it alongside
configured users; an existing account declaration wins. `no` disables the addition.
An explicit empty `users` map or config file disables `auto`. Lima keeps its
NoCloud account for all modes; developer SSH keeps its root-only login.
The generated account has no implicit `admin` grant. `pack --on TARGET` uses
the same default; `pack` without a target adds the account only with `yes`.
Use `howl ssh root@NAME` for root, including `root@werewolf-run` for the unnamed
run machine. `howl
ssh USER@NAME -- COMMAND...` selects another account. Connections to Lima's NoCloud
account also offer Lima's identity key. A missing account or failed login does not fall
back to root. Developer SSH only accepts root, so use `root@NAME` for a `--dev` VM.
Local FIDO keys enter a dedicated, destination-constrained 20-hour agent;
`--identity KEY` selects keys, `--no-agent` skips forwarding. First use pins
the host key with an authentication-free SSH handshake. GCP opens TCP 22 to
the current public IP when no Howl SSH firewall rule exists. See
[su](../../forms/ssh-su/README.md).
