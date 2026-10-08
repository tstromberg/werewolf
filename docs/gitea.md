# Gitea

The `gitea` form is `prod` with Gitea 1.26 hosting git repositories, with
`git` beside it as the one program it may run.

| | |
| --- | --- |
| Listens | tcp/3000, the web and API, behind `caddy`; tcp/22, git over Gitea's own SSH server, keys only, post-quantum exchange only, no shell |
| Sends | nothing: mirrors, migrations and webhooks leave the machine only when a form of your own adds `connect gitea tcp/443 udp/53 tcp/53` |
| Runs as | `gitea` (uid 219), leashed; it may run git, git's hooks (`gitea-hook`), itself and `ssh-keygen`, and reach its own API on loopback |
| Keeps | repositories, LFS, the SQLite database, indexes, queues, the SSH host key and its generated secrets in `/data/svc/gitea` |
| Config | `gitea/admin_password` (12 characters at least); settings `url` and `domain` (required), `admin` (default `admin`), `admin-email` (required) |

```sh
printf '%s' 'a long administrator password' >config/gitea/admin_password
build/host/werewolf pack gitea -o config.tar --config config \
	--url https://git.example.com/ --domain git.example.com --admin-email me@example.com
```

## Installed before it serves

`gitea-init` (`cmd/gitea-init`) runs before Gitea, as `gitea`, inside its
leash. It makes the SSH host key once, Ed25519, with `ssh-keygen`
(Gitea would make RSA under any name), and logs its fingerprint; makes
each secret `app.ini` names by file once, 0600, with `gitea generate
secret`; brings the schema up with `gitea migrate`; and, if the
administrator the settings name is missing, makes it with the config's
password. There is no web
installer (`INSTALL_LOCK`) and no registration; users are invited by the
administrator.

## Defaults

- **Nothing runs a repository's code:** hooks a repository admin writes
  are off (each is a script run on the server), Actions and the package
  registry are off, mirrors are off. Each is a line in a form of your
  own, with the ports it needs.
- **Gitea's own hooks without a shell.** Gitea writes each repository's
  hooks as bash scripts. git's `core.hooksPath` points instead at
  `/usr/lib/werewolf/gitea-hooks`, whose four hooks are links to
  `gitea-hook` (`cmd/gitea-hook`), which becomes `gitea hook NAME` with
  git's input and environment. Pushes work; no shell is in the image.
- Repositories are private by default; emails are private; passwords are
  argon2 and 12 characters at least; cookies are secure, so TLS is in
  front.
- SSH as the bastion and `sftpgo` have it: Ed25519 host key made once on
  `/data`, `mlkem768x25519-sha256` alone, `chacha20-poly1305` and
  `aes256-gcm`; a session gets Gitea's line saying there is no shell.

## Checked

`make check-gitea` ([test/config-gitea](../test/config-gitea)): from the
host, test/boot makes a repository and adds the run's key through the
API, clones it over SSH, commits, pushes, and sees a remote forward, a password and a non-post-quantum exchange refused, and
a command that is not git's refused without running. On
the machine, [test/checks-gitea](../test/checks-gitea) finds the
administrator and no other way in, the installer and registration gone,
the repository private to strangers and pushed to `main`, the host key
Ed25519, and the secrets `gitea`'s alone.
