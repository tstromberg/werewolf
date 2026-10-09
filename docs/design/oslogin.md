# OS Login

Proposed, 2026-10-09. GCP's accounts and security keys on a werewolf
machine, by one program that writes the four files sshd already reads, with
nothing of Google's in the image. On [manifest.md](manifest.md).

## Summary

A form, `oslogin`, whose one service polls the metadata server for the
users IAM lets in, and writes their accounts and security keys where init
writes them today. sshd changes not at all. Admins log in as root, by key.

## Background

OS Login is Google's answer to ssh keys in metadata: IAM roles say who may
log in and who may administer, the account has a uid that is the same on
every instance, and keys, security keys included, live with the Google
account. Google's guest environment delivers it as an NSS module, two PAM
modules and a sudoers file, loaded into sshd and sudo as root; three
privilege escalations were found in that path in 2020. werewolf has no PAM,
no sudo, and loads nothing into sshd. It also lets nothing reach the
metadata server after boot: user data holds secrets, and on GCP the same
server serves the instance's service-account token.

## Goals

- `with: [oslogin]` on GCP: a user with `roles/compute.osLogin` logs in by
  security key, with Google's uid; one with `osAdminLogin` logs in as root.
- Revocation in IAM ends the account and its sessions within a minute.
- Nothing new on the login path, and one process that may reach the server.
- `make check-oslogin` proves it against a stand-in metadata server.

## Non-Goals

PAM and the OTP second factor; sudo; Google Groups as POSIX groups; key
files; the guest agent; clouds other than GCP; OS Login on a bastion.

## Detailed design

**The form.** `forms/oslogin`: `with: [sshd]`, the service below, and
`net: [metadata _oslogin]`, fence's one rule that lets a user reach
169.254.169.254, held to TCP port 80. howl, creating a machine whose chain
has it, sets `enable-oslogin` and `enable-oslogin-sk` on the instance and
gives it no service account, so the server has no token to serve.

**The service**, `oslogin`, is cloud-metadata's shape: a fetcher forked as
`_oslogin`, chrooted to `/var/empty`, Landlock allowing no file and only TCP
to port 80, seccomp allowing a socket and little else; and a parent as root
with no capabilities and no network, Landlock allowing writes in
`/run/werewolf` and `/data/home` alone, which never touches a byte the
fetcher did not hand it through a pipe. Every minute the fetcher asks, with
`Metadata-Flavor: Google` and refusing any answer without it:

| Ask | For |
| --- | --- |
| `oslogin/users?pagesize=256&pagetoken=` | every login profile: `posixAccounts` (username, uid, gid), `securityKeys` (each a `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com` line) |
| `oslogin/authorize?email=E&policy=login` | may E log in here: `{"success": true}` |
| `oslogin/authorize?email=E&policy=adminLogin` | may E administer here |

The parent checks each profile as `lib/sshd.zig` checks a bastion's: a
username of `[a-z][a-z0-9_-]*`, at most 32 bytes, never `root` or one the
image has; a uid above 65535 that collides with nothing; at most 32 keys,
each an sk type and nothing else, no options; at most 256 users. Then it
writes, atomically, what init writes for a config's users: a passwd and
group line each, `/run/werewolf/keys/NAME` (0600, root) and `/data/home/NAME`
(0700, the user's). Root's keys file is the keys of every admin. A user no
longer served or authorized loses the lines, the file and, by `kill` of
every process with the uid, the session. An answer that fails, or any
profile that does not check, changes nothing and logs one line: the last
good state holds. A manifest's own `users` win a name; the clash is logged.

**sshd** reads `/run/werewolf/keys/%u` and `/etc/passwd` as it does now, with
`PubkeyAcceptedAlgorithms` the sk types and `PubkeyAuthOptions
touch-required`: a login takes the key, touched, and a root session is an
admin's, attributed by fingerprint in sshd's log. No `AuthorizedKeysCommand`,
so nothing on the login path opens a socket.

**Phases.** 1: the fetcher and parser, with a stand-in server, in `test/`.
2: the form, `check-oslogin`. 3: howl's instance flags and the no-account
default. 4: Google Groups, if asked for.

## Drawbacks

One more process that may reach the metadata server, for the machine's
life. A revoked user keeps a session for up to a minute. Two to three
requests a user a minute: a machine with 200 users makes 600.

## Alternatives Considered

**Google's guest-oslogin**: NSS and PAM in sshd's address space, sudoers,
and its own escalation history; its install is a shell script.
**`AuthorizedKeysCommand`**, the keys fetched at each login: a second
program, a socket opened by sshd's child on every attempt, and
accounts still needing a poller. **An NSS module**: Google's uids in every
process by dynamic loading. **Reading `ssh-keys` instead**: metadata any
project editor writes, no roles, no revocation, no security-key list.

## Security Considerations

The machine trusts the metadata server as it trusts its own config, which
comes from the same server: a project owner owns the machine either way.
What is new is bounded: one fetcher that can open one kind of socket to one
address, parse 128 KiB of JSON, and write to a pipe; one parent that can
write four kinds of file. No service account means no token to steal. Only
hardware keys are ever written, so a key copied off a laptop signs nothing.

## Reliability Considerations

A server that stops answering freezes accounts as they were; the log says
so each minute. A profile that fails its check is skipped, not fatal. The
poll is one request plus two a user; a page token walks past 256.
