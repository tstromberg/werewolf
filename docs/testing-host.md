# Host suites

A form that serves SSH is tested as its users reach it: from outside. A tests.yaml's
top-level `host:` suites run on the build host, by OpenSSH's own `ssh` and `sftp`,
against the port QEMU forwards to the machine's 22
([runner](../test/native-host.zig), [validation](../test/native/host.zig)). The test
image carries no SSH client, and the host's results come back in a file of its own,
never through the console the machine writes. Use them for logins and refusals; what
the machine kept is a guest case.

```yaml
host:
  - name: bastion-ssh
    cases:
      - name: bastion-permitted-destination
        steps:
          - ssh:
              user: bastion
              key: security
              forward: 127.0.0.1:22
            await: 60s
            expect:
              status: 0
              stdout:
                contains: SSH-2.0-OpenSSH
      - name: bastion-no-destination
        steps:
          - ssh: {user: bastion, key: security, forward: 127.0.0.3:22}
            expect:
              status: {not_equals: 0}
              stderr:
                contains_all: [Authenticated to, administratively prohibited]
```

`ssh` takes `user`, `key`, and a `command` (default `true`) or `forward` (stdio to
`HOST:PORT`, `ssh -W`); `remote_forward: true` asks for a remote forward, and `kex`
offers only those key exchanges. `same_host_key: true` holds the machine to the host
key it first offered in the run, so a case in both phases proves `/data` kept it. It
expects `status`, `stdout` and `stderr`, which holds what the client said at
`LogLevel=DEBUG1`. `sftp` takes `user`, `key` and a plain file name `path`, uploads
`put` to it if given, then downloads it; it expects `status`, `content` (what came
back) and `stderr`. `program: {name: ssh-su, args: [prod-ssh]}` runs an attack too
stateful for steps, `build/host/NAME PORT KEYS PROVIDER ARGS...` from
`test/NAME.zig`; it expects `status`, `stdout` and `stderr`. Each run of a step has a
`timeout` (default `60s`, at most `300s`). Matchers are the guest's, without
references.

`key: security` is the run's security key, held by the software provider
(tools/test-sk.zig); `file` is its key file; `none` offers only a password, which a
keys-only sshd must refuse with `Permission denied (publickey)`. The run gives root
both keys in `authorized_keys`, and `test/config DIR` finds the key file as DIR's
sibling `FORM-key.pub`. A generated form bakes in keys of its own: make passes their
prefix as `NATIVE_SSH_KEYS` (test/bastion-form).

Cases run in both phases unless `phases` picks one, once the machine's posture is in
and its guest cases are done, since one restarts sshd. `await` repeats a step until
it holds: give it to the first login. A refusal proves nothing from a machine that
never answered, so expect what the server said once it let the client in
(`Authenticated to`). sshd holds failed logins against their source: fail one, last.
Host suites run in clean runs only, not under `--iterate`.
