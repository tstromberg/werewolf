# webshell-example - A contained vulnerability

A form that ships the worst thing a web application can do: its page takes a
string from an unauthenticated request, runs it through `/bin/sh` as an
application's `sh -c` would, and shows the output. That is remote code
execution by design, the bug behind a large share of real breaches. The form
shows what an attacker gets for it on werewolf: nothing worth having. The
manifest is [form.yaml](form.yaml); the application is
[webshell.py](rootfs/usr/lib/app/webshell.py).

For full vulnerable Solr, n8n and Langflow products with a live containment
journal, use [vuln-demo](../vuln-demo/README.md). Its services use hardened
interpreters and direct command execution without a shell shim.

## Security Posture

The execution is real, and the leash bounds it, not an empty image: the form
ships coreutils and net-tools on purpose.

- `/bin/sh` is [sh-shim](../../cmd/sh-shim/README.md), which runs one
  program and refuses `&&`, pipes and `$`.
- The service's `run` line names the programs it may exec (`id`, `uname`,
  `cat`, `ls` and a few more). Landlock refuses every other file at exec:
  `ifconfig` and `route` are in the image and never run.
- The leash's read floor leaves out `/etc/shadow`; the root is read-only
  through dm-verity, so nothing persists; the form declares no `connect`,
  so fence drops every packet going out.
- `cat` also runs narrowed, by its link `/etc/sv/app/narrow/cat`
  ([narrow](../../docs/design/narrow.md)): it reads the image but neither
  the account list nor the app's own files, which plain `cat` reads.

Weaknesses: `programs-no-interpreters` (python3 runs the application) and
`programs-no-network-tools` (net-tools ships to show the leash refuses it).

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create webshell-example --with webshell-example
```

The page is on the machine's port 8080. Try to escape; the page keeps the
last 100 attempts, each with its source address, exit code and output, and
`attempts.json` lists them:

```text
$ curl --data-urlencode 'cmd=cat /etc/shadow && echo LEAK' MACHINE:8080
# sh-shim: refused: unquoted & is shell syntax                  (no shell ships)
$ curl --data-urlencode "cmd=/usr/bin/python3 -c \"open('/pwned','w')\"" MACHINE:8080
# OSError: Read-only file system                                 (dm-verity root)
$ curl --data-urlencode 'cmd=id' MACHINE:8080             # uid=527139628(app) ...
$ curl --data-urlencode 'cmd=cat /etc/shadow' MACHINE:8080
# cat: /etc/shadow: Permission denied                            (cat runs; the read is denied)
$ curl --data-urlencode 'cmd=dd if=/dev/zero of=/pwned' MACHINE:8080
# dd: failed to open '/pwned': Read-only file system
$ curl --data-urlencode 'cmd=ifconfig' MACHINE:8080
# sh-shim: ifconfig: permission denied                          (exec not allowed)
$ curl --data-urlencode 'cmd=/etc/sv/app/narrow/cat /etc/passwd' MACHINE:8080
# cat: /etc/passwd: Permission denied                            (narrowed)
```

`dd` runs: Landlock allows exec per file, and Wolfi's coreutils is one
multi-call binary, so naming `id` allows every applet. They gain nothing,
because the floor, the dropped capabilities (`chroot` has no
`CAP_SYS_CHROOT`) and the empty network still bind them. `run` allowlists
files; the containment is what surrounds whatever runs.

At boot the application attacks itself with this battery, logs as JSON on
the console that none escaped, that each allowed command ran, and that
narrowed `cat` held. `make check` boots it without a shell and checks all
three ([test/console](test/console)), so the claim is tested, not just made.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create webshell-example --with webshell-example --on gcp --allow-from me
```

The firewall permits this computer on port 8080. Pass
`--allow-from 0.0.0.0/0` to let anyone try the demo. Run
`howl delete webshell-example --on gcp` when you are done; the VM costs
money until then.

### Network Exposure

- `listen: tcp/8080 *`
