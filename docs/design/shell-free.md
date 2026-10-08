# Shell-free

Proposed, 2026-10-06.

A production werewolf machine should carry no shell and no interpreter.
Every program it runs is a binary from the image, started by a binary.
Services are declared in a file of fixed keys, not written as scripts, and
a machine runs what its form declares from the moment it boots.

## Why

- **IPE stops new binaries, not scripts.** [verified-boot.md](verified-boot.md)
  lists this as a non-goal: busybox `sh` is in every image and runs any
  script. Without an interpreter, code that takes over nginx has only what
  is in nginx's process. It cannot `sh -c`, pipe a download into a shell,
  or string the image's tools together. Living off the land needs land.
- **One checkable claim.** Per-service Landlock ([lockdown.md](lockdown.md))
  already keeps each service from running anything it did not declare.
  Shell-free extends that to root, PID 1 and the image as a whole, and turns
  it into a claim an auditor checks in one line: the image contains no
  interpreter.
- **Services an auditor can read.** A service file says, in ten lines, who
  a service runs as, which ports it opens, which paths it reads and writes,
  and which programs it may start. Its whole reach is on the page, with no
  code to follow.
- **No shell parsing at boot.** init's word splitting, globbing and the
  unchecked values from NoCloud and the config tar go with the shell.
- **It is done already, elsewhere.** Chainguard's images are built from the
  same Wolfi packages, carry no shell by default, and offer a `-dev`
  variant with one for debugging. We take the same shape.

## Not goals

- **Every form.** `sshd`, `lima` and development builds keep a shell; an
  ssh login with nothing to run is no login. Shell-free is for production
  forms.
- **bite.** It runs on the victim's distro, which has a shell.
- **Interpreters inside a program**, such as nginx's njs or Lua modules.
  They are part of that program, and judged with it.
- **External programs.** init still runs `blkid`, `mke2fs` and `cryptsetup`;
  postdoc still runs `7zz`. Binaries are fine; interpreters are not.

## Setting up nginx

Someone who wants a machine that serves a site with nginx writes a form,
as for any werewolf machine, and no executable at all:

```
forms/prod-nginx/apko.yaml                         packages and the service's user
forms/prod-nginx/form.yaml                         base: prod, and its network policy
forms/prod-nginx/rootfs/etc/sv/nginx/service       how nginx runs
forms/prod-nginx/rootfs/etc/nginx/nginx.conf       nginx's own configuration
forms/prod-nginx/rootfs/usr/share/nginx/html/      the site
```

### The form

```yaml
# prod-nginx: nginx serving the site in this form's folder, on 80 and 443.
include: autoupdate.yaml
contents:
  packages:
    - nginx
accounts:
  groups:
    - groupname: nginx
      gid: 221
  users:
    - username: nginx
      uid: 221
      gid: 221
```

It includes `prod`, as production forms do. The user is in the
image's `/etc/passwd`, which is read-only: nothing on the machine creates
accounts.

### The service

```
# nginx, as its own user, on 80 and 443.
exec     /usr/sbin/nginx -c /etc/nginx/nginx.conf
before   /usr/sbin/nginx -t -q -c /etc/nginx/nginx.conf
user     nginx
listen   tcp/80 tcp/443
read     /etc/nginx /usr/share/nginx/html
requires /run/config/nginx/cert.pem /run/config/nginx/key.pem
nofile   65536
```

The build links `/etc/sv/nginx/run` to the launcher, `leash`. Every service
in the image starts at boot, because runsvdir starts every directory in
`/etc/sv`. There is no enabling or disabling on the machine: a service is
on because the form has it, and a machine without it is another form.

At start, leash checks that the certificate and key arrived in the config
and runs `nginx -t`. It then starts nginx as `nginx`, able to bind 80 and
443 and nothing else, to read its configuration, its site and its own
config directory, and to write its two directories. It can start no other
program. A missing certificate, or a configuration nginx rejects, parks the
service with one line on the console, as `sv down .` does today.

### nginx's configuration

What leash provides shapes four lines of it:

```nginx
daemon off;                        # runsv supervises; nginx stays in the foreground
error_log stderr;                  # the console, like every service
pid /run/svc/nginx/nginx.pid;      # the service's runtime directory

events {}

http {
    access_log /dev/stdout;
    client_body_temp_path /data/svc/nginx/body;    # the service's state directory
    proxy_temp_path /data/svc/nginx/proxy;

    include /run/config/nginx/*.conf;              # this machine's server_name, upstreams

    server {
        listen 443 ssl;
        ssl_certificate     /run/config/nginx/cert.pem;
        ssl_certificate_key /run/config/nginx/key.pem;
        root /usr/share/nginx/html;
    }
}
```

nginx warns that its `user` directive needs root and runs on as `nginx`.

### This machine's values

What differs between machines arrives in the config tar, never by editing
the image:

```
config/
  hostname
  nginx/
    cert.pem
    key.pem
    site.conf          server_name www.example.com;
```

`/run/config/nginx` belongs to the `nginx` service: leash gives it to the
service's user before starting it. The image's configuration includes the
per-machine part by name. There is no templating at boot, because there is
nothing to run a template; a program that cannot include a file takes its
per-machine values through `secret` (below).

### Building and running

```sh
make FORM=prod-nginx slot          # a slot, for bite or an update
make run FORM=prod-nginx           # under QEMU: the console shows the log
make run FORM=prod-nginx DEV=1     # the same, with a shell on the console
```

A change to `nginx.conf` or the site is a new build, and reaches machines
as an update. The root is read-only, and has nothing to edit it with.

## The service file

One directive per line: a key, then words separated by spaces. Double
quotes group words; there are no escapes, variables or expansions. `#`
starts a comment. Unknown keys, a repeated key that may appear once, or a
relative path keep the service down, with the line number on the console.
The format is small enough that leash's parser is a page, and fuzzed.

| Key | Meaning |
| --- | --- |
| `exec PROGRAM ARG...` | what runs; required; an absolute path |
| `before PROGRAM ARG...` | run first, in order, in the same sandbox; each must exit 0 |
| `user NAME` | required; never `root`: a service that needs root is not one leash starts |
| `listen tcp/PORT...` | the ports it may bind; one below 1024 brings `CAP_NET_BIND_SERVICE`, and nothing else, as an ambient capability |
| `connect tcp/PORT...` | the ports it may reach; without it, none |
| `read PATH...` | read-only beyond the floor (below) |
| `write PATH...` | read and write beyond its own directories |
| `run PROGRAM...` | other programs it may start, beyond `exec` and `before` |
| `requires PATH...` | stay down unless each exists |
| `env NAME=VALUE` | its environment, which is otherwise empty but `PATH` |
| `secret NAME PATH` | an environment variable read from a file, as cloudflared's token is today; stays down without it; never logged |
| `config NAME PATH` | copy one file beneath `/run/config` to `/run/svc/SERVICE/NAME`, service-owned, mode `0600`; refreshed before `before` commands; contents never logged |
| `nofile N`, `memory SIZE`, `nice N`, `oom N` | limits, priority and OOM score, set as root before it gives root up |
| `cgroup delegate` | a cgroup v2 subtree it may manage itself |

Every service gets, without asking:

- `/run/svc/NAME` and `/data/svc/NAME`, made, owned by its user and
  writable: runtime files that end with the boot, and the service's data,
  which outlives it.
- **The floor**: read the image's `/usr`; read `/etc/passwd`, `/etc/group`,
  `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`,
  `/etc/ld.so.cache`, `/etc/localtime` and `/etc/ssl`; read `/proc` and
  `/sys/devices/system/cpu`; write `/dev/null` and the console;
  read `/dev/zero` and `/dev/urandom`. Libraries need only read: Landlock's
  execute right covers `execve`, not mapping a library; the program's ELF
  loader, which the kernel opens for execution, gets it too.

Config access is explicit: `config` accepts up to 32 named files, each at
most 64 KiB, without granting access to the source directory. See
[the configuration reference](../forms.md#private-configuration-files).

Built (`cmd/leash/leash.zig`): every key above but `nice`, `oom` and
`cgroup`. A path in `read`, `write` or `run` that another
service has yet to make is a retry, not a park: leash exits, and runsv
starts it again a second later. Leash installs the service's `pledge`
seccomp filter on top of the machine seal.

### What leash does

`runsv` starts `./run` in the service's directory, which is leash. leash reads
`./service`, and then:

1. **As root**: checks `requires`, reads `secret` and `config`; makes the service's
   directories and hands them to its user; sets limits and its cgroup.
2. **Gives up root**: supplementary groups, gid and uid, keeping only
   `CAP_NET_BIND_SERVICE` if a port needs it.
3. **Seals itself**: `no_new_privs`; a Landlock ruleset of the floor, the
   paths, the ports and the programs; and Landlock scoping.
4. **Copies the named config files**, then runs each `before` and waits for it.
5. **Installs the service's seccomp filter and execs `exec`**, with only the
   environment the file names. The machine seal also covers `before` commands.

It logs one line saying what it applied. When a requirement is missing or a
`before` fails, it logs why, writes `d` to `supervise/control` and exits:
the service parks, as `exec sv down .` parks it today.

This is the same launcher as lockdown.md's *Services*, with its flags
written as a file. Forms with a shell may still use a `run` script instead
of a `service` file; a directory has one or the other.

### Today's services in the format

cloudflared's 14-line script:

```
exec   /usr/bin/cloudflared --no-autoupdate tunnel run
user   cloudflared
secret TUNNEL_TOKEN /run/config/cloudflared/token
connect tcp/443 tcp/7844
```

autoupdate's loop moves into the updater (`update daemon`): wait for
commit, run `outcome`, then `check` every 20 hours. Its service file is an
`exec` line, `user root`, and what it reads and writes.

sshd stays a script: `ssh-keygen -A` and an sshd that hands out shells
belong to forms that have one.

## postdoc

postdoc is close to the ideal shell-free workload.

- **One binary.** cleave, scan and isomer are linked in as Rust libraries,
  not run as programs. Its only `/bin/sh` is in a scan test.
- **It runs a few programs directly**, without a shell, and only if
  present: `7zz` (or `7z`), `innoextract` and `upx`, to unpack what it
  analyses. Each is a binary from the image, named in `run`.
- **It parses hostile input for a living:** archives, installers and packed
  executables, through 7-Zip, unrar, yara-x and tree-sitter. A parser bug
  is the likeliest way in, and what an attacker finds there is what this
  design removes.

```
exec    /usr/bin/postdoc worker --url https://hopper.example
user    postdoc
connect tcp/443
read    /usr/share/postdoc
run     /usr/bin/7zz /usr/bin/innoextract /usr/bin/upx
secret  SCAN_LLM /run/config/postdoc/llm
cgroup  delegate
nice    -20
memory  80%
```

It asks werewolf for two things systemd gives it today:

- **A delegated cgroup.** scan freezes and kills idle workers through a
  cgroup v2 subtree under its own (`Delegate=yes` under systemd). leash makes
  `/sys/fs/cgroup/postdoc`, hands it to `postdoc`, and allows writing it.
- **Limits.** `nice -20` and the memory backstop (`MemoryMax=80%`) are set
  as root before leash gives root up. The unit's `OOMScoreAdjust` is `oom`.

postdoc's CA roots are compiled in (rustls with webpki-roots), so the image
needs no certificate bundle for it. Its unpackers inherit its sandbox; a
tighter one per unpacker would be postdoc's own work.

## PID 1 without a shell

Two Zig programs replace werewolf's shell: one for the root image, one for
stage0.

**init** is PID 1 for the life of the machine, in place of `runit-init`:

1. **Stage 1, as today.** Mounts, the modules (`finit_module(2)`, the
   roadmap's helper, which takes kmod out), sysctls and lockdown, the
   network (ioctls), the config (Zig's tar reader, extracting only the
   names it knows, and only regular files), NoCloud for Lima, and `/data`.
   `blkid`, `mke2fs`, `e2fsck` and `cryptsetup` are run as programs,
   without a shell.
2. **The seal**, lockdown.md's, applied to itself before it starts
   anything.
3. **Stage 2**: starts `runsvdir -P /etc/sv` and reaps orphans.
4. **Stage 3**, on `reboot`, `poweroff`, the power button or a signal:
   SIGHUP to runsvdir, which stops each service; then `/data` and
   `/victim` down and the LUKS volume closed, as `/etc/runit/3` does now;
   then `reboot(2)`.

The power button is read by init itself, so `power-button` goes. `reboot` and
`poweroff` become links to init, which signal PID 1. `slot-keep` reads
runsv's `supervise/status` records rather than `sv status` output, and
rewrites GRUB's environment block itself. runit's `runsvdir`, `runsv` and
`sv` stay; `runit-init` and `/etc/runit` go.

**stage0** does what its script does, with the deadman as a forked child
that holds no files once it sleeps.

`minimal` then carries no busybox. A form that wants a shell adds
`busybox-full`, and its links come with it.

## Debugging

- **The console** carries every service's output, leash's line per start,
  and the posture line (lockdown.md). Landlock (Linux 6.15 and later) logs
  its refusals through audit, which with no audit daemon reaches the
  console.
- **`DEV=1`** builds the same chain with a development layer on top:
  `busybox-full`, `strace`, and a root shell on the console. The posture
  line says `"dev":true`, and `make dist`, which CI publishes from,
  refuses one. As with
  Chainguard's `-dev` images, it is a different image from the one in
  production, so a fix is confirmed on the production image after.
- **`werewolf.debug=1`** on a shell-free image has no shell to start, and
  only makes the log more verbose. It loosens nothing.

## Checks

The build refuses a production form whose image contains:

- a file beginning `#!`, which is a script, or a dependency on something
  that runs one;
- a known interpreter: `sh`, `ash`, `bash`, `dash`, `busybox`, `awk`,
  `python*`, `perl`, `lua*`, `node`, `ruby`, `php`, `tclsh`.

CI boots each production form and checks that its services commit. A
program that calls `system(3)` or `popen(3)` fails there, with `ENOENT`
from `/bin/sh`.

## Phases

1. **Service files.** leash reads `service` files, and the Makefile links
   `run` to it. cloudflared, and autoupdate with `update daemon`, convert.
   This is lockdown.md phase 4.
2. **init and stage0 in Zig.** commit, the power button, `reboot`,
   `poweroff` and `grub-setenv` with them. `runit-init` goes, and `minimal`
   stops carrying busybox; `sshd`, `lima` and `DEV=1` add it.

   Done, as a first step: init (`cmd/init/init.zig`), stage0, commit,
   `power-button`, `reboot` and `poweroff`, `grub-setenv`, runit's three stages
   (`runit-stage`, one program that knows its stage by its name), and the console
   and sshd services (`debug-shell`, `sshd-start`) are programs, and `minimal`
   carries no busybox: `sshd`, `lima`, `prod-ssh` and `DEV=1` add it.
   `runit-init` is still PID 1 after init, running the stage programs,
   which is the alternative below; init owning PID 1 is what remains.
3. **The checks, and `DEV=1`.**
4. **`prod-nginx`**, as the worked example, booted by CI.

## Alternatives considered

- **Keep the shell, and rely on Landlock.** Each service's Landlock
  ruleset already keeps it from running `/bin/sh`, which buys most of this
  for services. It leaves root, PID 1, and anything not run through leash,
  and the claim is no longer one line.
- **systemd.** Its units are the same idea, declared sandboxes included,
  and the inspiration for several keys here. It is also most of the size
  and attack surface werewolf exists to avoid.
- **dinit, or s6 with execline.** dinit's service files are declarative;
  execline is a scripting language without a shell's parsing. Either
  replaces runit, and neither sandboxes; leash would still be ours.
- **Keep `runit-init`, with Zig stage programs.** runit runs `/etc/runit/2`
  with no arguments, so it would need a program that knows it is stage 2
  by its name. It splits the machine's life between runit's PID 1 and ours,
  where one program can own it.
- **Variables or conditionals in service files.** Per-machine values come
  as files in the config, which the program includes; a service file that
  can branch is a script again.

## Open questions

- **Wolfi's packages.** A package that depends on `busybox` or `cmd:sh`
  brings a shell into the image. Chainguard ships nginx without one, so
  that closure is clean; each production form's closure needs checking,
  which the build's check does.
- **`accounts` across includes.** Whether apko merges each form's
  `accounts` along the chain, or the Makefile must.
- **bite** stays shell: it runs on the distro, as does `--undo`, where a
  shell and GRUB's tools are. Its cleanup, which runs in werewolf, is
  `bite-cleanup`, in Zig.
- **Forms outside this repository.** postdoc's form belongs in postdoc's
  repository. The Makefile looks only in `forms/`; it could take a
  directory, and resolve includes against ours.
- **Per-machine arguments.** A program that takes a per-machine value only
  as a flag has no way to receive it. An arguments file in the config is
  the obvious answer; it waits for a program that needs it.
- **Lima** runs `limactl shell`, which needs a shell; the `lima` form keeps
  one.
