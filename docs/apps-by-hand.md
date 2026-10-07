# Apps by hand

An application on werewolf is two things, kept apart:

| | Holds | Changes when |
| --- | --- | --- |
| **The image** | the form's Wolfi packages, werewolf's own programs, and your application's files: one read-only, verified root | you change the code; a new image, a new machine |
| **The config tar** | what differs per machine: settings, keys, secrets | you change a setting; a reboot |

## The fast way

From the repository root, with the [build tools](../examples/README.md#build-host)
installed:

```sh
make werewolf
build/host/werewolf create example-python web --app ./myapp --greeting "Hello"
```

`./myapp` is the application's directory (step 1 below writes one).
`create` lays it where the form keeps its application, builds the
image, packs the config tar from `--greeting` (the one setting the
`example-python` form declares), starts a VM (Lima on a Mac, QEMU here
otherwise), and prints its name and address; the application answers on
:8080. `build/host/werewolf delete web` removes it. See [forms.md](forms.md#without-a-form---app).

## Step by step

The same, with `make`, `tar` and QEMU alone, to cut and paste into `sh`,
`bash` or `zsh` at the repository root. It makes a one-file application
that answers with its greeting, builds it into an image, packs a config tar
that gives the greeting, and boots the two.

**0. Where to work.** `build/` is the build's, and kept out of git.

```sh
ARCH=$(uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
W=build/by-hand
rm -rf "$W" && mkdir -p "$W"
```

**1. The application.** Anything its runtime runs; here, Python's standard
library and a setting it reads from its environment.

```sh
mkdir -p "$W/myapp"
cat >"$W/myapp/main.py" <<'EOF'
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GREETING = os.environ.get("GREETING", "Hello from my app")


class App(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (GREETING + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", 8080), App).serve_forever()
EOF
```

**2. The image.** Stage the application as a tree from the root, at the
path the form keeps it, and build a boot disk with it laid over the
`example-python` form: Python, a service that starts
`/usr/lib/app/main.py` as the `app` user on :8080, and the `greeting`
setting.

```sh
mkdir -p "$W/stage/usr/lib/app"
cp -R "$W/myapp/." "$W/stage/usr/lib/app/"
make FORM=example-python DEV= APP="$PWD/$W/stage" disk
cp "build/$ARCH/example-python-app/disk.img" "$W/disk.img"
```

The copy is the machine's disk: it keeps `/data` and its updates, so the
build's own stays clean for the next.

**3. The config tar.** A hostname, and the greeting, as the setting's JSON.
Keys and secrets would be files here too, made with `umask 077`.

```sh
mkdir -p "$W/config/app"
printf '%s\n' myapp >"$W/config/hostname"
printf '%s\n' '{"greeting": "Hello from my app, by hand"}' >"$W/config/app/settings.json"
COPYFILE_DISABLE=1 tar --format=ustar --uid 0 --gid 0 -cf "$W/config.tar" \
  -C "$W/config" hostname app/settings.json
```

**4. Boot it,** the disk first and the tar as a second disk, with the
application's port forwarded to this host's 8080. On arm64 (Apple silicon,
or Linux with KVM):

```sh
for f in /opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/share/qemu/edk2-aarch64-code.fd \
  /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd; do
  [ -f "$f" ] && FW=$f && break
done
ACCEL=kvm; [ "$(uname)" = Darwin ] && ACCEL=hvf
qemu-system-aarch64 -M virt -accel "$ACCEL" -cpu host -m 2048 -nographic \
  -bios "$FW" -device virtio-rng-pci \
  -drive file="$W/disk.img",format=raw,if=virtio \
  -drive file="$W/config.tar",format=raw,if=virtio,readonly=on \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8080-:8080 -device virtio-net-pci,netdev=n0
```

On x86_64, whose UEFI firmware is a read-only code image and a writable
copy of its variables:

```sh
for f in /opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/share/qemu/edk2-x86_64-code.fd \
  /usr/share/ovmf/OVMF.fd; do
  [ -f "$f" ] && CODE=$f && break
done
for f in /opt/homebrew/share/qemu/edk2-i386-vars.fd /usr/share/qemu/edk2-i386-vars.fd \
  /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd; do
  [ -f "$f" ] && cp "$f" "$W/vars.fd" && break
done
ACCEL=kvm; [ "$(uname)" = Darwin ] && ACCEL=hvf
qemu-system-x86_64 -M q35 -accel "$ACCEL" -cpu host -m 2048 -nographic \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$CODE" \
  -drive if=pflash,format=raw,unit=1,file="$W/vars.fd" -device virtio-rng-pci \
  -drive file="$W/disk.img",format=raw,if=virtio \
  -drive file="$W/config.tar",format=raw,if=virtio,readonly=on \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8080-:8080 -device virtio-net-pci,netdev=n0
```

The console is this terminal: the boot, then `posture`'s line. From another:

```sh
curl http://127.0.0.1:8080/
```

`Hello from my app, by hand`. `Ctrl-a x` quits QEMU. To change the
greeting, rewrite `settings.json`, make the tar again (step 3) and boot
again (step 4): no rebuild. To change the code, stage and build again
(step 2), into a new copy of the disk.

## How it works

### The image

The image is the form's packages (apko, from `forms/NAME.yaml` and the
forms it includes) with *overlays* laid on top: each form's directory
(`forms/NAME/`), werewolf's programs, and `APP`, last. Every overlay is a
tree that mirrors the root: `$W/stage/usr/lib/app/main.py` above is
`/usr/lib/app/main.py` on the machine. A runtime form says where it keeps
its application in `etc/werewolf/app`: `/usr/lib/app` for `python`, `node`
and `jre`; nginx's html root, `/usr/share/nginx/html`, for `nginx` and `php`.

`APP` is what `--app` does. For anything deployed more than once, a form
of your own is better, since it is reviewed in version control: include a
runtime form and put the files in `forms/NAME/usr/lib/app/`, as the
[tutorials](../examples/README.md) do. An image with `APP` builds in
`build/ARCH/FORM-app`, apart from the form's own. `APP` can hold any path,
a service file too, but then it is a form in all but name. `--app` stages
only the application's directory and refuses links, devices and setuid
files on the way; by hand, ship none: `posture` fails a machine with a
setuid file.

The build copies each overlay in order, a later one's file replacing an
earlier one's, makes every file root's, `u=rwX,go=rX`, dated 1970, and
writes a sorted ustar, so the same files make the same bytes. The root,
packages and overlays together, is an erofs image that stage0 mounts
read-only through dm-verity ([design/verified-boot.md](design/verified-boot.md)):
a byte of the application changed on the disk stops the machine booting
it. `make FORM=example-python DEV= APP=... DIST=out _dist-form` writes the
release files and their manifest, each file's sha256, as `werewolf build`
does ([releases.md](releases.md)).

### How it runs

leash starts the application from the form's service file,
`etc/sv/app/service`, as its own user, with only what the file names
([programs.md](programs.md); `cmd/leash/leash.zig` lists every directive).
`example-python`'s:

```
exec    /usr/bin/python3 /usr/lib/app/main.py
user    app
pledge  stdio rpath proc inet listen
memory  512
listen  tcp/8080
env     PYTHONDONTWRITEBYTECODE=1
env     PYTHONUNBUFFERED=1
config  settings /run/config/app/settings.json
setting greeting string
render  env app.env
```

The application may write only `/run/svc/app` and `/data/svc/app`, its
working directory, which outlives reboots and updates. It may bind only
the ports it lists, and reach only what the form's `.net` file allows
(`forms/python.net`: `listen tcp/8080`); a database elsewhere is a line
there, `connect app tcp/5432`. A program that starts differently needs a
form with its own service file ([forms.md](forms.md#a-python-web-server)).

### What differs per machine

init finds the config tar at boot, raw, on any block device, or in a
cloud's user data, and extracts it into `/run/config`, which only root can
read ([cloud.md](cloud.md)). The service file decides what the application
sees of it:

- **A file**: `config NAME PATH`, PATH under `/run/config`. leash copies it
  to `/run/svc/SERVICE/NAME`, mode 0600, the service's, at every start. A
  missing file keeps the service down.
- **A secret as a variable**: `secret NAME PATH` reads one line into the
  environment. A file is better: many frameworks take `NAME_FILE`.
- **A setting**: a value that is not secret, typed and checked
  ([forms.md](forms.md#settings), [design/settings.md](design/settings.md)).
  At each start leash copies `settings.json` (`{}` if the tar has none),
  and `service-config`, as the service's user, checks every value against
  its declared type and writes `/run/svc/app/app.env`, whose variables,
  here `GREETING`, leash puts in the application's environment, and
  nothing it did not declare.

What init and the cloud fetcher accept: regular files and directories,
relative names of letters, digits and `. _ - /` up to 100 bytes; from a
disk, files up to 1 MiB; from cloud user data, at most 32 entries of
32 KiB each, 48 KiB in all, and AWS's user data is 16 KiB of base64. A
setting of the wrong type, or one not declared, keeps the service down,
with a line on the console saying which. `werewolf pack` refuses the same
things on your machine first, with the same code.

### Elsewhere

The two files are all any hypervisor needs:

- **Proxmox, VMware, Hyper-V**: import the disk (`qemu-img convert -O vmdk`
  or `-O vpc`), and attach `config.tar` as a second, raw disk.
- **Lima**: `limactl disk import NAME-config config.tar`, listed under
  `additionalDisks` with `format: false`; to reach the VM from the Mac,
  build the disk with `DISK_ARGS="werewolf.mac=MAC console=hvc0"` and give
  it a vzNAT network with that MAC ([service-vms.md](service-vms.md)).
- **A cloud**: an image of the disk, and `base64 config.tar` as the
  instance's user data ([service-vms.md](service-vms.md#gcp-vm) does GCP by
  hand; on AWS, VM Import makes the image from a VHD,
  [service-vms.md](service-vms.md#aws-vm)).

### Updates

The updater rebuilds the machine's next slot from fresh Wolfi and Alpine
packages, then copies into it, from the running, verified root, every file
the build listed in `/usr/share/werewolf/overlay`: werewolf's programs, the
forms' files, and your application's, `APP` being an overlay too
([updater.md](updater.md)). An update brings new packages under the same
application, and the new slot keeps itself only if the machine stays
healthy, the application included. The code changes only when you build
and deploy a new image; `/data/svc/app` and the config tar stay as they
were.

### What `werewolf` adds

Checks before anything boots (`pack` runs the machine's own setting checks
on your machine, and refuses a missing key by name), the application's
digest, and each provider's steps (Lima's template and MAC, GCP's image and
user data, AWS's import, AMI and security group). The mechanism is the one above.
