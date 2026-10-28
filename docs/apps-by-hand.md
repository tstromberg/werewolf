# Apps by hand

An application on werewolf is two things, kept apart:

| | Holds | Changes when |
| --- | --- | --- |
| **The image** | the form's Wolfi packages, werewolf's own programs, and your application's files: one read-only, verified root | you change the code; a new image, a new machine |
| **The config tar** | what differs per machine: settings, keys, secrets | you change a setting; a reboot |

## The fast way

At the repository root, with the [build tools](../examples/README.md#build-host):

```sh
make howl
build/host/howl create web --with python-example --app ./myapp --greeting "Hello"
```

`create` lays `./myapp` where the form keeps its application, builds the
image, packs the config tar from `--greeting` (the one setting
`python-example` declares), starts a VM (Lima on a Mac, QEMU elsewhere) and
prints its address; the application answers on :8080. `howl delete web`
removes it ([applications.md](applications.md#without-a-form---app)).

## Step by step

The same by hand, with `make disk` (howl's build, at make's paths), `tar`
and QEMU, to paste into a shell at the repository root.

**0. Where to work.** `build/` is the build's, and kept out of git.

```sh
ARCH=$(uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
W=build/by-hand
rm -rf "$W" && mkdir -p "$W"
```

**1. The application.** Anything its runtime runs; here, Python's standard
library, and a setting read from the environment.

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
path the form keeps it, and build a boot disk with it laid over
`python-example`: Python, a service that runs `/usr/lib/app/main.py` as
`app` on :8080, the `greeting` setting, and a sample `main.py` yours replaces.

```sh
mkdir -p "$W/stage/usr/lib/app"
cp -R "$W/myapp/." "$W/stage/usr/lib/app/"
make FORM=python-example APP="$PWD/$W/stage" disk
cp "build/$ARCH/python-example-app/disk.img" "$W/disk.img"
```

The copy is the machine's disk, which keeps `/data` and its updates; the
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
  /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd; do [ -f "$f" ] && FW=$f && break; done
ACCEL=kvm; [ "$(uname)" = Darwin ] && ACCEL=hvf
qemu-system-aarch64 -M virt -accel "$ACCEL" -cpu host -m 2048 -nographic \
  -bios "$FW" -boot menu=on,splash-time=0 -device virtio-rng-pci \
  -drive file="$W/disk.img",format=raw,if=virtio \
  -drive file="$W/config.tar",format=raw,if=virtio,readonly=on \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8080-:8080 -device virtio-net-pci,netdev=n0
```

(`-boot menu=on,splash-time=0` skips edk2's 5-second menu.) On x86_64, whose
UEFI firmware is a read-only code image and a writable copy of its variables:

```sh
for f in /opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/share/qemu/edk2-x86_64-code.fd \
  /usr/share/ovmf/OVMF.fd; do [ -f "$f" ] && CODE=$f && break; done
for f in /opt/homebrew/share/qemu/edk2-i386-vars.fd /usr/share/qemu/edk2-i386-vars.fd \
  /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd; do [ -f "$f" ] && cp "$f" "$W/vars.fd" && break; done
ACCEL=kvm; [ "$(uname)" = Darwin ] && ACCEL=hvf
qemu-system-x86_64 -M q35 -accel "$ACCEL" -cpu host -m 2048 -nographic \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$CODE" \
  -drive if=pflash,format=raw,unit=1,file="$W/vars.fd" -device virtio-rng-pci \
  -drive file="$W/disk.img",format=raw,if=virtio \
  -drive file="$W/config.tar",format=raw,if=virtio,readonly=on \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8080-:8080 -device virtio-net-pci,netdev=n0
```

The console is this terminal: the boot, then `posture`'s line. From
another, `curl http://127.0.0.1:8080/` answers `Hello from my app, by
hand`. `Ctrl-a x` quits QEMU. A new greeting is a new tar (step 3) and a
boot (step 4), no rebuild; new code is a new image (step 2) on a new disk.

## How it works

**The image** is the form's packages (apko, from `forms/NAME/form.yaml` and the forms
it includes) under overlays laid in order: each form's `forms/NAME/`, werewolf's
programs, and `APP` last, which is what `--app` does. An overlay mirrors the root:
`$W/stage/usr/lib/app/main.py` is `/usr/lib/app/main.py` on the machine, where
form.yaml's `app` keeps the application. Every file is made root's, `u=rwX,go=rX`,
dated 1970, in a sorted ustar, so the same files make the same bytes, and the root is
an erofs image stage0 mounts through dm-verity
([design/implemented/verified-boot.md](design/implemented/verified-boot.md)): a byte
changed on the disk stops the boot. For anything deployed more than once, put the
files in a form of your own, under `forms/NAME/rootfs/usr/lib/app/`, where version
control reviews them. Ship no links, devices or setuid files, as `--app` refuses
them.

**How it runs.** leash starts the application from the form's service
file, `etc/sv/app/service`, which the build writes from form.yaml's
`services` (`cmd/leash/leash.zig` lists every directive), as its own user
with only what the file names
([applications.md](applications.md#what-the-leash-holds)): it may write
only `/run/svc/app` and `/data/svc/app`, its working directory, which
outlives reboots and updates; bind only the ports it lists; and reach only
what the form's `net` allows. A program that starts differently needs a
form with its own service ([applications.md](applications.md#a-python-web-server)).

**What differs per machine.** init finds the config tar at boot, raw on
any block device or in a cloud's user data, and extracts it into
`/run/config`, root's alone ([cloud.md](cloud.md)). The service file says
what the application sees of it: a file or a secret
([forms.md](forms.md#private-configuration-files)), or a typed setting,
checked at each start ([forms.md](forms.md#settings)). `howl pack` refuses
what init would, with the same code, on your machine first.

**Elsewhere.** The two files are all any hypervisor needs. Proxmox, VMware
and Hyper-V import the disk (`qemu-img convert -O vmdk` or `-O vpc`) and
attach `config.tar` as a second, raw disk. Lima takes
`limactl disk import NAME-config config.tar` under `additionalDisks` with
`format: false`; to reach the VM from the Mac, build the disk with
`DISK_ARGS="werewolf.mac=MAC console=hvc0"` and give it a vzNAT network with
that MAC ([service-vms.md](service-vms.md)). A cloud takes an image of the
disk and `base64 config.tar` as user data ([GCP](service-vms.md#gcp-vm),
[AWS](service-vms.md#aws-vm)).

**Updates.** The updater rebuilds the next slot from fresh packages and
copies in every file in `/usr/share/werewolf/overlay`, `APP` included
([updater.md](updater.md)): the code changes only with a new image;
`/data/svc/app` and the config tar stay.

**What `howl` adds** is those checks before anything boots, the application's
digest, and each provider's steps; the mechanism is the one above.
