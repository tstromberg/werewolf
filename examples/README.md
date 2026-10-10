# Applications on werewolf

Six small HTTP services, each with a form and a tutorial:

| Tutorial | Form | Builds on | Guest port |
| --- | --- | --- | --- |
| [PHP](php/README.md) | `php-example` | `php` (nginx and PHP-FPM) | 80 |
| [Python](python/README.md) | `python-example` | `python-app` | 8080 |
| [Node.js](nodejs/README.md) | `node-example` | `node-app` | 8080 |
| [Go](go/README.md) | `go-example` | `app`, with a static binary | 8080 |
| [Rust](rust/README.md) | `rust-example` | `app`, with a static musl binary | 8080 |
| [ASP.NET Core](aspnet/README.md) | `aspnet-example` | `app`, with ASP.NET Core 10 | 8080 |

Each serves a greeting at `/`, `ok` at `/health`, and 404 for an unknown
path. These are small teaching applications, with no database or external
dependencies. Python's standard-library server and Rust's minimal HTTP
parser are for learning; use an application server/framework when adapting
them for a public service.

`prod` is application-neutral: it does not declare an `app` user or group.
Its descendant [app](../forms/app/form.yaml) declares the unprivileged `app`
user and group. Python, Node.js and JRE inherit it through their runtime
forms; Go, Rust and ASP.NET Core inherit it directly. PHP keeps distinct `php` and
`nginx` service accounts for its two services in the same VM.

## Service forms

The [SSH bastion](../forms/bastion/README.md) builds its users, keys and
destinations into its image, from your form. The
[Tailscale subnet router](tailscale/README.md) takes its routes and
credentials from restricted boot configuration; its image keeps the
accounts, service permissions and network ports fixed.

## Build host

Work from a clone of this repository. The applications run on Linux; the
images can be built on macOS or Linux. Install the repository's build tools
first: apko, Zig **0.17.0**, zstd, libarchive's bsdtar, erofs-utils **1.9 or
newer, with zstd**, QEMU, mtools and e2fsprogs. The pinned CI setup is in
[test/ci-setup](../test/ci-setup). On macOS:

```sh
brew install apko zig zstd libarchive qemu mtools e2fsprogs
make install-deps  # builds erofs-utils with zstd: Homebrew's has none
zig version  # must match the version above
make howl          # build/host/howl
```

The compiled tutorials' applications are built on this host by howl
([app.zig](../cmd/howl/app.zig)), so their compilers must be here; none goes into
the image. Go needs the Go compiler. Rust needs rustup and its stable
toolchain, including the Linux musl target (even on a Mac):

```sh
rustup toolchain install stable --profile minimal \
  --target aarch64-unknown-linux-musl --target x86_64-unknown-linux-musl
```

Go sets `GOOS=linux` and disables cgo; Rust uses its bundled linker and
static musl target. `RUSTC` can override `rustup run stable rustc`; it must
have the requested target installed. ASP.NET Core needs the
[.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0): it
publishes for Linux on the image's architecture; the VM holds the packaged
runtime, not the SDK.

## With werewolf

Each tutorial's form is an ordinary form, so `howl` runs it as it runs any
other, from the repository root:

```sh
build/host/howl run --with python-example                    # here: Lima on a Mac, else QEMU
build/host/howl create web --with python-example             # the same, a machine named web
build/host/howl create web --with python-app --app ./myapp   # your own ./myapp/main.py, and no example
build/host/howl build --with python-example                  # its release disk, in dist/
```

`run` builds the image, boots it, and prints how to reach it: on Lima, the
machine's own address, where the application answers on :8080 (PHP on :80);
under QEMU (`--on qemu`), a loopback port forwarded to it. `howl stop` ends
`run`'s machine, and `howl delete web` removes `web`. The Python tutorial's
form takes a setting, `--greeting TEXT`, as an example of handing an
application per-machine values
([docs/forms.md](../docs/forms.md#without-a-form---app)).

`run` replaces its machine each time, `/data` and all, so it boots what you
last built. `create` of a name that exists keeps the machine's `/data`:
under QEMU it boots the rebuilt image; elsewhere it gives the same image a
new config, so `howl delete` the machine first to boot changed code.

`howl build` writes `dist/FORM-ARCH-disk.qcow2`, an 8 GiB virtual UEFI disk
with a verified root and update slots, and its manifest. The compressed file
is smaller than its virtual size. The package locks in `build/lock/` make
repeated builds use the same package versions; `make FORM=python-example
relock` resolves them again. `--arch x86_64` builds for the other
architecture.

A/B slots are files, not separate disks or separate root partitions. The
disk has a FAT32 EFI partition for both slots' kernels and stage0 images,
and an ext4 partition with `werewolf/a/root.erofs`, `werewolf/b/root.erofs`
and the shared `werewolf/data/`. The updater writes the inactive slot and
changes the boot entry. The whole disk is for a cloud or a hypervisor, but
the update mechanism can use existing filesystems:
[bite](../docs/bite.md) installs slots without repartitioning.

## Prepare GCP once

Install the [Google Cloud CLI](https://docs.cloud.google.com/sdk/docs/install),
authenticate, and choose a project with billing enabled. The account needs
permission to create Compute Engine images, instances and firewall rules,
and storage buckets and objects.

```sh
gcloud auth login
gcloud config set project your-project-id
gcloud config set compute/zone us-central1-a   # howl's default, which has Arm machines
gcloud services enable compute.googleapis.com storage.googleapis.com
```

howl uploads each image once, through a bucket it makes,
`gs://PROJECT-werewolf-images`, in the zone's region, and deletes the
upload after. Machines use the `default` VPC.

## Deploy and inspect

```sh
build/host/howl create web --with python-example --on gcp --allow-from me
curl -f http://ADDRESS:8080/          # the address create printed
curl -f http://ADDRESS:8080/health
build/host/howl console web --on gcp  # the serial port: boot, posture, the app's log
```

`--arch` picks the machine, 4 GB either way: `t2a-standard-1` with gVNIC
on aarch64, `e2-medium` with VirtIO networking on x86_64; `--size` names
another type.
A machine lets nothing in: `--allow-from me` opens the form's TCP ports to
this host's address (`--allow-from CIDR` to a network), or create prints the
gcloud commands that would. The machine has no service account, and Secure
Boot is off, because werewolf's boot loader is not signed for it
([verified-boot.md](../docs/design/verified-boot.md)). Its config travels
as a base64 config tar in `user-data` metadata ([cloud.md](../docs/cloud.md)).
Application code, users and packages come from the image. These examples
have no SSH daemon: the console has boot messages, service failures,
posture and updater events.

If HTTP fails, read the console first, then check the source address and
VPC rules. `programs-no-interpreters` fails by design on PHP, Python,
Node.js and ASP.NET Core, and passes on Go and Rust. A missing package,
compiler or firmware is a build-host problem; an `app` retry or a denied
operation on the console points to the service declaration or the
application. These examples use plain HTTP; put a TLS endpoint in front of
a real application.

## Change, update and remove

Treat the form and source code as the machine's specification. Commit
changes, build a new image, try it here, then create a machine under a new
name, such as `web-v2`, and move traffic once it is checked, keeping the old
one for rollback. Application data is on the boot disk in these examples;
a new machine does not inherit it. Back it up or migrate it before replacing
a service that keeps state. A second `create` of the same name and form only
gives it a new config, and a restart.

For these forms, automatic updates refresh Wolfi packages and the Alpine
kernel, build the inactive slot and reboot. They keep the baked application
and werewolf's own binaries; they do not fetch your Git tree, run package
managers such as pip, npm or Composer, rebuild application code, or adopt
edits to a service or firewall declaration. Each tutorial says what that
means for its dependencies, and [updater.md](../docs/updater.md) describes
the update process.

Machines may reboot after updates. A single machine has downtime;
applications that need availability should run several behind a load
balancer and roll out in turn. Slot rollback is not a backup of application
data.

A cloud machine costs money until it is deleted:

```sh
build/host/howl delete web --on gcp
```

That deletes the VM and its boot disk (**with its application data**) and
its firewall rule. The image stays, so the next create of the same build
skips the upload; delete it with `gcloud compute images delete` when done.

## Possible next steps

The examples need no new VM-side helper. Application-aware health gating,
a shared production deployment command, and a signed release channel for
custom application images would be useful follow-ups to discuss. Each would
need its own policy for rollout, rollback and preserving data.
