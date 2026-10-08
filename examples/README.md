# Applications on werewolf

Six small HTTP services, each with a form, a Makefile and a tutorial:

| Tutorial | Form | Builds on | Guest port |
| --- | --- | --- | --- |
| [PHP](php/README.md) | `example-php` | `php` (nginx and PHP-FPM) | 80 |
| [Python](python/README.md) | `example-python` | `python` | 8080 |
| [Node.js](nodejs/README.md) | `example-node` | `node` | 8080 |
| [Go](go/README.md) | `example-go` | `app`, with a static binary | 8080 |
| [Rust](rust/README.md) | `example-rust` | `app`, with a static musl binary | 8080 |
| [ASP.NET Core](aspnet/README.md) | `example-aspnet` | `app`, with ASP.NET Core 10 | 8080 |

Each serves a greeting at `/`, `ok` at `/health`, and 404 for an unknown
path. These are small teaching applications, with no database or external
dependencies. Python's standard-library server and Rust's minimal HTTP
parser are for learning; use an application server/framework when adapting
them for a public service.

`prod` is application-neutral: it does not declare an `app` user or group.
Its descendant [app](../forms/app/apko.yaml) declares the unprivileged `app`
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
```

QEMU also needs UEFI firmware: Homebrew's QEMU includes edk2; Linux packages
are usually `ovmf` for x86_64 and `qemu-efi-aarch64` for Arm. If the build
does not find it, pass `UEFI_FIRMWARE=/path/to/code.fd`; x86_64 also needs
`UEFI_VARS=/path/to/matching/vars.fd`. Use firmware without Secure Boot.

Go needs the Go compiler on the host. Rust needs rustup and its stable
toolchain, including the Linux musl target (even on a Mac):

```sh
rustup toolchain install stable --profile minimal \
  --target aarch64-unknown-linux-musl --target x86_64-unknown-linux-musl
```

`ARCH` defaults to the host: `aarch64` on Apple silicon, `x86_64` on an
Intel/AMD machine. Both can build either architecture. Go sets `GOOS=linux`
and disables cgo; Rust uses its bundled linker and static musl target.
Neither compiler goes into the image. `RUSTC` can override
`rustup run stable rustc`; it must have the requested target installed.

ASP.NET Core needs the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
on the host. It publishes for Linux using the selected architecture; the VM
contains the packaged runtime, not the SDK.

## With werewolf

Each tutorial's form is an ordinary form, so `howl` runs it as it runs
any other, from the repository root (`make howl` builds it):

```sh
build/host/howl create web --with example-python            # Lima on a Mac, else QEMU here
build/host/howl create web --with example-python --on gcp   # Google Compute Engine
build/host/howl create web --with python --app ./myapp      # your own app, on the python form
```

It prints the VM's address; the application answers on :8080 (PHP on :80).
`howl delete web` removes it. The Python tutorial's form takes a
setting, `--greeting TEXT`, as an example of handing an application
per-machine values ([docs/forms.md](../docs/forms.md#without-a-form---app)).
The Makefiles below do the same for QEMU and GCP step by step.

## What the Makefiles do

From the root, replace `python` below with the tutorial directory:

```sh
make -C examples/python image
make -C examples/python deploy-qemu
```

`image` creates `build/ARCH/example-python/disk.qcow2`, an 8 GiB virtual
UEFI disk with a verified root and update slots. The compressed file is
smaller than its virtual size. The root build's package locks in
`build/lock/` make repeated builds use the same package versions.

A/B slots are files, not separate disks or separate root partitions. The
native disk has a FAT32 EFI partition for both slots' kernels and stage0
images, and an ext4 partition with `werewolf/a/root.erofs`,
`werewolf/b/root.erofs` and shared `werewolf/data/`. The updater writes the
inactive slot and changes the boot entry. The complete disk image is useful
for cloud import, but the update mechanism can use existing filesystems:
[bite](../docs/bite.md) installs slots without repartitioning. A general
installer for arbitrary existing partitions is outside these examples.

`deploy-qemu` copies that image to `qemu.qcow2` beside it on the first run,
then boots that writable copy. Open `http://127.0.0.1:8080/`; PHP's guest
port 80 is also forwarded to host port 8080. Check `/health`, then quit with
`Ctrl-a x`. The next launch keeps `/data` and automatic updates. Stop the
VM before starting another with the same disk. `HTTP_PORT=8081` changes
the host port, so different examples can run together.

A rebuilt image does **not** overwrite that running disk. To test changed
code, stop QEMU and choose a new disk:

```sh
make -C examples/python deploy-qemu \
  QEMU_DISK=build/aarch64/example-python/qemu-v2.qcow2
```

Use your actual architecture in that path, which is relative to the
repository root. Each new disk starts with empty application data. Keep the
old disk for rollback or backup. Unlike the root Makefile's direct-boot
`make run`, this disk boot can install and reboot into automatic updates.
Network access is needed to build and, inside the VM, to update.

The six Makefiles share [common.mk](common.mk) and [vm.mk](vm.mk), which
invoke the existing image builder. [build.mk](build.mk) adds the three compiled
applications to architecture-specific overlays and to the updater's list
of files to carry forward. Ordinary `make FORM=example-go disk` works too.

## Prepare GCP once

Install the [Google Cloud CLI](https://docs.cloud.google.com/sdk/docs/install),
authenticate, and choose a project with billing enabled. The account needs
permission to create Compute Engine images, instances and firewall rules,
use the selected network, and upload/read/delete objects in the staging
bucket. Have the project administrator grant those permissions if needed.

```sh
gcloud auth login
export GCP_PROJECT=your-project-id
export GCP_BUCKET=your-globally-unique-werewolf-bucket
export GCP_ZONE=us-central1-a
gcloud services enable compute.googleapis.com storage.googleapis.com \
  --project="$GCP_PROJECT"
gcloud storage buckets create "gs://$GCP_BUCKET" --project="$GCP_PROJECT" \
  --location=us-central1 --uniform-bucket-level-access
```

Reuse an existing bucket by skipping its creation. Set `GCP_BUCKET` to its
name without `gs://`. Set the source range to your workstation's public
IPv4 address with `/32`, or a network you control; the value here is only
a documentation placeholder:

```sh
export GCP_SOURCE_RANGES=203.0.113.4/32  # replace with YOUR public IP/CIDR
```

The recipes use the `default` VPC and its automatic subnet in the chosen
region. For another auto-mode VPC, set `GCP_NETWORK`. For a custom-mode VPC,
adapt `--network-interface` in [vm.mk](vm.mk) to name your subnet. Ensure its
routes and egress policy allow DNS and HTTPS so the updater can work.

## Deploy and inspect

```sh
make -C examples/python deploy-gcp ARCH=x86_64
make -C examples/python serial-gcp ARCH=x86_64
```

Keep `ARCH` and any `GCP_NAME`, `GCP_IMAGE`, `GCP_ZONE` or project overrides
the same for later commands. Defaults are `e2-medium` with VirtIO networking
on x86_64, or `t2a-standard-1` with gVNIC on aarch64; choose a zone supporting
the selected machine. `GCP_MACHINE` overrides its type and must match `ARCH`.

The deployment recipe converts the pristine qcow2 to `disk.raw`, wraps it
in a GNU-format gzip tar, uploads it, creates a UEFI-compatible GCP image,
and creates a VM. These follow Google's
[manual disk import procedure](https://docs.cloud.google.com/compute/docs/import/import-existing-image)
and [image creation interface](https://docs.cloud.google.com/sdk/gcloud/reference/compute/images/create).
The instance has no service account, and Secure Boot is disabled because
werewolf's bootloader is not signed for it; see the
[instance flags](https://docs.cloud.google.com/sdk/gcloud/reference/compute/instances/create)
and [verified boot design](../docs/design/verified-boot.md).

The hostname travels as a base64 config tar in `user-data` metadata, as
[cloud.md](../docs/cloud.md) describes. Application code, users and packages
come from the image. These examples have no SSH daemon. Use `serial-gcp`
for boot messages, service failures, posture and updater events.

The final output gives an HTTP URL. Allow boot to finish, then:

```sh
curl -f http://EXTERNAL_IP:8080/
curl -f http://EXTERNAL_IP:8080/health
```

For PHP, use port **80**. The firewall rule permits only your selected
source range and application port; the form's own network policy must also
permit it. `/health` is available for your checks; slot commitment checks
service uptime and updater readiness, and does not call this endpoint.
These examples use plain HTTP; put a TLS endpoint in front of a real app.

If HTTP fails, inspect the serial output first, then the source CIDR and
VPC rules. `programs-no-interpreters` fails by design on PHP, Python and
Node.js and ASP.NET Core. It should pass on Go and Rust. A missing package/compiler/firmware
is a build-host issue; an `app` retry or denied operation in the console
points to the service declaration or application.

## Change, update and remove

Treat the form and source code as the machine's specification. Commit
changes, build a new image, test it under QEMU, then deploy with a fresh
name, for example `GCP_NAME=werewolf-python-v2`. The recipe refuses an
existing VM. Move traffic after checking the new one, keeping the old VM
available for rollback. Application data is on the boot disk in these
examples; a new VM does not inherit it. Back it up or migrate it before
replacing a service that keeps state.

For these custom forms, automatic updates refresh Wolfi packages and the
Alpine kernel, build the inactive slot and reboot. They preserve the baked
application and werewolf's own binaries; they do not fetch your Git tree,
run package managers such as pip/npm/Composer, rebuild application code, or adopt
edits to a service or firewall declaration. See each language tutorial for
what that means for its dependencies, and [updater.md](../docs/updater.md)
for the update process. To refresh the build host's package locks:

```sh
make FORM=example-python relock
make -C examples/python image
```

VMs may reboot after updates. A single VM has downtime; applications that
need availability should run multiple instances behind a load balancer and
coordinate rollout. Slot rollback is not an application-data backup.

GCP resources keep accruing charges until removed. With the same variables
used for deployment, this explicitly deletes the VM and its auto-deleted
boot disk (**including application data**), firewall rule, image and upload:

```sh
make -C examples/python delete-gcp ARCH=x86_64
```

The bucket is retained. Review gcloud's confirmation prompts. After a
partially failed deployment, use `make -k ... delete-gcp` so cleanup continues
past resources that were never created. Resources are kept on failure for
inspection. Use a fresh deployment name when retrying a changed image;
uploads require an absent object (`--if-generation-match=0`) and an existing
GCP image is never replaced.

## Possible next steps

The examples need no new VM-side helper. Application-aware health gating,
a shared production deployment command, and a signed release channel for
custom application images would be useful follow-ups to discuss. Each would
need its own policy for rollout, rollback and preserving data.
