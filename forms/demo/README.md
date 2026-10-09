# The demo

`demo` is werewolf shown off: a machine that serves one web page about
itself and keeps itself patched, with no shell anywhere in the image.

The page, rewritten every minute, is plain and quick: no script, no web
fonts, light or dark as the browser prefers, and readable on a phone.

- **At a glance**: how long it has been up, when it last patched itself and
  what that fixed, how many known vulnerabilities it has by severity, and
  when it last checked for updates.
- **System**: `uname -a`, the release, the boot slot, whether the image
  has a shell (it has none), and what `/data` is.
- **Security**: every protection the machine has, each tested once per
  boot by `posture` ([posture.md](../../docs/posture.md)), with what it stops, how it
  was checked, and whether it passed. What werewolf does not do yet fails,
  in plain view.
- **Patches**: the last 25 package changes it applied to itself, newest
  first, with the CVEs each fixed and whether the update was applied or rolled
  back.
- **Vulnerabilities**: grype's findings, grouped by the package that put
  them in the image, worst first. A Go module that grype finds inside
  `/usr/bin/grype` is listed under `grype`: the apk database says which
  package installed each file, and the build record which files are
  werewolf's own. Each advisory links to OSV.
- **Packages**: everything installed, with each package's findings linked.

Times read as "2 hours ago", with the moment itself on hover. The logo is
`docs/media/logo-small.png`, served from the image.

## How it works

| Piece | Runs as | Does |
| --- | --- | --- |
| `status` (`forms/demo/cmd/status-page/status-page.zig`) | `status` | writes the page every minute, and may reach nothing on the network |
| `scan` (the same program) | `grype` | once an hour, and at start, runs grype over the root (`dir:/`, without `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/data`, `/victim`) and keeps a summary for the page; the only user allowed to fetch |
| PostgreSQL | `postgres` | keeps every boot's posture report and every scan's summary, which the page reads back, newest first; on a UNIX socket only ([postgresql.md](../postgresql/README.md)) |
| nginx | `nginx`, master and workers | serves `index.html` from `/data/svc/status/www`, `GET` only, and nothing else; able to bind :80 and nothing else |
| autoupdate | root | checks Wolfi and Alpine every hour (`/etc/werewolf/update-every`), and on anything newer builds the other slot and reboots into it |

nginx, status and scan are leashed ([programs.md](../../docs/programs.md)): each
`/etc/sv/NAME/run` is a link to `leash`, which reads the `service` file
beside it and starts the service as its own user, never root, under a
Landlock ruleset of what that file names. nginx may bind :80, read its
configuration and the page, and nothing else. The page writer reads
`/data/svc` and `/run/werewolf`, writes its own directory, and may reach
nothing on the network. The scan reads the whole image, writes only its
own directory, and runs nothing but grype. No script stands between runsv
and any of them. init, runit's stages and the updater are programs too
([docs/design/shell-free.md](../../docs/design/shell-free.md)), so the image carries no
shell, interpreter or download tool at all, which `posture` checks at
every boot.

The patch history is the updater's own record: its reports and log in
`/data/svc/autoupdate` ([updater.md](../../docs/updater.md)). A CVE is listed against
a package when the update's report credits that package's source package
with the fix.

nginx sends `Content-Security-Policy: default-src 'none'`, so the page can
run no script and load nothing. Every value on it, from package names to
grype's findings, is HTML-escaped. Advisory IDs link to osv.dev only when
they consist of the characters IDs use.

## What it keeps

```
/data/svc/status/      the page's, owned by the status user
    www/index.html     the page
/data/svc/postgres/    PostgreSQL's cluster: every boot's posture and every
                       scan, of which the page shows the newest
/data/svc/scan/        the scan's, owned by the grype user
    scan.json          the last grype run's findings, which the page shows
    scan-error         why the last run did not finish, while it did not
    db/                grype's vulnerability database
    tmp/               its downloads, emptied before each run
/data/svc/autoupdate/  the updater's log and reports (the patch history),
                       and its package cache
```

grype's database is a 190 MB download, rebuilt daily, which unpacks to
several times that. It is fetched again when grype finds a newer one. A
`/data` in RAM cannot hold it, so on a machine without a data disk status
does not scan, and the page says why.

## Running it

The demo is for a VM, booted from a slot so that `/data` is on the VM's
disk and survives every reboot and update. It has two ways in.

**Its own disk**, wherever a VM can boot a disk image with UEFI
([docs/design/native-boot.md](../../docs/design/native-boot.md)):

```sh
make FORM=demo disk                     # build/<arch>/demo/disk.img, 8 GiB, sparse
```

**bite**, where a provider boots only its own images:

```sh
make FORM=demo slot                     # build/<arch>/demo/slot/
scp -r build/<arch>/demo/slot bite vm:  # then, on the VM:
sudo ./bite -n slot                     # check, and show the plan
sudo ./bite --reboot slot               # take over, and reboot into werewolf
```

Allow TCP port 80 in the provider's firewall. The page is up as soon as the
machine is; the first scan follows the database download.

| | Enough |
| --- | --- |
| Memory | 2 GB: grype loads its database |
| Disk | 8 GiB, its disk's size; with bite, 10 GB free in `/var/lib/werewolf` |
| Network | Wolfi, Alpine, git.kernel.org (updates); grype.anchore.io (the database) |

On a Mac with Apple silicon, howl builds the disk and boots it in Lima, as
Lima boots a distro, and prints the page's URL:

```sh
build/host/howl create werewolf-demo --with demo --on lima   # http://192.168.64.N/
build/host/howl delete werewolf-demo --on lima               # the VM, and the /data it kept
```

Lima forwards ports through ssh or its guest agent, and the demo runs
neither, so the VM gets a second network, vzNAT, whose address the Mac
reaches directly. The disk names that network's MAC (`werewolf.mac=`),
derived from the VM's name, so DHCP runs there, and macOS's DHCP server
records the address it gave. `limactl start` waits for ssh that never
answers, so `howl create` waits for that address instead. A second create
restarts the VM with a new config, keeping its `/data`. Building the disk
on a Mac needs `brew install mtools e2fsprogs`.

On Google Compute Engine, howl makes the same disk a GCP image, once, boots
a VM of it, and with `--allow-from` opens port 80 to this host:

```sh
build/host/howl create werewolf-demo --with demo --on gcp --allow-from me
build/host/howl console werewolf-demo --on gcp               # the serial port: the boot
build/host/howl delete werewolf-demo --on gcp                # the VM, its disk and firewall rule
```

It uses gcloud's project and zone (`us-central1-a` if none), and uploads the
image through a bucket it makes, `PROJECT-werewolf-images`, deleting the
upload once the image is made. The VM is this host's arch, or `--arch`'s:
a `t2a-standard-1` on aarch64; on x86_64 add `--size e2-medium`, since the
default `e2-small` is too small for PostgreSQL and grype. It costs what its
machine type costs until it is deleted
([examples/README.md](../../examples/README.md#prepare-gcp-once)).

To boot the image directly instead, without slots or updates, under QEMU
with an 8 GiB `/data` disk:

```sh
build/host/howl run --with demo --on qemu                    # prints the page's URL
```

## Costs

- **Hourly checks rebuild the image's package set** to compare it with the
  running one. The updater keeps a package cache on `/data`, so a check
  downloads the indexes and whatever changed, not grype's 90 MB again.
- **Reboots.** An update reboots the machine when it applies. Wolfi
  publishes several times a day, so the demo reboots that often; each
  reboot is a minute of downtime, and the page's uptime shows it.
- **grype's database**, daily.

## Limits

- One page, over HTTP. TLS needs a certificate, which this form has no
  way to receive or renew; put it behind a proxy that has one, or a
  Cloudflare tunnel.
- grype reports what its database knows. Its findings for grype itself, a
  Go program with many dependencies, are usually most of the list.
