# The demo

`demo` is werewolf shown off: a machine that serves one web page about
itself and keeps itself patched. Its own services, nginx and the program
that writes the page, run without a shell.

The page, rewritten every minute, is plain and quick: no script, no web
fonts, light or dark as the browser prefers, and readable on a phone.

- **At a glance**: how long it has been up, when it last patched itself and
  what that fixed, how many known vulnerabilities it has by severity, and
  when it last checked for updates.
- **System**: `uname -a`, the release, the boot slot, whether the image
  still has a shell, and what `/data` is.
- **Security**: every protection the machine has, each tested once per
  boot by `posture` ([posture.md](posture.md)), with what it stops, how it
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
`media/logo-small.png`, served from the image.

## How it works

| Piece | Runs as | Does |
| --- | --- | --- |
| `status` (`status/status.zig`) | root | writes the page every minute; once an hour, and at start, runs grype and keeps a summary |
| grype | `grype` | scans the root (`dir:/`, without `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/data`, `/victim`) |
| nginx | root master, `nginx` workers | serves `index.html` from `/data/svc/status/www`, `GET` only, and nothing else |
| autoupdate | root | checks Wolfi and Alpine every hour (`/etc/werewolf/update-every`), and on anything newer builds the other slot and reboots into it |

`/etc/sv/status/run` and `/etc/sv/nginx/run` are links to the programs
themselves, so runsv starts them with no script between. `init`, runit's
stage scripts and `autoupdate`'s loop are still shell. They go with the
shell-free design's phases 1 and 2 ([design/shell-free.md](../design/shell-free.md)),
and then the image carries no shell at all. The page says which is true.

The patch history is the updater's own record: its reports and log in
`/data/svc/autoupdate` ([updater.md](updater.md)). A CVE is listed against
a package when the update's report credits that package's source package
with the fix.

nginx sends `Content-Security-Policy: default-src 'none'`, so the page can
run no script and load nothing. Every value on it, from package names to
grype's findings, is HTML-escaped. Advisory IDs link to osv.dev only when
they consist of the characters IDs use.

## What it keeps

```
/data/svc/status/
    www/index.html     the page
    scan.json          the last grype run's findings, which the page shows
    scan-error         why the last run did not finish, while it did not
/data/svc/grype/       grype's own, owned by the grype user
    db/                its vulnerability database
    tmp/               its downloads, emptied before each run
/data/svc/autoupdate/  the updater's log and reports (the patch history),
                       and its package cache
```

grype's database is a 190 MB download, rebuilt daily, which unpacks to
several times that. It is fetched again when grype finds a newer one. A
`/data` in RAM cannot hold it, so on a machine booted directly (`make run`)
status does not scan, and the page says why.

## Running it

The demo is for a VM, booted from a slot so that `/data` is on the VM's
disk and survives every reboot and update. It has two ways in.

**Its own disk**, wherever a VM can boot a disk image with UEFI
([design/native-boot.md](../design/native-boot.md)):

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

On a Mac with Apple silicon, `make demo` builds the disk and boots it in
Lima, as Lima boots a distro, and prints the page's URL:

```sh
make demo                               # http://192.168.64.N/, when it is up
make demo-stop                          # delete the VM
```

Lima forwards ports through ssh or its guest agent, and the demo runs
neither, so the VM gets a second network, vzNAT, whose address the Mac
reaches directly. The disk names that network's MAC (`werewolf.mac=`), so
DHCP runs there, and macOS's DHCP server records the address it gave.
`limactl start` waits for ssh that never answers, so `make demo` waits for
the page instead. A second `make demo` finds the VM and prints the URL
again. Building the disk on a Mac needs `brew install mtools e2fsprogs`.

To boot the image directly instead, without slots, updates or a scan:

```sh
make run FORM=demo                      # then http://127.0.0.1:8080/
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
