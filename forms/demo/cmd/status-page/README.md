# status-page

## Summary

status-page writes the demo form's web page about the machine it runs on.
As `status-page scan` it runs the grype scan the page reports. Two leashed
services run the one program. The page shows the kernel, uptime and boot
times, the security checks, the last 25 patches the updater applied with
the CVEs each fixed, what grype finds in the image, and the packages.

## Background

The demo shows what werewolf does on a running machine, so the page reads
the machine itself: posture's report, the updater's log and reports, the
image's package list, and a vulnerability scan. nginx serves the page.
Where the form runs PostgreSQL, it keeps the history of postures and scans.
grype's database comes from the network and package metadata is other
people's text, so all of it is untrusted input.

## Goals

- The page is true of the machine, and is rewritten every minute.
- Nothing from outside reaches the page unescaped.
- The scan, the only part that fetches, runs apart from the page.
- The page survives PostgreSQL being down, and says so.

## Non-Goals

- Serving: nginx serves the page's directory.
- Judging a finding: the page shows grype's severity as grype gives it.

## Detailed design

- **Files**: `status-page.zig` (the loop, gathering, the database, the
  updater's history), `page.zig` (the HTML), `scan.zig` (grype and its
  summary), `pg.zig` (the PostgreSQL client).
- **status** (user `status`, never root, pledge `stdio rpath wpath unix
  connect`, no network): every minute it gathers facts and writes
  `/data/svc/status/www/index.html` through a temp file and a rename, since
  nginx may be reading the old one. Every outside string goes through `esc`
  (`& < > " '`). Advisory IDs become OSV links only if made of ID characters.
  It reads at most 4 MiB of the scan's summary, which another user writes.
- **Boot row**: at start it reads the kernel and userland times from
  `/run/werewolf/boot`, and polls every 25 ms, for up to 30 s, until nginx
  listens on :80 and a PostgreSQL login completes.
- **scan** (user `grype`, may connect only to ports 443 and 53): at start and
  hourly it runs grype over `/`, excluding `/proc`, `/sys`, `/dev`, `/run`,
  `/tmp`, `/data` and `/victim`, for at most 30 minutes. Its database lives
  in `/data/svc/scan`, never in RAM: with `/data` on tmpfs it does not scan.
  grype's stderr reaches the console a line at a time, with control
  characters shown as `?`. The summary goes to `scan.json` and, where there
  is PostgreSQL, to `status.scans`. A failure goes to `scan-error`.
- **PostgreSQL**: the wire protocol over the UNIX socket, as the service's
  role by peer authentication: no password, no TCP, no libpq. Every value
  is a parameter, never part of the SQL. Only "authentication OK" is
  accepted. Messages are capped at 16 MiB, row lengths are checked, and each
  read and write times out after 30 s. A refusal is logged with
  PostgreSQL's message. The page shows the newer of the database's scan
  and `scan.json`, since a scan that ended while PostgreSQL was down is
  only in the file.
- **Lost data**: the page keeps the counts of postures and scans it last
  saw. A database that holds fewer has lost data, and the page says so.
- **Logs**: one JSON line per event. A line too long to log is replaced by
  an error saying so. A repeating failure is logged once, when it starts.

## Drawbacks

- The page can be a minute stale, and the scan an hour.
- The PostgreSQL client speaks only what the page needs.

## Alternatives Considered

### libpq, or a driver
A C library and its dependencies in the image, for two queries.

### A dynamic page
A process answering the network, when a file nginx serves is enough.

### One user for page and scan
The scan fetches from the internet; the page must not be able to.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| HTML or script injection | Every outside string is escaped; links only for checked IDs. |
| SQL injection | Every value is a parameter of the extended protocol. |
| A hostile grype database | grype runs as its own user, leashed; the page escapes its findings and caps what it reads. |
| The console driven by grype | Control characters are shown as `?`. |
| A rogue PostgreSQL message | Lengths are checked before use; any auth but OK is refused. |

## Reliability Considerations

- **Degrades**: without PostgreSQL it reads the files; without a scan it
  says why; without `/data` on disk it does not scan, and says so.
- **Bounded memory**: each pass has its own arena, freed when the pass ends,
  so a process that runs for months uses what one pass needs.
- **Tested**: unit tests per file (escaping, protocol rows, grype's summary,
  PostgreSQL's refusals, the page); `check-demo` and `check-persist` boot it
  and read the page.
