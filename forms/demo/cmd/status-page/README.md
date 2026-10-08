# status-page

## Summary

The demo form's web page about the machine it runs on, and the grype scan
the page reports: two leashed services, one program. The page shows the
kernel and uptime, the security checks, the patches the updater applied
with the CVEs each fixed, what grype finds in the image, and the packages.

## Background

The demo shows what werewolf does on a running machine, so the page reads
the machine itself: posture's report, the updater's log and reports, the
image's package list, and a vulnerability scan. nginx serves the page;
PostgreSQL keeps the history of postures and scans where the form runs it.
grype's database comes from the network and package metadata is other
people's text, so all of it is input to distrust.

## Goals

- A page that is true of the machine, rewritten every minute.
- Nothing from outside written into it unescaped.
- The scan, the only part that fetches, kept apart from the page.
- A page that survives PostgreSQL being down, and says so.

## Non-Goals

- Serving: nginx does, from the page's directory.
- Judging a finding: grype's severity is shown as grype gives it.

## Detailed design

- **Files**: `status-page.zig` (the loop, what it gathers, the database's
  use, the updater's history), `page.zig` (the HTML), `scan.zig` (grype and
  its summary), `pg.zig` (the PostgreSQL client).
- **status** (user `status`, pledge `stdio rpath wpath unix connect`, no
  network): every minute, gathers and writes
  `/data/svc/status/www/index.html` whole (a temp file renamed in). Every
  string from outside goes through `esc` (`& < > " '`); advisory IDs become
  OSV links only if made of ID characters. What it reads of the scan's
  files, which another user writes, is capped at 4 MiB.
- **scan** (user `grype`, may connect to 443 and 53 alone): at start and
  hourly, runs grype over the root but `/proc`, `/sys`, `/dev`, `/run`,
  `/tmp`, `/data` and `/victim`, with its database in `/data/svc/scan`,
  never in RAM. grype's stderr reaches the console a line at a time, each
  control character as `?`. The summary is kept in `scan.json` and, where
  there is PostgreSQL, in `status.scans`.
- **PostgreSQL**: its own wire protocol over the UNIX socket, as the
  service's role by peer authentication: no password, no TCP, no libpq.
  Every value is a parameter, never part of the SQL; only "authentication
  OK" is accepted; messages are capped at 16 MiB, rows bounds-checked, and
  each read and write times out at 30 s. A refusal is logged with
  PostgreSQL's own message.
- **Data lost**: the page keeps how many postures and scans it last saw; a
  database that holds fewer has lost data, and the page says so.
- **Logs** one JSON line per event; one too long to say is said to be.

## Drawbacks

- A minute's staleness, and an hour's for the scan.
- The PostgreSQL client speaks only what the page needs.

## Alternatives Considered

### libpq, or a driver
A C library and its dependencies in the image, for two queries.

### A dynamic page
A process answering the network; a file nginx serves is all this needs.

### One user for page and scan
The scan fetches from the internet; the page must not be able to.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| HTML or script injection | Every outside string escaped; links only for checked IDs. |
| SQL injection | Every value a parameter of the extended protocol. |
| A hostile grype database | grype runs as its own user, leashed; the page escapes its findings and caps what it reads of them. |
| The console driven by grype | Control characters shown as `?`. |
| A rogue PostgreSQL message | Lengths checked before use; any auth but OK refused. |

## Reliability Considerations

- **Degrades**: without PostgreSQL, from the files; without a scan, says
  why; without `/data` on disk, no scan, and says so.
- **Bounded**: each pass has its own arena, freed when the pass ends.
- **Tested**: unit tests per file (escaping, the protocol's rows, grype's
  summary, PostgreSQL's refusals, the page); `check-demo` and
  `check-persist` boot it and read the page.
