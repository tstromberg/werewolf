# clsi-confine

## Summary

clsi-confine runs one Overleaf compile on a leash of its own, so a document reads
only its own project, TeX's files and a TeX cache of its own.

## Background

Overleaf's compiler, clsi, runs every project's TeX as one user, `_oci-clsi`, beneath
one directory. TeX runs what its users write. TeX Live 2026 made `openin_any` a no-op
(`texmf.cnf`: `kpse_in_name_ok` always returns true), so `\input` of any path clsi's
user can read worked, another project's compile directory included. clsi's leash
cannot tell compiles apart, and `narrow` (docs/design/implemented/narrow.md) takes
neither an image's root nor a directory chosen per run.

## Goals

- A compile reads its directory, `/usr`, the loader's cache, fontconfig's files, the
  CPU list and the devices; it writes only its directory and its own cache.
- It makes no link, device or socket, connects to no TCP port or pathname socket, and
  signals nothing outside its domain.
- The case `overleaf-write18` (forms/overleaf/test/tests.yaml) holds: a compile's
  read of `/etc/hostname` yields nothing, where its read of its own `main.tex` does
  not.

## Non-Goals

- Word counts (`texcount`) and SyncTeX, which clsi runs itself, not by latexmk.
- Compiles as separate users, as upstream's Server Pro does with containers.

## Detailed design

clsi's setting `clsi.latexmkCommandPrefix` names it (clsi-settings.cjs, clsi's
`OVERLEAF_CONFIG`), so clsi runs `clsi-confine DIR latexmk ...`, with DIR the
compile's directory. It refuses a DIR not beneath `/var/lib/overleaf/data/compiles/`
or a name other than hex and dashes, and opens DIR and its cache with no link in the
way. The cache is `/var/lib/overleaf/tmp/texmf-var/NAME`, made if absent, and becomes
`TEXMFVAR`. It sets `no_new_privs` and refuses gaining executable memory, enters a
Landlock domain of those paths, and execs latexmk by `PATH`. The domain stacks on
clsi's leash, whose run list still names what latexmk may start. A refusal is a
`refused` line on stderr and exit 1, which clsi reports as a failed compile.

## Drawbacks

- One cache per project: fonts and formats TeX makes are made again for each, and the
  caches stay after clsi drops a project.
- Landlock refuses opening, not looking: a document still learns which paths exist,
  and `\input` or `\openin` of one outside the domain stops TeX with a fatal error
  (web2c opens a file it found with `xfopen`), where TeX would otherwise read it as
  absent.

## Alternatives Considered

- One shared cache. A document could leave a font cache, Lua that luaotfload loads,
  for another project's compile.
- A preload wrapping clsi's spawn. The setting is upstream's own and covers every
  latexmk run.
- A user per compile. That needs a privileged helper; clsi holds no capability.
