# Porting a form to native tests

See [testing.md](testing.md) for running tests and the integration coverage rules.

Start with one existing behaviour and keep the DEV check until its native
equivalent passes. Declare each driver's user, groups, client programs, paths,
network endpoints and seed/verify cases in `test/native.json`; the harness
rejects root drivers, broad grants, missing results and changes to production
files. Put the Zig client beside the plan and use the shared result context,
deadline and protocol helpers from `test/native/driver.zig`.

Use the service's real client where practical: Greenbone uses `psql` for SQL,
then small GMP/OSP clients for its private sockets. Run under the service's
actual account and only add a group when the socket or data share requires it.
Wait for paths to appear before applying test confinement, then let the client
check that the service is ready. Procfs reports a zero file size, so use
`readKernel` for `/proc` tables; an empty or unreadable table must fail a check.

For persistence, write a run-specific value in seed and read it on the same
encrypted disk in verify, before setup can recreate it. Keep expected case
names fixed in the plan and test refusal with a valid request that cannot
change state. Compare the generated test image with the plain image before
boot; add only declared test packages, clients and metadata. Retire each old
shell assertion only after its protocol-level replacement passes on both
phases and the retained checks still pass.

