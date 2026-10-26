# Scenarios

A form's native tests boot it as it ships. The platform's own tests boot a stock form
some other way: with no address for DHCP, with its address in the config, with posture
under strain. Each is a scenario, `test/scenarios/NAME/`, a plan beside its config hook
and any driver, and `make check-scenario-NAME` (or its old name, such as `make
check-lease`) runs it as `check-native-tests-FORM` runs a form: the stock form's own
production image is the baseline, the test image adds the drivers, the payloads must
match, and the machine boots twice on one data disk ([native tests](testing-native.md)).

```yaml
version: 1
form: minimal              # the stock form it boots
kernel_address: false      # no werewolf.ip on the kernel command line
skip: [data-encrypted]     # shared checks its way of booting rules out
console:
  - seen: from-config
    matches: 'werewolf: [^ ]+ 10[.]0[.]2[.]15/24 via 10[.]0[.]2[.]2'
  - unseen: refused
    matches: 'werewolf: network: .*refused'
  - up: service-down       # no leash down or retry; `service: NAME` for one
suites:
  - name: static
    cases: ...
```

`form` names a form in `forms/`. `kernel_address: false` boots with `BOOT`, the check
command line without an address, so init must find one in the config's `network` file
or by DHCP. `skip` adds to the form's own `check.skip`. `console` lines are judged by
[test/console.zig](../test/console.zig) in every boot, as a form's `test/console` is in
its shipping check: `seen`/`unseen` POSIX EREs, `up` for services that stay up. `config`
and `config-again` beside the plan prepare each boot's config directory, as a form's
`test/config` does. A scenario may have no suites of its own (`suites: []`). A form's
own plan may use none of these keys, and `--iterate` does not run scenarios.

`boots` changes how one of the two boots is made: `verify: {data_key: false}` packs its
config without `data.key`, so init must refuse the disk the seed boot made, as
[nodata](../test/scenarios/nodata/tests.yaml) checks; a boot that formats the disk
fails. A console line or a case judged in one boot only names it in `phases`.

`app: NAME` boots the form with the code `howl --app` would supply: the fixture
[test/app-fixtures](../test/app-fixtures) names, staged by
[test/app-fixture](../test/app-fixture). Both images are built with it (`-app`), and the
form's own `check.skip`, for what its missing code rules out, no longer applies. Each
application-carrier form has one, `app-FORM`, which `make check-app-FORM` runs. A
runtime is for running an application, so `make check-RUNTIME` runs its carrier's, the
runtime the fixture's last column names: `make check-python` boots `python-app` with
a hello-world. Every runtime's hello-world answers one contract, the same cases in each
`app-FORM` plan: a greeting naming the runtime, `/health`, 404 for an unknown path, and
405 with `Allow: GET` for any other method, all `text/plain; charset=utf-8`. A new
runtime brings a hello-world that answers it.

Forms that a check generates, such as `test/bastion-form`'s and `test/people-form`'s,
are not scenarios: their generators copy a plan from `test/generated/NAME/` or the
form's own `test/` into the form they write, and make checks that form as any other.
