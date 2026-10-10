# Examples

Proposed, 2026-10-10.

## Summary

The two shell fences in a form's README are how that form is started in a
test. `make example-FORM` runs the local fence on howl's default engine.
`make examples-gcp` runs the production fence on GCP. The run is the
service's test, and it records a few measurements beside the pass.

## Background

`make check-FORM` boots a `DEV=1` image under QEMU and runs
[test/checks](../../test/checks) as root on the serial console, then
`forms/FORM/test/checks`. That attacks a machine. The README starts one
with `howl create`, files made in the prose above the fence, a shared
machine name, and `--on lima` or `--on proxmox`. Nothing runs the fence,
so a flag can rot while the command still looks right.

howl already picks a local engine when `--on` is absent: Lima where it is
installed, otherwise bhyve, otherwise Firecracker when its network needs
no password, otherwise QEMU ([cli.md](cli.md)). `make check-gcp` already
makes one machine and deletes it ([testing.md](../testing.md)). The runner
is those two, pointed at a fence.

## Goals

- `make example-FORM` runs that form's local fence, checks the machine from
  outside, deletes it, and exits 0.
- `make examples-gcp` does the same with the production fence, on GCP, when
  gcloud is logged in.
- A fence that names the wrong engine, or a second `sh` fence in the
  section, fails `make lint`. The log records seconds, posture, and
  whether each documented TCP port accepted a connection.

## Non-Goals

- Replacing the `DEV=1` console checks. They need a root shell the shipping
  image lacks, and they stay `make check`.
- AWS, Azure, Proxmox, or a browser. Proxmox stays prose for a home form.
  The fence that runs is GCP.
- A public DNS name, an SMTP relay, or a boot-time budget.
- READMEs with no Getting Started. They stay on `make check`.

## Detailed design

**The fences.** Under each deployment heading in
[forms/TEMPLATE.md](../../forms/TEMPLATE.md), one fenced `sh` block, and it
is the whole setup. Prose is documentation. A variant (another upstream, a
forward zone) is a `text` block, so lint can tell an example from an
illustration. The local fence passes no `--on`. The production fence
passes `--on gcp` and `--allow-from me`. The machine's name is the form's
name, so Blocky and Unbound are `blocky` and `unbound`.

A file the command reads is written by an earlier line of the fence, or it
lives in `forms/NAME/example/`. The runner copies that directory into an
empty scratch directory and runs the fence there. A jar, a PKCS#8 key, and
an Authelia `users.yml` go in `example/` or are written by the fence. A
secret is a command (`openssl rand`), never a literal in the README.

**The run.** `test/example FORM local|gcp` extracts the fence and runs it
with `sh`, with `build/host/howl` first on `PATH`. howl prints
`NAME ADDRESS FORM`. The runner then:

- reads the posture line from the console log howl kept, and requires the
  failures to be the form's `weaknesses`, as `test/boot` does
- connects, from the host, to each `tcp/PORT` listed under Network Exposure
- runs `forms/NAME/test/probe` when that file exists, with the address and
  the scratch directory, so it can read the password the fence wrote
- runs `howl delete NAME` on the way out, after a failure or a timeout too,
  and deletes a leftover of that name before it starts

A probe is the protocol check (a login, a blocked name) run from the host.
It takes over from `forms/NAME/test/checks` once it covers the same
behavior. Until then `make check-FORM` stays, and the example run sits
beside it. A form whose `archs` exclude the host is skipped on `local`;
its production fence passes `--arch` and runs on GCP.

**CI.** `make examples` is a job beside `check-forms`, sharded the same
way. The GitHub runner has QEMU and no Lima, so that engine is QEMU, and
the fence is the one a laptop with Lima runs too. Production is nightly:
a few cents and several minutes a form, and pull-request CI has no cloud
credentials. `CLOUD_KEEP=1` keeps the machine, as `make check-gcp` does.
Each run appends form, engine, seconds until howl returned, and posture to
`build/<arch>/check/FORM-example.log`. This version sets no time limit.

## Drawbacks

- A form boots two ways until its probe covers its console checks, and a
  fence is a poor place for an aside, so variants move to `text` blocks.
- A nightly GCP failure can be a quota or a credential. The log names which.
- Lima and QEMU pass UDP differently, so a DNS probe can fail on one engine.

## Alternatives Considered

- **Review the README by hand.** That is the drift this catches.
- **Generate the README from the test, or include a sidecar script.** A
  root shell on a NAT address is not a howl command, and a second file can
  drift from the fence. The fence is the source.
- **Pin `--on lima`, and skip where Lima is absent.** CI would skip the
  command the README gives.
- **Run every fence, variants included.** The second command wants a mail
  relay, another cloud, or a name the first command already took.

## Security Considerations

The machine is the image a user gets, with no debug shell. The production
fence opens ports to the runner's address (`--allow-from me`), as
`make check-gcp` does; `0.0.0.0/0` fails lint. The scratch directory is
mode 0700 and is removed afterwards. The runner adds no flags and does not
print the files the fence wrote. GCP uses gcloud's existing login.

## Reliability Considerations

A crashed run's machine is deleted before the next create, and again in a
trap. A create that never prints its line fails at the patience `make
check` uses, and a console with no posture line fails too. Local runs go
in parallel: each form has its own name and scratch directory. The GCP job
runs a few at a time, inside the project's quota.
