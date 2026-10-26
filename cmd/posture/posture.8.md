# posture(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

posture — report the running machine's protections

## SYNOPSIS

**posture** [**--extended**] [**--attack**] [**--no-cache**] [**--verbose**]
[**--json** | **--line** | **--summary**]

## DESCRIPTION

The **posture** utility checks kernel protections, processes, filesystems and network
policy. It reports passes, failures and checks it cannot perform, with reasons. On
Werewolf it also checks the machine seal and service confinement. Other Linux systems
receive the applicable generic checks.

The options are as follows:

- **--extended**

  Include protections Werewolf deliberately leaves optional, such as forced CPU
  mitigations and wiping freed memory.

- **--attack**

  Run additional intrusion probes. These expect the kernel to refuse access; use only
  when testing is intended.

- **--no-cache**

  Do not use the boot report for checks this invocation cannot perform. Report those
  checks as skipped.

- **--verbose**

  Write phases, timings and walk progress to standard error.

- **--json**

  Write JSON, including the source, expected value, observation and comparison.

- **--line**

  Write one line with failure identifiers, counts and JSON.

- **--summary**

  Print the login summary: identity, state, counts and declared gaps.

Without a format option, output is human-readable text. Results taken from the boot
report are marked as cached. Running as root permits more checks; some checks require
the boot service's context even when the caller is root.

When invoked as `/etc/sv/posture/run`, **posture** waits for services to settle,
writes the boot report and login message, then takes itself down. Checks may leave
refusal records in the kernel log and console.

## ENVIRONMENT

- `WEREWOLF_CHECK`

  The value 1 enables intrusion probes, as does the kernel argument
  `werewolf.check=1`.

## FILES

- `/run/werewolf/posture.json`

  Boot report used for cached results.

- `/run/werewolf/motd`

  Boot login message.

- `/usr/share/werewolf/weaknesses`

  Failures the image declares and excuses.

## EXIT STATUS

The exit status is 1 if any check fails, including an excused failure, and 0 if no
check fails. Invalid arguments produce status 2.

## EXAMPLES

```sh
posture --summary
posture --json
```

## SEE ALSO

fence(8), leash(8), seal(8)
