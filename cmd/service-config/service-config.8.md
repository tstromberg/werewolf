# service-config(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

service-config — render declared service settings inside the service's confinement

## SYNOPSIS

**service-config** *directory* [*name*]

## DESCRIPTION

The **service-config** utility reads setting and render declarations on standard
input, validates the private settings copy in *directory*, and writes the declared
configuration output. The directory must be absolute. The service name defaults to
its basename.

leash(8) invokes this helper after dropping to the service's user and applying
Landlock restrictions. The helper refuses to run as root. It reads its inputs before
installing a system call filter and parsing the machine's settings.

Only declared names and types are accepted. Supported outputs are environment
variables, JSON and configuration lines. Validation precedes all writes; files are
recreated with mode 0600. A rejected value is reported by service, setting and
reason, without logging the value. Leash keeps a service down if its settings cannot
be rendered.

## FILES

- `/run/svc/NAME/settings`

  Private settings copy supplied by leash.

## SEE ALSO

leash(8)

## CAVEATS

Settings are not a secret-delivery mechanism. Use the service's declared secret or
configuration files for credentials.
