# leash(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

leash — start a service with its declared privileges and resource limits

## SYNOPSIS

**/etc/sv/NAME/run**

**/etc/sv/NAME/narrow/PROGRAM** [*argument ...*]

## DESCRIPTION

The **leash** launcher reads the service declaration in runsv's working directory,
prepares its private directories, drops to its user, applies Landlock and seccomp
restrictions, and executes the declared program. A malformed declaration parks the
service rather than starting it partially.

The service file contains a key and words per line. Double quotes group words; a hash
at the beginning of a word starts a comment. Principal declarations are:

- **exec**, **user**, **pledge**

  Required program and arguments, account and system call promises. Root is reserved
  for the SSH service's login capability.

- **before**

  Commands run before the main program, confined as the service user. Each must
  succeed.

- **read**, **write**, **run**

  Additional readable paths, writable paths and executable files.

- **listen**, **connect**

  Granted ports and, for connect, named UNIX sockets. A low listening port retains
  the capability required to bind it.

- **requires**

  Paths that must exist before startup.

- **env**, **secret**, **config**

  Environment values and private copies of boot configuration. Missing required files
  park the service.

- **setting**, **render**

  Typed settings consumed by service-config(8).

- **nofile**, **memory**, **cpu**

  Open-file limit, memory limit in MiB and contended CPU weight.

- **share**, **group**

  Directory sharing mode and supplementary service groups. Directories are private by
  default.

- **root**, **dir**

  Embedded image root and starting directory.

- **narrow**

  Additional pledge and path restrictions for a named executable.

As root, the launcher validates the declaration, reads required secrets, creates the
service directories and joins its cgroup. It then drops privileges, sets no_new_privs
and applies filesystem rules. Configuration rendering and before commands run before
the final pledge. The main program replaces the launcher.

A narrowed invocation stacks the named program's smaller policy on the service's
existing confinement and preserves its arguments. Restrictions cannot be widened.

## FILES

- `/etc/sv/NAME/service`

  Immutable service declaration.

- `/run/svc/NAME`

  Private runtime directory.

- `/data/svc/NAME`

  Persistent service directory when data is available.

- `/run/cgroup/svc/NAME`

  Service cgroup, with a limit of 4096 tasks.

## SEE ALSO

fence(8), leash-reap(8), seal(8), service-config(8)

## CAVEATS

An executable grant applies to a file, so granting one BusyBox applet allows the
other applets in that binary. A readable dynamic executable may also be started
through its permitted loader.
