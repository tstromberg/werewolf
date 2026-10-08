# Settings

**Note for reviewers**:
While reviewing this proposal, focus on answering for yourself:

* Does this proposal fit with our engineering principles?
* Are there unexplored concerns with this design, such as reliability or usability issues?
* Could the proposed implementation be made simpler?
* Are there other alternatives to consider?

Built, 2026-10-07: `lib/settings.zig`, `service-config` and leash's
`setting` and `render` lines; the bastion and Tailscale forms use them.
Since 2026-10-08 the bastion takes no settings: its users and their
destinations are its image's, from form.yaml's `bastion:`
([forms/bastion/README.md](../../forms/bastion/README.md)).
The guest's half of [cli.md](cli.md); `howl pack` checks with the
same library on the host.

## Summary

A service file declares its per-machine settings, each with a type from a
closed set of ten, and one of three formats to render them in: `env`,
`json` or `conf`. One program, `service-config`, renders any service's
settings from the config tar, unprivileged, inside the service's leash;
the host's `howl pack` validates with the same code. A new service
gets per-machine settings by writing two lines in its service file, not a
renderer.

## Background

A form says what runs; the config tar ([cloud.md](../cloud.md)) says
what is particular to one machine. Secrets in the tar are files, and
leash already hands them to a service: `config authorized-keys
/run/config/bastion/authorized_keys` copies that file into
`/run/svc/sshd/authorized-keys`, mode 0600, owned by the service, at
every start ([programs.md](../programs.md)).

*Settings* are the other half: values that are not secret but differ per
machine, such as a bastion's destinations, a router's routes, a server's
public address, an application's database URL. A daemon reads them in
its own syntax, which is never a werewolf file.

[service-forms.md](service-forms.md) planned for each daemon to include a
per-machine fragment from `/run/config/NAME`. That makes whoever writes
the config tar an author of the daemon's configuration: a fragment can say
`PermitOpen any` or `"locked": false` as easily as a destination, and the
form's review no longer describes the machine. `service-config` was the
correction, built for two services: it reads `settings.json`, accepts
literal addresses and networks only, and writes what the daemon reads.

It does so with a case per service. `renderBastion` knows `PermitOpen`;
`renderTailscale` knows `advertiseRoutes`. The forms planned next
(openbao, caddy, haproxy, step-ca, valkey, the runtime forms'
applications) would each add a case: a parser of untrusted input per
service, in a program every machine carries. And the host cannot check a
setting before boot without its own copy of each case.

## Goals

- `service-config` has no service's name in it. Its bastion and
  Tailscale cases become declarations in their service files, with the
  same output and the same refusals: its tests carry over unchanged.
- A form adds a setting in one line of its service file, with no Zig.
- The host and the guest validate with one function per type, in `lib/`.
  A setting `howl pack` accepts, the guest accepts.
- A setting cannot add a directive, a key or a variable the service file
  did not declare. The image's review still describes the machine.
- The forms in service-forms.md and the runtime forms' applications are
  served by three formats, or this document says which are not and why.

## Non-Goals

- Secrets. They stay files, through `config` and `secret`, and never
  pass through a renderer, so a renderer has nothing to leak.
- A template language, an expression, or a path into a list. A `json`
  key with dots, `a.b.c`, names a nested object's key, and no more.
- Every daemon's syntax. A format is added when a form needs it and none
  of the three will do.
- Changing settings on a running machine. Settings change with the tar;
  the tar changes with a reboot ([cli.md](cli.md)'s `create`).
- Wireguard's peers. The kernel's module is configured over netlink by a
  program, not a file; that is its own design.

## Detailed design

### Two lines in a service file

```
setting NAME TYPE[...] [required] [as KEY]
render  FORMAT FILE [from PATH]
```

The values come from the file the service's `config settings PATH` line
names, which leash copies as it copies any `config` file. With `setting`
lines that line is required, and its file is not: a missing file is no
values. The path is the service file's to say, not derived from the
service's name, because a service's name is not always its own to pick:
the bastion's is `sshd`, as the service sshd is, while its files live in
`/run/config/bastion`.

`setting` declares one. `NAME` is a plain lowercase name: the key in
`settings.json`, and the flag `--NAME` on the host. `TYPE` is one of the
types below; `TYPE...` is a list of at most 32. `required` keeps the
service down until the setting is given; otherwise an absent setting is
absent from the output, and the daemon's own configuration in the image
supplies the default. `as KEY` names it in the output: the variable, the
JSON key or the directive. Without it, `KEY` is `NAME` for `json` and
`conf`, and `NAME` in upper case with `-` as `_` for `env`.

`render` says where they go, once per service that has settings. `FILE`
is a name in `/run/svc/SERVICE`, the service's own directory, where the
daemon's configuration in the image points. `from PATH` is for `json`
only: a file in the image, whose keys the settings replace.

Defaults live in the daemon's configuration, in the image, where the form
author already writes them and the reviewer already reads them. The
service file declares names and types, never values.

The bastion and the Tailscale router:

```
config  settings /run/config/bastion/settings.json
setting destinations addrport... as PermitOpen
render  conf destinations
```
```
config  settings /run/config/tailscale/settings.json
setting routes cidr... as advertiseRoutes
render  json config.json from /etc/tailscale/config.json
```

Each replaces a `before` line and a case in `service-config`.

### Types

A closed set in `lib/settings.zig`, named as Go's `net/netip` names them
where it has a name:

| Type | Accepts | For example |
| --- | --- | --- |
| `ip` | a literal IPv4 or IPv6 address, no zone | `10.0.0.1` |
| `cidr` | a network: no host bits, not `/0` | `10.20.0.0/24` |
| `addrport` | a literal address and port | `10.20.0.10:22`, `[fd00::1]:22` |
| `hostport` | a hostname or literal address, and port | `db.internal:5432` |
| `hostname` | RFC 1123, at most 253 bytes | `bao.example.com` |
| `port` | 1 to 65535 | `8200` |
| `url` | `http` or `https`, no user or password, at most 2 KiB | `https://bao.example.com:8200` |
| `int` | a decimal, signed 64-bit | `4` |
| `bool` | JSON `true` or `false` | `true` |
| `string` | printable UTF-8, no control characters, at most 1 KiB | `Engineering` |

`cidr` refuses `/0` because a setting that means everything is not a
setting: a router that should be an exit node is another form. `url`
refuses a password because settings are not secret: a database URL with
one in it belongs in a file. `string` is the escape hatch, and the most
restricted in where it may go.

A form that needs a type not here takes a file, validated by its own
service, until enough forms want the same thing to make it a type.

### Formats

| Format | Writes | A list is | Absent | Types it refuses |
| --- | --- | --- | --- | --- |
| `env` | `KEY=VALUE` lines | joined by `,` | no line | `string...`, `url...` |
| `json` | one object; with `from`, the image's object with declared keys replaced | an array | the base's value, or no key | none |
| `conf` | `KEY VALUE...` lines | joined by a space | no line | `string`, `url` |

Each refusal is the case the format cannot escape: a list of strings or
URLs may contain the comma that joins it, and a string or URL may contain the
space or `#` that ends a `conf` value. The pair is refused where the
service file is parsed, so a form that declares one does not build. No
renderer quotes anything; the types are what make quoting unneeded, and
`json` is written by Zig's serializer.

**`env`** is for applications and for daemons that read their variables
into their own configuration: Caddyfile's `{$NAME}`, haproxy's
`"${NAME}"`, Spring Boot's relaxed binding (`SPRING_DATASOURCE_URL`),
.NET's `ConnectionStrings__Default`, PHP's `getenv`. leash reads the
rendered file itself, not a shell: each line is split at its first `=`
and the value taken as it is. A `KEY` that is also an `env` or `secret`
line, or is `PATH` or begins `LD_`, does not build. php-fpm clears its
workers' environment, so the `php` form's pool lists the variables it
passes on.

**`json`** without `from` is a file of its own, for a daemon that reads
several (openbao's `-config`, given twice). With `from`, it is a daemon
that reads one, such as Tailscale's or step-ca's: the base's other keys,
`locked` among them, pass through untouched, and the settings can only
replace the keys declared. A key with dots, `a.b.c`, is a path into
nested objects (step-ca's `authority.policy.x509.allow.dns`, openbao's
`seal.static.current_key_id`), made where the base has none; a list is
never entered.

**`conf`** is for line-oriented daemons, such as sshd and valkey. A
`bool` is `yes` or `no`. Where the rendered file is included decides
precedence, and that is the form's to get right: sshd takes the first
value of a keyword, so the bastion includes its destinations before its
`PermitOpen none`; valkey takes the last, so it would include its file at
the end.

### Rendering

At each start of a service with `setting` lines, leash, as root, reads
the `config settings` file, or `{}` if it is missing, and copies it to
`/run/svc/SERVICE/settings` with the service's other `config` files,
then runs `/usr/lib/werewolf/service-config` as
the service's user, inside the service's Landlock rules, before any
`before` line. It writes the service's `setting` and `render` lines, as
it parsed them from the image with every key filled in, to
`service-config`'s standard input, so the renderer reads its
declarations from the image and its values from the tar, and parses the
first with the functions leash used. leash lets the renderer read the
`from` file, so a form need not add a `read` line for it. JSON keys and
`from` paths are words without spaces, as `conf` keys are.

`service-config` reads at most 32 KiB, refuses a duplicate key, a key not
declared and a value of the wrong type, and writes nothing until all of
it has been checked. It replaces its output by name and never follows a
link. Then leash, for `env`, reads the rendered file into the
environment, and runs the `before` lines and `exec`.

A refusal keeps the service down, as a missing `config` file does, and is
one structured line naming the service, the setting, the list index and
the reason:

```
{"event":"settings","service":"tailscale","setting":"routes","index":1,"why":"host bits set"}
```

The value is not in it. Settings are not secret, but a user who put a
secret in one by mistake should not find it on a serial console, and the
host's `pack` showed them the same refusal with the value already on
their screen.

The settings are copied and rendered again at every start, from root's
copy in `/run/config`. A service that is taken over can rewrite its own
rendered file, which it could configure anyway, but cannot keep the
change past a restart.

### On the host

`lib/settings.zig` is linked into `howl` too ([cli.md](cli.md)).
`pack` reads each service's `setting` and `render` lines from the form's
service files, in `./forms` or, later, in the image itself, offers
`--NAME` for each
setting, builds `settings.json` from the flags or checks the one in
`--config DIR`, and refuses with the guest's error and the value. The
guest's check is the one that counts; the host's is the same function,
run earlier.

### Checked against the forms

| Form | Settings | Format | |
| --- | --- | --- | --- |
| `bastion` | `destinations addrport...` | `conf` | since 2026-10-08, form.yaml's `bastion:` instead |
| `tailscale` | `routes cidr...` | `json from` | as today |
| `openbao` | `api-addr url required`, `cluster-addr url required` | `json` | a single node |
| `step-ca` | `dns-names hostname...`, `address hostport` | `json from` | |
| `caddy` | `domain hostname`, `upstream hostport` | `env` | `{$DOMAIN}` in the Caddyfile |
| `haproxy` | `backends hostport...` | `env` | one variable per backend list |
| `valkey` | `maxmemory int` | `conf` | included last |
| `node`, `python`, `jre`, `php` | the application's own | `env` | `_FILE` variables point at `config` files for secrets |
| `unbound` | forward zones | none | nested blocks; waits |
| `openbao`, clustered | `retry_join` | none | a list of objects inside `storage`; waits |

The two that wait both want structure: a list of objects, or a block per
value. Neither is a type or a format here, and a path language to reach
into one is the template language this design refuses. They wait for a
second form with the same need, or stay single-node.

### Order

1. `lib/settings.zig`: the types, the three formats, and the parser for
   `setting` and `render`, with tests that every value the bastion and
   Tailscale cases refuse today is still refused. `service-config` reads
   declarations from standard input and loses its two cases.
2. leash: the two lines, the implicit copy and render, the `env` file.
   The bastion and Tailscale service files lose their `config settings`
   and `before` lines.
3. `make check`: the bastion and Tailscale forms boot with settings, and
   the rendered files are compared with what is expected; a fuzz test of
   each type's parser.
4. `howl pack` links the library ([cli.md](cli.md), its first step).
5. The forms in service-forms.md, as they arrive.

## Drawbacks

- **A schema in the service file.** Two keys, ten types, three formats,
  `required`, `as`, `from`. Small, and still more than a reader of a
  service file had to learn before.
- **Precedence is the form's to get right.** Whether a `conf` include
  comes first or last depends on the daemon, and getting it wrong
  silently lets the image's default win over the setting. The check in
  step 3 is what catches it, per form.
- **Renaming a setting breaks machines.** A tar that names a setting the
  new image does not declare is refused, and the service stays down. On
  an A/B update that is caught: the new slot is unhealthy, and slot-keep
  boots the old one ([updater.md](../updater.md)). It is caught, not
  avoided; a form adds settings and does not rename them.
- **Structure is out of reach.** A `json` key with dots reaches into the
  image's nested objects (step-ca's `authority.policy.x509.allow.dns`),
  but a list of objects (OpenBao's peers, unbound's zones) does not fit a
  setting, and a user who needs one builds a form with the configuration
  in the image.
- **leash grows.** It parses two more lines, copies one more file, runs
  one more program and reads an environment file. leash is the code
  every service passes through.

## Alternatives Considered

### Fragments the daemon includes

service-forms.md's plan: `Include /run/config/bastion/sshd.conf`. No
renderer, and every daemon's whole syntax available. It makes the config
tar an author of the daemon's configuration: a destination and
`PermitOpen any` are the same kind of line. For a machine with sshd the
tar's writer already holds root's keys; for `prod`, with nothing
listening, they hold nothing, and a fragment would hand them the
service. The image's review would describe less than the machine.

### A renderer per service

Where `service-config` is. Exact, and each case can know its daemon. It
is a parser of untrusted input per service in every image, and a copy of
each on the host. With a dozen forms planned, the cost is the forms'
count times two.

### Templates

A file in the image with `{{ .destinations }}` in it, rendered by Go's
`text/template` or `envsubst`. Every daemon's syntax, with no format
list. A template language is an interpreter, which shell-free removes
from the machine ([shell-free.md](shell-free.md)); and escaping depends on
the daemon, so a template that is safe for sshd is unsafe for a JSON
file, and the template's author decides which.

### leash renders, as root

One program fewer. It parses the tar's JSON as root, which is the work
the privilege-separated programs exist to keep out of root
([programs.md](../programs.md)). Rendered after leash drops to the
service's user, in-process, it would run under the service's pledge,
which may not allow the writes.

### A path language for nested JSON

`as storage.raft.retry_join[].leader_api_addr` would serve clustered
OpenBao. Each such language grows until it is jq. Dotted keys into nested
objects, without lists, serve every form planned but two.

### More formats now: YAML, TOML, Java properties

Java applications read the environment: Spring Boot binds
`SPRING_DATASOURCE_URL`, and Quarkus and Micronaut do likewise. No form
planned reads YAML or TOML for a per-machine value. Each would be an
emitter with its own escaping, written for no form.

### Environment only

One format, and every application reads it. sshd and Tailscale do not.

### Defaults in the service file

`setting maxmemory int default 256`. Then a default is in two places,
the service file and the daemon's configuration, and the second one wins
or loses by include order. In the daemon's configuration it is where the
form's reviewer already reads.

## Security Considerations

- **Declarations come from the image; values from the tar.** The tar
  cannot name a key, a variable or a directive: it can only fill one the
  verified image declared, with a value of the declared type. Settings
  cannot widen policy, because policy is not a setting.
- **No value is quoted, because no value needs to be.** Each type's
  alphabet excludes the format's delimiters, and the pairs where it does
  not are refused at build. A newline in a `string` never reaches an
  `env` file; a space never reaches a `conf` value.
- **Parsed unprivileged.** The tar's JSON is parsed by the service's
  user, inside the service's Landlock rules, after root has copied it.
  The renderer has no network and no capability, and its input is 32 KiB
  at most.
- **One function per type, on both sides.** The host's check cannot
  drift from the guest's, because they are the same code; and the
  guest's check remains the one that is enforced.
- **Secrets never pass through.** A renderer that handles no secret has
  none to log or leak. `url` refuses a password so that one is not
  carried in a setting by habit.
- **`env` cannot reach the loader.** `PATH` and `LD_*` cannot be
  declared, and a declared name cannot shadow an `env` or `secret` line.
- **Theo would ask** why there is JSON at all, rather than lines of
  `KEY VALUE`. Lists and types are why, and Zig's parser is in its
  standard library, strict about duplicates and unknown fields. The
  parsing is unprivileged, bounded and the same on both sides, which is
  what matters more than the syntax.

## Reliability Considerations

- **No state.** Settings are rendered at every start from the tar, into
  a tmpfs. A machine's settings are what its tar says, every boot.
- **Fail closed, and say so.** A refused setting keeps its service down
  with one structured line, like a missing key. The host's `pack`
  refuses the same value first, so on a machine made with `howl` it
  is reached only by a hand-made tar.
- **Updates that change settings are caught by the update.** A setting
  renamed or retyped in a new image refuses an old tar; the new slot does
  not stay healthy, and slot-keep keeps the old one. The rule for forms
  is to add settings, never rename them.
- **Tested where it can break.** Per form, `make check` boots with
  settings and compares the rendered file, which is where include order
  and daemon syntax go wrong. Per type, a fuzz test, where the parser
  goes wrong.
- **An SRE would ask** what a user sees when a router comes up without
  routes. The service is up and the routes are absent, which is right
  for an optional setting. `service-config` should log what it rendered,
  one line per service with the names it set, so the difference between
  "none given" and "refused" is a line, not a guess.
