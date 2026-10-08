# service-config

## Summary

Writes one machine's settings into the file a service's daemon reads (an
sshd_config fragment, a JSON config, environment variables), at each start
of the service, and refuses any value that is not what the image declared.

## Background

A form's image is the same on every machine; what differs is in the config
tar: a router's routes, an application's database URL. The service file
declares what may be set (`setting NAME TYPE`) and how it is written out
(`render FORMAT FILE`). The machine's `settings.json` gives the values
(docs/design/settings.md, `lib/settings.zig`). Those values come from
outside the image, from a disk or a cloud's metadata server, so they are
the one input here an attacker might write.

## Goals

- A value fills a key the image declared, with a value of its type, and
  can do nothing else: not name a key, not end a line, not quote.
- Every value checked before anything is written.
- A refusal names the service, the setting and why, never the value.

## Non-Goals

- Knowing any service: it renders what is declared.
- Secrets: a setting is not secret; a secret is a `config` file.

## Detailed design

- **Run by leash**, after it has dropped to the service's user, inside the
  service's Landlock rules, with the service's `/run/svc/NAME` as its only
  argument. On stdin come the service file's `setting` and `render` lines,
  which leash has already checked with the same functions. In the
  directory is `settings`, the machine's settings.json, copied there by
  leash as the service's user. It refuses to run as root.
- **Reads everything first**: the declarations, `settings`, and the image's
  `from` file for json. Then it holds itself to what is left
  (`lib/sandbox.zig`): memory, `unlinkat`, `openat`, `writev`, `close`,
  `rt_sigaction` (Zig's exit puts back a handler) and exit. Any other call
  kills it. Only then is settings.json parsed.
- **Types**, each an alphabet that cannot hold a format's delimiters: ip,
  cidr, addrport, hostport, hostname, port, url, int, bool, string. conf
  refuses string and url; env refuses lists of them; json is serialized,
  not pasted. At most 32 settings, 32 values each, 32 KiB of input.
- **Writes** the render file new, 0600, in place of the old name: never
  truncating an inode a link might share.
- **Says** one JSON line: what was set, or the setting and why it was
  refused. An unknown key is named only if it could be a setting's name.
  A line too long to fit is replaced by one that says so. leash parks the
  service on any refusal, pointing at this line.

## Drawbacks

- A refused setting keeps the service down until the config is fixed: a
  half-applied config would be worse.
- Types are coarse: a hostname is any RFC 1123 name, not one that resolves.

## Alternatives Considered

### Templates, as cloud-init and confd have
A template pastes text; one value with a newline or a quote rewrites the
file. Here no value can hold the characters that would.

### Rendering in leash, as root
leash would parse outside input before it drops privileges. Here the
parser runs as the service, under a filter of its own.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A value that injects a directive | Typed alphabets without the format's delimiters; conf takes no free text; json is re-serialized. |
| A key that is not declared | Refused; the setting must be in the image's service file. |
| A parser bug in the JSON reader | Run as the service's user, in its Landlock rules, under a filter of ten calls. |
| A link planted in the service's directory | The directory is opened without following links; the file is made new with O_EXCL. |
| A value reaching a log | Never; an unknown key only if it is a well-formed name. |

## Reliability Considerations

- **All or nothing**: every value is checked before the file is replaced.
- **Always says why**: a refusal line, or a short one if the full one will
  not fit.
- **Tested**: `lib/settings.zig`'s tests (types, formats, the bastion's and
  tailscale's declarations); `check-tailscale` renders a router's route
  at boot.
