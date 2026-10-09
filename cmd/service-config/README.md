# service-config

## Summary

service-config writes one machine's settings into the file a service's
daemon reads: an sshd_config fragment, a JSON config, or environment
variables. It runs at each start of the service and refuses any value the
image did not declare.

## Background

A form's image is the same on every machine. What differs is in the config
tar: a router's routes, an application's database URL. The service file
declares what may be set (`setting NAME TYPE`) and how it is written out
(`render FORMAT FILE`). The machine's `settings.json` gives the values
(docs/design/settings.md, `lib/settings.zig`). Those values come from a
disk or a cloud's metadata server, outside the image, so they are the one
input here an attacker might write.

## Goals

- A value fills a key the image declared, with a value of its type. It
  cannot name a key, end a line, or quote.
- Every value is checked before anything is written.
- A refusal names the service, the setting and why, never the value.

## Non-Goals

- Knowing any service. It renders what is declared.
- Secrets. A setting is not secret; a secret is a `config` file.

## Detailed design

- **leash runs it** as `service-config /run/svc/NAME`, after it has dropped
  to the service's user and applied the service's Landlock rules.
  leash reads `settings.json` as root and writes a copy, `settings`, into
  that directory as the service's user. On stdin come the service file's
  `setting` and `render` lines, which leash has already checked with the
  same functions. service-config refuses to run as root.
- **It reads everything first**: the declarations, `settings`, and the
  image's `from` file for json. Then it installs a seccomp filter
  (`lib/sandbox.zig`) that allows only memory calls, `unlinkat`, `openat`,
  `writev`, `close`, `rt_sigaction` (Zig restores a handler at exit) and
  exit. Any other call kills it. Only then does it parse settings.json.
- **Types** use alphabets that cannot hold a format's delimiters: ip,
  cidr, addrport, hostport, hostname, port, url, int, bool, string. conf
  refuses string and url; env refuses lists of them; json output is
  serialized, not pasted. The limits are 32 settings, 32 values each, and
  32 KiB of input.
- **It writes** the render file anew, mode 0600, after unlinking the old
  name, so it never truncates an inode a link might share.
- **It logs** one JSON line: what was set, or the setting and why it was
  refused. An unknown key is named only if it is a well-formed setting
  name. If the line does not fit, a short line says so. leash parks the
  service on any refusal and points at this line.

## Drawbacks

- A refused setting keeps the service down until the config is fixed. A
  half-applied config would be worse.
- Types are coarse: a hostname is any RFC 1123 name, not one that resolves.

## Alternatives Considered

### Templates, as in cloud-init and confd
A template pastes text, so one value with a newline or a quote rewrites the
file. Here no value can hold those characters.

### Rendering in leash, as root
leash would then parse outside input before it drops privileges. Here the
parser runs as the service, under its own filter.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A value that injects a directive | Typed alphabets without the format's delimiters; conf takes no free text; json is re-serialized. |
| A key that is not declared | Refused; the setting must be in the image's service file. |
| A parser bug in the JSON reader | Runs as the service's user, in its Landlock rules, under a filter of ten calls. |
| A link planted in the service's directory | The directory is opened without following links; the file is made new with O_EXCL. |
| A value reaching a log | Never; an unknown key only if it is a well-formed name. |

## Reliability Considerations

- **All or nothing**: every value is checked before the file is replaced.
- **Always says why**: a refusal line, or a short one if the full one does
  not fit.
- **Tested**: `lib/settings.zig`'s tests cover types, formats, and the
  bastion's and tailscale's declarations; `check-tailscale` renders a
  router's route at boot.
