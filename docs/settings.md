# Service settings

## Syntax

*Settings* are values that differ per machine but are not secret: a router's
routes, a database URL. A service file declares each with a type and says
where the values go ([design](design/settings.md)):

```text
config  settings /run/config/tailscale/settings.json
setting routes cidr... as advertiseRoutes
render  json config.json from /etc/tailscale/config.json
```

`config settings` names the file in the boot config, `{"routes":
["10.20.0.0/24"]}`, which may be missing. `setting NAME TYPE[...] [required]
[as KEY]` declares one, up to 32 a service: NAME is its key in the JSON and
`howl pack`'s `--NAME`; KEY names it in the output, by default NAME (for
`env`, upper case with `_`). A list (`TYPE...`) holds up to 32 values.

| Type | Accepts |
| --- | --- |
| `ip`, `cidr`, `addrport`, `hostport` | a literal address; a network with no host bits; address and port; hostname or address and port |
| `hostname`, `port`, `url` | RFC 1123, at most 253 bytes; 1 to 65535; `http` or `https` without credentials, at most 2 KiB |
| `int`, `bool`, `string` | a signed 64-bit number; `true` or `false`; UTF-8 without control characters, at most 1 KiB |

At each start leash runs `service-config` as the service, which checks every
value against its type and writes `/run/svc/SERVICE/FILE` in the `render
FORMAT FILE` format: `env` (`KEY=VALUE` lines leash adds to the environment;
no lists of `string` or `url`, no `PATH` or `LD_*`), `json` (one object,
`from PATH` merged into a file from the image, dotted keys nested) or `conf`
(`KEY VALUE...` lines; no `string` or `url`). A refused pair does not build.
A setting not given is left out, so the daemon's default holds; `required`
keeps the service down instead, as does an undeclared key or a value of the
wrong type, with one line naming it.
