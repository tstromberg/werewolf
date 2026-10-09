# Vaultwarden

The `vaultwarden` form is `prod` with Vaultwarden 1.37, a server for the
Bitwarden password manager's apps, and its web vault.

| | |
| --- | --- |
| Listens | tcp/8080, behind `caddy`, whose TLS the apps require |
| Sends | nothing: no icons fetched, no push relay, no mail, no breach lookups |
| Runs as | `vaultwarden` (a uid of its own, its name's hash), leashed |
| Keeps | the vault, SQLite in WAL mode, and attachments in `/data/svc/vaultwarden` |
| Config | `vaultwarden/admin-token`, an Argon2id PHC string (`vaultwarden hash`, or as [forms/vaultwarden/test/config](test/config) makes one); setting `domain` (the site's https URL, required) |

```sh
build/host/howl pack --with vaultwarden -o config.tar --config config --domain https://vault.example.com
```

## Built by melange, until Wolfi ships it

Wolfi does not ship Vaultwarden yet, so [forms/vaultwarden/melange/vaultwarden.yaml](melange/vaultwarden.yaml)
is a melange recipe in Wolfi's style: release 1.37.4 and the 2026.7.0 web
vault, each checked by sha256, built in Wolfi's environment with Wolfi's
Rust, linked to Wolfi's OpenSSL 4 and SQLite, mimalloc's secure mode
(guard pages, encrypted free lists) compiled in, and its crates recorded
in the binary by cargo-auditable for scanners. [forms/vaultwarden/form.yaml](form.yaml) names it,
[melange.mk](../../melange.mk) unpacks the package over the image,
and checks that every library it
links is one of the form's packages, so Wolfi's fixes to those reach the
machine through its updater; a new Vaultwarden is a new pin and a new
image. The same recipe is meant for wolfi-dev/os, after which the form
names the package and the recipe goes.

melange builds on Linux with bubblewrap. On macOS it uses its QEMU
runner, booted from werewolf's own Alpine kernel and a guest from
`melange initramfs` with the kernel's modules under `/usr/lib/modules`
(melange's own `QEMU_KERNEL_MODULES` writes them under `/lib`, which
replaces the guest's `/lib` link and breaks its loader). A first build
takes about five minutes; the package is kept in `build/vendor`, and
`howl build-apk forms/vaultwarden/melange/vaultwarden.yaml` builds it alone.

## Defaults

- **Nobody signs up.** The admin, with the config's token, invites each
  user from `/admin`; without mail, the invited address registers in the
  apps directly. Password hints are neither kept nor shown.
- **Nothing leaves the machine.** Icons are not downloaded (each would be
  a request to a site a user saved, made on their behalf), and the policy
  declares no outbound port at all, so fence would refuse one anyway.
- **The configuration is the image's.** The admin page cannot save
  settings (`CONFIG_FILE` points at a file the read-only image does not
  have), so enabling sign-ups, say, is a new image, not a click.
- Client addresses from caddy's `X-Forwarded-For`; Vaultwarden's own login
  and admin rate limits as it ships them.

Mail (invitations, two-factor by email, new-device notices) is a form of
your own with `connect vaultwarden tcp/587` and the `SMTP_*` settings.

## Checked

`make check-vaultwarden` runs [forms/vaultwarden/test/checks](test/checks):
the web vault is served; a stranger cannot start a sign-up; a wrong admin
token gets no session; the admin invites a user, who registers, logs in,
stores an item and finds it in a sync; a wrong master password is
refused; the token and database are `vaultwarden`'s, and no admin config
was written.
