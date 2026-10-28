# Plex - Hardened VM

[Plex Media Server](https://www.plex.tv/media-server-downloads/), behind Caddy, with
a separate transcoder, callback proxy and media owner. The [manifest](form.yaml)
defines the boundaries. [Image
availability](../../docs/forms-catalog.md#images-and-downloads).

This form is experimental. The broker and callback boundary are under review.
Normal account registration and playback through the confined VM have not yet
been validated. Live account testing is deferred; the automated fixture does
not require a Plex account.

## Security Posture

- Plex, the transcoder, the media owner and Caddy have different users.
- Plex reads media and owns its database. The transcoder reads media and
  writes only scratch output. It has no DNS or direct account-token access.
  Its only TCP destination is a loopback proxy accepting transcode callbacks.
- Vendor binaries and pinned codecs live in the verified, read-only image.
  Writable storage is never executable. No JIT allowance is needed.
- Plex may resolve `plex.tv` and its subdomains and connect to public HTTPS.
  It cannot connect to its own port. Caddy is its only network ingress.
- Discovery, DLNA, UPnP, relay, legacy Python plugins and GPU access are off.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

Save your existing Plex account's authentication token as `plex-token`, mode 0600.
See [Plex's token
instructions](https://support.plex.tv/articles/204059436-finding-an-authentication-token-x-plex-token/).
A short-lived `claim-` code is not an account token.

```sh
howl create plex --with plex --domain plex.example.com --plex-token ./plex-token
```

Open `https://plex.example.com/web` and sign in with that Plex account.
Use your real DNS name and point it at the VM. The server advertises this
HTTPS address; its internal port 32400 is not public.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create plex --with plex --on gcp --allow-from me \
  --domain plex.example.com --plex-token ./plex-token
```

Account and metadata requests use public HTTPS. DNS is granted to `plex.tv`
and `*.plex.tv`. The observed `api.plex.tv` CNAME outside that domain is also
granted explicitly; other external aliases require their own grants.
DNS grants do not restrict HTTPS connections to those hosts.

### Importing data

At creation, attach your media directory as the read-only import disk:

```text
howl create plex --with plex --domain plex.example.com \
  --plex-token ./plex-token --import ./media
```

Add `/data/svc/plex-media` as a library in Plex. The importer alone owns these files.
Init requires an empty destination. A later `howl sync NAME ./media` adds and
replaces changed files while preserving destination-only files. Staging works while
the VM runs; the selected snapshot is applied after a full stop/start through Howl. A
guest reboot alone does not switch the attached import disk. Completed snapshots are
not reapplied across starts and updates. See the [data import
design](../../docs/design/pending/data-import.md) for recovery semantics. Do not
import an old writable codec or plugin directory.

### Known Quirks

- Software transcoding only, one transcoder job at a time.
- The pinned codecs cover H.264 encoding/decoding, HEVC decoding, AAC and MP3.
- Legacy Python agents, custom plugins, DVR and commercial skipping are absent.
- The vendor package and Caddy currently build from the sibling `packages` checkout.
- Setup preserves existing Plex preferences. Changing the supplied token or
  domain does not automatically rewrite those preferences.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
- connect: tcp/443 public

## Review and validation

`plex-transcode` is the transcoder socket client/worker. Its peers are checked
by kernel UID; only the worker executes the fixed vendor transcoder, with a fixed
environment. It does not select a program, inherit caller environment variables
or run as root. Preferences setup and media readiness are separate programs,
`plex-setup` and `plex-media`.

The callback proxy is Caddy under its own UID. It holds the configured account
token, accepts only PUTs to progress and manifest paths, and reconstructs the
matched upstream path. The worker cannot connect directly to port 32400. The
loopback adapter changes Plex's bind address; the firewall independently prevents
external access to its internal ports.

The form selects the private `musl-werewolf` runtime from
[`packages/devel/musl`](https://github.com/werewolf-linux/packages/blob/main/devel/musl/README.md),
retaining Plex's musl ABI. It includes the upstream regex overflow fix and binds DNS
sockets to loopback when all IPv4 resolvers are local. The package builds and runs
resolver probes for successful answers, NXDOMAIN, nonlocal resolvers and mixed lists.
The adapter also binds application UDP sockets locally, including implicit binds on
send/connect. Discovery remains disabled by configuration and firewall policy; the
adapter is a compatibility measure, not the security boundary.

Run `make check-native-tests-plex` for VM startup, TLS, service identity, actual
H.264 decoding/encoding, output readability across UIDs, authentication checks and
denied file/network/output checks. The suite checks that Plex accepts the configured
fixture token for preference reads and rejects anonymous requests. This deliberately
invalid account token cannot create a library, so the suite does **not** prove
account registration, library management, metadata fetching or client playback. Those
need a real account test, deferred for now. The exploratory namespace playback
fixture is compatibility evidence only. Data transfer uses `howl export` and
`howl import`; `--service plex` selects server state, while `--service plex-media`
selects media. The archive does not expand dependencies. See
[data storage](../../docs/data.md) for current support and
[application transfer
tests](../../docs/design/pending/data-import-application.md) for
the remaining release gate.
Production IPE/verified-boot client
playback remains unvalidated. Native VM checks exclude Secure Boot and TPM; IPE can
be exercised with `IPE=1` and the signed kernel inputs described in the testing
guide. Protected transfer startup must separately pass all three protections.
