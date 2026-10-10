# Syncthing

The `syncthing` form keeps folders in sync between your devices, peer to
peer: [Syncthing](https://syncthing.net) 2.1, from its project's own
image, with Caddy in front of its web GUI, each on a leash of its own
([design/self-hosting.md](../../docs/design/self-hosting.md)).

| | |
| --- | --- |
| Listens | :22000, TCP and QUIC, Syncthing's TLS, for your devices; :80 and :443, Caddy, for the GUI |
| Sends | to your devices on :22000; to Syncthing's global discovery servers, relays and STUN servers, at public addresses |
| Runs as | `_oci-syncthing` and `caddy`, each a uid of its own, leashed |
| Keeps | the device key, config, database and folders in `/data/svc/syncthing/var/syncthing` |
| Config | `caddy/gui-password` (12 to 72 bytes); settings `gui-user` (required), `base-url`, `relays` and `global-discovery` (both on unless false) |

## Run your own

```sh
openssl rand -base64 24 >gui-password      # you sign in with it; keep it
howl create sync --with syncthing --base-url https://sync.example.com \
	--gui-user alice --gui-password gui-password
```

Sign in at `https://sync.example.com` as `alice`, add your other devices
by their IDs, and share folders; new folders go under `/var/syncthing`,
which is on `/data`. Without `--base-url`, Caddy serves the GUI over plain
HTTP on :80, for a LAN or a tailnet only: the password crosses the wire.

## How the parts are held

- **One user at the GUI.** Syncthing's GUI and API run the device:
  whoever reaches them can share any folder with anyone. The GUI listens
  on loopback alone (`STGUIADDRESS`, whatever its config says), and Caddy
  lets in the config's user alone, by a bcrypt hash syncthing-auth writes
  before each start ([cmd/syncthing-auth](cmd/syncthing-auth/syncthing-auth.zig)).
  Syncthing's own host check stays on, against DNS rebinding.
- **Its project's image.** Syncthing runs from
  `docker.io/syncthing/syncthing:2`, its latest 2.x release, pinned by
  digest when built and baked in at `/oci/syncthing`
  ([docs/design/oci.md](../../docs/design/oci.md)). Its entrypoint, a
  shell script, never runs: the form starts `/bin/syncthing` itself.
- **Options held at each start.** Before Syncthing starts,
  syncthing-setup makes its device key and config once, with Syncthing's
  own `generate`, then sets what the form decides and leaves the rest
  (devices, folders, the GUI's choices) as Syncthing keeps them
  ([cmd/syncthing-setup](cmd/syncthing-setup/syncthing-setup.zig)).
- **Nothing phones home.** It never upgrades itself (`STNOUPGRADE`); it
  runs without its monitor process, which restarted it and uploaded
  crash reports, so runsv restarts it and nothing is uploaded. Usage
  reports are declined.
- **No router ports opened.** UPnP and NAT-PMP are off: they would ask
  the router to forward its ports to the machine.
- **Found across NAT.** Global discovery and relays stay on, as
  Syncthing ships them: they are how two devices behind routers find
  each other. `--relays false` and `--global-discovery false` turn them
  off, for a LAN or a tailnet alone; the setup holds them at each start.
- **No local discovery.** It broadcasts on the LAN, which fence neither
  sends nor delivers. Add a device on your LAN by its address,
  `tcp://ADDRESS:22000`.

## Checked

`make check-syncthing` runs [test/checks](test/checks): Syncthing runs as
`_oci-syncthing`, alone in its cgroup, with no capabilities; it keeps its
device key on `/data`; syncthing-setup held its options, global discovery
off as the check's settings say; its GUI is bound to loopback; through
Caddy, the config's user reaches the GUI and API, and plain HTTP is sent
to HTTPS; syncthing-auth kept a hash and removed the password's copy;
and, the attack, the GUI and API without the password, or with a wrong
one, are refused. Booted as it ships with no config, Caddy parks and
says why, while Syncthing makes its key and runs, reachable by nothing
([test/console](test/console)).
