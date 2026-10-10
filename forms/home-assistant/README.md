# home-assistant

The `home-assistant` form is `prod` with Home Assistant, for a home's
devices and automations, behind Caddy, which serves it over HTTPS for
your domain. It runs Home Assistant's own image, the `stable` release,
pinned by digest at each build, with every integration's Python packages
already in it.

| | |
| --- | --- |
| Listens | tcp/80 and tcp/443, Caddy's; Home Assistant on loopback alone |
| Sends | HTTPS, HTTP and DNS anywhere; to devices, the ports their integrations use (below) |
| Runs as | `_oci-home-assistant` in Home Assistant's image, and `caddy`, each leashed |
| Keeps | its configuration, history, backups and logins in `/data/svc/home-assistant` |
| Config | `home-assistant/owner-password` (12 to 72 bytes); settings `owner` (required), `domain`, `time-zone`, `latitude`, `longitude`, `country`, `unit-system` (`metric` or `us_customary`) |

## Run your own

```sh
printf %s 'a long owner password' >owner-password
howl create home --with home-assistant --domain home.home.arpa --owner me \
	--owner-password owner-password --time-zone Europe/Berlin --country DE
```

Names under `.home.arpa`, `.local` and `.internal` get a certificate from
Caddy's own CA, for a home network; a public name gets one from Let's
Encrypt. Without `--domain`, Caddy serves plain HTTP on `:80`.

## Defaults

- **No onboarding.** home-assistant-setup makes the owner, an
  administrator, from the config before Home Assistant first starts, and
  marks every onboarding step done, so a new machine is never claimed by
  the first visitor. The location comes from the settings, and later from
  Settings → System → General.
- **The owner's password is the config's.** At each start the owner's
  login is set back to it if it changed: change it in the config, and a
  forgotten one is reset the same way.
- **Analytics off**, as onboarding leaves them when nobody opts in.
- **Banned after five failed logins**, by address, which Caddy reports.
- **`default_config`, less what cannot work here:** discovery (DHCP,
  SSDP, zeroconf) needs multicast, and Bluetooth and USB need devices,
  which werewolf does not pass to a machine yet; go2rtc would start a
  program of its own. Add devices by address in the UI instead.
- **configuration.yaml is the image's**, rewritten at each start; what
  you set up in the UI is kept in `.storage`, on `/data`.
- **Only Python runs**: the image's entrypoint is s6-overlay's shell
  scripts, so leash runs `python3 -m homeassistant` itself, and nothing
  else in the image, its shell included, can run.

## Devices

fence lets Home Assistant reach a device only by a port its service
declares: 80 and 443, MQTT (1883, 8883), ESPHome (6053), Matter (5580),
Z-Wave JS (3000), Cast (8008, 8009), Sonos (1400), and 8080, 8443, 8096
and 32400 (Kodi, UniFi, Jellyfin, Plex). Another integration's port is a
form of your own that names the service again with it.

For Zigbee, run Zigbee2MQTT where the radio is, and the `mosquitto` form
as the broker; Home Assistant's MQTT integration reaches it on 8883.

## Drawbacks

- Integrations Home Assistant ships work: their packages are in the
  image. A custom integration (HACS) whose packages are not cannot
  install them, since the image is read-only; one with none works, from
  `/data`.
- The image is 2.3 GB, so a build and an update take a while.
- HomeKit, which pairs by mDNS and serves on ports of its own choosing,
  waits on multicast.

## Checked

`make check-home-assistant` boots it with its test config
([test/config](test/config)), domain `localhost`, for which Caddy's own
CA signs: onboarding is done and Home Assistant listens on loopback
alone; the API refuses a request without a token; the owner logs in with
the config's password and gets a token the API takes, and finds the
settings' location and no discovery; a wrong password is refused; the
logins are the service's alone, and leash's copy of the password is
gone. The attack: a visitor posts an owner to onboarding, as the first
to reach a new Home Assistant would, and is refused.
`make check-shellfree-home-assistant` boots it as it ships, with no
config: Home Assistant parks, saying why.
