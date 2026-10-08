# Mosquitto

The `mosquitto` form is `prod` with Mosquitto 2.1, an MQTT broker for the
devices and automations on a network.

| | |
| --- | --- |
| Listens | tcp/8883, MQTT over TLS, 1.2 at least |
| Sends | nothing: no bridges |
| Runs as | `mosquitto` (uid 215), leashed |
| Keeps | retained messages, subscriptions and queues in `/data/svc/mosquitto` |
| Config | `mosquitto/tls.crt` and `tls.key`; `mosquitto/passwords` (as `mosquitto_passwd` writes it); `mosquitto/acls` (Mosquitto's ACL file: who may publish and subscribe to what) |

```text
user sensor
topic write home/sensor/#
user automation
topic readwrite home/#
```

Nothing anonymous, nothing plain: a listener on 1883 for a LAN that must
have one is two lines in a form of your own. `$SYS` topics are off; a
device that floods is held by the limits, not the broker.

## Checked

`make check-mosquitto` makes a certificate and two users
([test/config-mosquitto](../test/config-mosquitto)) and runs
[test/checks-mosquitto](../test/checks-mosquitto) with Mosquitto's own
clients, which the DEV build carries (`forms/mosquitto.dev`): a message
goes round over TLS; anonymous, a wrong password and plain MQTT are
refused; a user hears nothing from topics outside its ACL and cannot
publish into another's; keys and passwords are the broker's, 0600.
