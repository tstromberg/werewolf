# OpenCanary - Hardened VM

A low-interaction honeypot: [OpenCanary](https://opencanary.org/) from its project's image. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/opencanary/index.html).

## Security Posture

- The service runs as its image's user. It may bind the bait ports and reach nothing.
- The config is written at each start. SMB, scanners, HTTPS and anything that would read this host's logs are off.
- A login the bait accepts is a log line. It is not an account, and it does not open a shell.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create opencanary --with opencanary
```

Events are on the console and in `/data/svc/opencanary/opencanary.log`. The listeners are FTP :21, SSH :22, Telnet :23, HTTP :80, RDP :3389 and VNC :5900. What a service pretends to be is in [OpenCanary's documentation](https://opencanary.readthedocs.io/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create opencanary --with opencanary --on gcp --allow-from me
```

Point a name at it that an attacker might try. Do not put anything else on this machine. The events are the point.

### Importing data

There is nothing to import. Events from this machine are the log on `/data`.

### Known Quirks

- The image's own launcher is a shell. This form runs Python on twistd instead.
- The config is not yours to edit in place. A change is a change to the form.
- Telnet's listed passwords are bait. They do not log in to werewolf.

### Network Exposure

- listen: tcp/21 tcp/22 tcp/23 tcp/80 tcp/3389 tcp/5900 *
- connect: none
