# Galène - Hardened VM

Videoconference for lectures and seminars: [Galène](https://galene.org) 1.2, with Caddy in front. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/galene/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names. The root is read-only. `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >operator-password
openssl rand -base64 12 >password
howl create galene --with galene \
	--base-url https://meet.home.arpa --groups cs101 \
	--operator ada --operator-password operator-password --password password
```

Open `https://meet.home.arpa/group/cs101/`. The operator password is in `operator-password`; everyone else uses `password`. UDP port 10000 must reach the machine. Rooms and keys are in [Galène's documentation](https://galene.org/galene.html).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >operator-password
openssl rand -base64 12 >password
howl create galene --with galene --on gcp --allow-from me \
	--base-url https://meet.example.edu --groups cs101 --groups seminar \
	--operator ada --operator-password operator-password --password password
```

Point the name at the machine and open `https://meet.example.edu/group/cs101/`. Also open UDP 10000. Omit `--password` and the operator is alone until they invite someone. `--recording true` writes to `/data/svc/galene/recordings`. Students whose network blocks UDP need `--ice-servers` pointing at a TURN server you run elsewhere.

### Importing data

Rooms and keys are in the create command or `--config`. There is no database to import.

### Known Quirks

- Passwords are stored as bcrypt. The files you passed are not kept.
- Rooms are unlisted: `/public-groups.json` is empty.
- A group name is letters, digits, `.`, `-` and `_`.
- There is no built-in TURN server.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
- listen: udp/10000 *
