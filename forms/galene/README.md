# Galène

Videoconference for lectures and seminars: [Galène](https://galene.org) 1.2, with Caddy in front. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

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

### Migrating data in

Rooms and keys are in the create command or `--config`. There is no database to import.

### Known Quirks

- Passwords are stored as bcrypt. The files you passed are not kept.
- Rooms are unlisted: `/public-groups.json` is empty.
- A group name is letters, digits, `.`, `-` and `_`.
- There is no built-in TURN server.

### Network Exposure

- tcp/80 and tcp/443, Caddy. udp/10000, Galène, for the media.
