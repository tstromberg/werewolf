# Galène

Videoconference for lectures and seminars: [Galène](https://galene.org) 1.2, with Caddy in front.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >operator-password
openssl rand -base64 9 >password
howl create lectures --with galene --on lima \
	--base-url https://meet.home.arpa --groups cs101 \
	--operator ada --operator-password operator-password --password password
```

Open `https://meet.home.arpa/group/cs101/`. UDP port 10000 must reach the machine, beside 80 and 443.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >operator-password
openssl rand -base64 9 >password
howl create lectures --with galene --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://meet.example.edu --groups cs101 --groups seminar \
	--operator ada --operator-password operator-password --password password
```

Point the name at the machine and open UDP 10000. The operator presents, mutes and locks. Everyone else joins with the shared password. Omit `--password` and the operator is alone until they invite someone. `--recording true` writes to `/data/svc/galene/recordings`. Students whose network blocks UDP need `--ice-servers` pointing at a TURN server you run elsewhere.

Run the same create line again to change rooms or passwords. Groups not named are removed.

### Known Quirks

- Passwords are stored as bcrypt. The files you passed are not kept.
- Rooms are unlisted: `/public-groups.json` is empty.
- A group name is letters, digits, `.`, `-` and `_`.
- There is no built-in TURN server.

### Network Exposure

- tcp/80 and tcp/443, Caddy. udp/10000, Galène, for the media.
