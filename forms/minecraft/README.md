# Minecraft - Hardened VM

A [Minecraft](https://www.minecraft.net/en-us/download/server) Java server: 26.3, with the people you name on the whitelist. The form's manifest is [form.yaml](form.yaml).

## Security Posture

- The service runs as its own user, held to the files and the one port its manifest names. The root is read-only. The world is on `/data`.
- The whitelist is on. A name that is not an account is refused before the server starts.
- Online mode is on. A login is checked with Mojang.
- There is no RCON and no query port.

### Weaknesses

- Java runs the server, and the JVM compiles it as it runs. Both are named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create minecraft --with minecraft --players steve
```

Add a server at the machine's address, port 25565. `steve` is on the whitelist. Anyone else is refused at login. Worlds, operators and the rest are in [the server documentation](https://minecraft.wiki/w/Server).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create minecraft --with minecraft --on gcp --allow-from me \
	--players steve --players alex
```

Open TCP 25565 to the people who play. The whitelist is those names.

### Importing data

The world is the directory the server keeps under `/data/svc/minecraft`. A new machine starts a new one.

### Known Quirks

- The server is Minecraft 26.3, pinned in the image. Nothing here notices when Mojang publishes a newer one.
- It runs on the `jre` form's Java 27.
- Starting it agrees to [Mojang's EULA](https://www.minecraft.net/en-us/eula). The form sets `eula=true` so it will start.
- Each name is resolved with Mojang at start, and the whitelist is rewritten from the config.
- View distance is 5. There is no RCON and no query port.

### Network Exposure

- listen: tcp/25565 *
- connect: tcp/443 *
- connect: tcp/53 *
- connect: udp/53 *
