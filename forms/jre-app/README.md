# jre-app

A Java service for a jar you supply. It runs `java -jar app.jar` on port 8080, the port a Spring Boot or Quarkus jar uses by default. Nothing is shipped with it. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- Java runs the jar, and the JVM compiles it as it runs. Both are named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p myapp
cp forms/jre-app/example/app.jar myapp/app.jar
howl create jre-app --with jre-app --app ./myapp
```

Open `http://ADDRESS:8080`, the address howl prints. The jar in `forms/jre-app/example` answers `ok`. Replace `myapp/app.jar` with your own. Howl refuses an empty directory. What your jar serves is the application's own documentation.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p myapp
cp forms/jre-app/example/app.jar myapp/app.jar
howl create jre-app --with jre-app --on gcp --allow-from me --app ./myapp
```

The jar speaks plain HTTP on port 8080. Put Caddy, or the load balancer you already run, in front of it. The heap is 640 MiB, inside a 1 GiB limit. When the heap runs out the process exits and leash starts it again.

### Migrating data in

The application is in the image. What it must remember is in the create command or `--config`. There is no database to import unless the application brings its own.

### Known Quirks

- There is no shell. A jar that tries to run a script fails.
- Temporary files go in the service's own directory, not a shared `/tmp`.
- A form of your own can build on `jre-app` and lay the jar in the image instead of passing `--app`.

### Network Exposure

- tcp/8080, the application, for the networks you allow.
