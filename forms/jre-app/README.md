# jre-app

A Java service for a jar you supply. It runs `java -jar app.jar` on port 8080, the port a Spring Boot or Quarkus jar uses by default. Nothing is shipped with it.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create app --with jre-app --on lima --app ./myapp
```

`./myapp` must contain `app.jar`. Until it does, the service stays down and the console says why.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create app --with jre-app --on gcp --allow-from 10.0.0.0/8 --app ./myapp
```

The jar speaks plain HTTP. Put Caddy, or the load balancer you already run, in front of it. The heap is 640 MiB, inside a 1 GiB limit. When the heap runs out the process exits and leash starts it again.

### Known Quirks

- There is no shell. A jar that tries to run a script fails.
- Temporary files go in the service's own directory, not a shared `/tmp`.
- A form of your own can build on `jre-app` and lay the jar in the image instead of passing `--app`.

### Network Exposure

- tcp/8080, the application, for the networks you allow.

### Security Weaknesses

- Java runs the jar, and the JVM compiles it as it runs. Both are named in `form.yaml`.
