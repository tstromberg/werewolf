# Available forms

A **form** defines the software and permissions of a Werewolf VM. Choose one
below and follow its setup guide for configuration, credentials and how to
connect. Names link to a guide where one exists, or to the manifest for a
building block or example.

For your own application, start with the [language tutorials](../examples/README.md).
The `-app` forms need your code supplied through `--app`; the `-example` forms
include a sample application. Runtime forms such as `python` supply the
interpreter and leave the service definition to you.

## Get started

Browse and inspect forms from the command line:

```sh
howl forms                       # this checkout, or the signed catalog outside it
howl forms database              # search names and descriptions
howl forms caddy                 # setup guide, architectures and commands
howl forms --published --arch arm64  # published image inventory for one architecture
howl test --with caddy            # integration and production-variant boot checks
```

Follow the [installation steps](../README.md#try-it), then try the Node.js
sample locally from the checkout:

```sh
howl run --build --with node-example
```

For a service, open its guide below first: many need credentials or certificates
before they start. `howl pack --build --with FORM -h` lists that form’s
configuration flags. Replace `FORM` with its name.

`--build` uses this checkout. Secure deployment is the default; using a
prebuilt download requires a published protected image for the selected form,
host and architecture. See the [host support table](../README.md#secure-boot)
and [howl guide](../cmd/howl/README.md) for deployment options.

## Images and downloads

Browse the [image catalog](https://dist.werewolf-linux.org/images/v1/index.html)
or use `howl forms --published`. Each form has a page with arm64 and x86_64
downloads, package release notes, signatures, test evidence and the latest attempt's status. A failed
test or build keeps the previous passing image. Unsupported architectures are
listed explicitly: Overleaf's upstream image currently supports x86_64 only.

The [form-image workflow](../.github/workflows/form-images.yml) discovers every
form, resolves package and OCI versions, builds each changed target independently
twice, and requires matching bytes and passing tests on that architecture.
See [verification and deployment instructions](releases.md#form-image-catalog).
Publishing a `NAME-form` APK package is separate from publishing a boot disk.

Catalog disks use signed UEFI boot, IPE and signed complete-slot updates. They
require firmware enrollment and boot configuration. Custom application forms
still need your code and a corresponding signed update channel.

`howl run` and `howl create` also require TPM enrollment in their protected mode.
Their prebuilt downloads currently cover `playground` on x86_64 QEMU and arm64
Lima; the [protected download guide](releases.md#downloading-a-protected-qcow2)
describes that separate path. A catalog qcow2 does not satisfy its lifecycle
gates or create owner keys and a host permit service. For other forms, use
`howl run --build --with FORM` from the checkout and follow its setup guide.

## Alphabetical list

| Form | Use it for |
| --- | --- |
| [adguard-home](../forms/adguard-home/README.md) | DNS filtering for a home network, with a web interface behind Caddy. |
| [app](../forms/app/form.yaml) | A starting point for your own application; provides an application directory, with no runtime or application service. |
| [aspnet-example](../examples/aspnet/README.md) | A sample ASP.NET Core web application, with a tutorial. |
| [authelia](../forms/authelia/README.md) | Shared sign-in for your websites, with passwords and TOTP or security keys. |
| [bastion](../forms/bastion/README.md) | SSH forwarding to explicitly allowed destinations, using security keys; no interactive shell or file transfer. |
| [blocky](../forms/blocky/README.md) | DNS filtering for ads and trackers, with upstream DNS over TLS and no web interface. |
| [bloodhound](../forms/bloodhound/README.md) | BloodHound CE for exploring Active Directory relationships. |
| [bugsink](../forms/bugsink/README.md) | Error tracking compatible with Sentry SDKs. |
| [caddy](../forms/caddy/README.md) | A web server with automatic HTTPS. Supply your site and Caddyfile. |
| [cloudflared](../forms/cloudflared/README.md) | Cloudflare Tunnel to publish services without opening inbound ports. |
| [continuwuity](../forms/continuwuity/README.md) | A Matrix homeserver with federation and closed registration. |
| [cron](../forms/cron/README.md) | Scheduled jobs using supercronic. Supply a crontab with the programs to run. |
| [demo](../forms/demo/README.md) | A status page showing the VM’s uptime, patches and vulnerability findings. |
| [dependency-track](../forms/dependency-track/README.md) | Software bill of materials analysis, with a web UI and API. |
| [galene](../forms/galene/README.md) | Galène videoconferencing for lectures and seminars. |
| [gatus](../forms/gatus/README.md) | A status page that monitors a service. Add authentication before exposing it publicly. |
| [gitea](../forms/gitea/README.md) | Git hosting over HTTP and SSH, with custom hooks and Actions disabled. |
| [go-example](../examples/go/README.md) | A sample compiled Go web application, with a tutorial. |
| [grafana](../forms/grafana/README.md) | Dashboards and alerts, with the web interface behind Caddy. |
| [greenbone](../forms/greenbone/README.md) | Vulnerability scanning and management with Greenbone’s community feed. |
| [haproxy](../forms/haproxy/README.md) | HTTP load balancing across backends you configure; HTTPS when you supply a certificate. |
| [headscale](../forms/headscale/README.md) | A self-hosted coordination server for Tailscale clients. |
| [home-assistant](../forms/home-assistant/README.md) | Home automation, with the owner account supplied through boot configuration. |
| [immich](../forms/immich/README.md) | A photo and video library for browsers and phone apps. |
| [iris](../forms/iris/README.md) | DFIR-IRIS incident response case management. |
| [jellyfin](../forms/jellyfin/README.md) | Media streaming behind HTTPS, with media copied in over SSH. |
| [jre](../forms/jre/form.yaml) | A Java 27 runtime for your own service; no application service included. |
| [jre-app](../forms/jre-app/README.md) | Run your own `app.jar` on port 8080 using Java 27; supply it with `--app`. |
| [jre-example](../forms/jre-example/form.yaml) | A sample Java web application using the JDK’s HTTP server. |
| [jre21](../forms/jre21/form.yaml) | A Java 21 runtime for applications that require it; no application service included. |
| [kafka](../forms/kafka/README.md) | An Apache Kafka event stream on one KRaft node, with TLS, SCRAM authentication and ACLs. |
| [keycloak](../forms/keycloak/README.md) | Single sign-on through OpenID Connect and SAML. |
| [limesurvey](../forms/limesurvey/README.md) | Surveys and research data, stored in MariaDB. |
| [loki](../forms/loki/README.md) | Log storage and queries over HTTPS, with authentication through Caddy. |
| [mariadb-local](../forms/mariadb-local/README.md) | MariaDB for services in the same VM, accessed through a UNIX socket. |
| [mariadb-tcp](../forms/mariadb-tcp/README.md) | MariaDB for network clients on TCP port 3306. Configure database accounts for remote access. |
| [mastodon](../forms/mastodon/README.md) | A federated social server. |
| [mattermost](../forms/mattermost/README.md) | Team chat with Mattermost Team Edition. |
| [mediawiki](../forms/mediawiki/README.md) | A wiki backed by SQLite. |
| [minecraft](../forms/minecraft/README.md) | A Minecraft Java Edition server with online mode and a player whitelist; no RCON or query port. |
| [miniflux](../forms/miniflux/README.md) | An RSS and Atom feed reader. |
| [minimal](../forms/minimal/form.yaml) | A minimal VM that boots, supports slot updates and listens on no network ports. |
| [minio](../forms/minio/README.md) | S3-compatible object storage backed by the VM’s data disk. |
| [misp](../forms/misp/README.md) | Threat intelligence sharing and management with MISP core. |
| [mongodb](../forms/mongodb/README.md) | MongoDB for declared clients in the same VM, on loopback port 27017; database authentication is disabled. |
| [moodle](../forms/moodle/README.md) | Courses and learning management for schools and universities. |
| [mosquitto](../forms/mosquitto/README.md) | An MQTT broker over TLS, with configured users and access rules. |
| [mox](../forms/mox/README.md) | A mail server for your domain: SMTP, submission, IMAP and web administration. |
| [nats](../forms/nats/README.md) | A message bus over TLS, with JetStream for persistent messages. |
| [nextcloud](../forms/nextcloud/README.md) | Files, calendars and contacts for a household. |
| [nginx](../forms/nginx/form.yaml) | Serve your static website on port 80. Supply the site with `--app`. |
| [node](../forms/node/form.yaml) | A Node.js runtime for your own service; no application service included. |
| [node-app](../forms/node-app/form.yaml) | Run your own `server.js` on port 8080; supply the application with `--app`. |
| [node-example](../examples/nodejs/README.md) | A sample Node.js web application, with a tutorial. |
| [oauth2-proxy](../forms/oauth2-proxy/README.md) | Put an OIDC login in front of another service. |
| [ollama](../forms/ollama/README.md) | Run and serve AI models on the CPU. Add authentication before exposing the API. |
| [open-webui](../forms/open-webui/README.md) | A chat interface for Ollama models running in the same VM. |
| [openbao](../forms/openbao/README.md) | Secrets storage. Supply TLS certificates, an unseal key and administrator credentials. |
| [opencanary](../forms/opencanary/README.md) | A low-interaction honeypot that records connection attempts. |
| [openldap](../forms/openldap/README.md) | An LDAP directory over TLS, with anonymous binds disabled. |
| [opensearch](../forms/opensearch/README.md) | A single-node search server with TLS and its security plugin enabled. |
| [otel-collector](../forms/otel-collector/README.md) | Receive OpenTelemetry traces, metrics and logs over TLS and forward them to a configured backend. |
| [overleaf](../forms/overleaf/README.md) | Collaborative LaTeX editing with Overleaf Community Edition. Available for x86_64 only. |
| [paperless](../forms/paperless/README.md) | Document archiving with OCR and search using Paperless-ngx. |
| [php](../forms/php/form.yaml) | Serve your PHP website through nginx and PHP-FPM. Supply the site with `--app`. |
| [php-example](../examples/php/README.md) | A sample PHP website, with a tutorial. |
| [pi-hole](../forms/pi-hole/README.md) | DNS filtering for a home network, with the web interface behind Caddy. |
| [playground](../forms/playground/README.md) | The default `howl run` environment, with an interactive SSH shell and support for ordinary key files. |
| [postgresql](../forms/postgresql/README.md) | PostgreSQL for services in the same VM, accessed through a UNIX socket. |
| [prod](../forms/prod/form.yaml) | A production starting point with DHCP, cloud metadata, persistent data and automatic updates; no application or listener. |
| [prod-ssh](../forms/prod-ssh/form.yaml) | The production starting point with interactive SSH access using security keys. |
| [prometheus](../forms/prometheus/README.md) | Metrics collection from configured targets, with a web UI and authenticated API. |
| [python](../forms/python/form.yaml) | A Python runtime for your own service; no application service included. |
| [python-app](../forms/python-app/form.yaml) | Run your own `main.py` on port 8080; supply the application with `--app`. |
| [python-example](../examples/python/README.md) | A sample Python web application, with a tutorial. |
| [qemu-host](../forms/qemu-host/form.yaml) | A VM host with QEMU, KVM and interactive SSH; nested virtualization is disabled. |
| [rabbitmq](../forms/rabbitmq/README.md) | RabbitMQ for declared clients in the same VM, with password authentication; no clustering or management UI. |
| [restic-server](../forms/restic-server/README.md) | An append-only REST backup target for restic, with a private repository per user. |
| [ruby](../forms/ruby/form.yaml) | A Ruby runtime with Bundler for your own service; no application service included. |
| [ruby-app](../forms/ruby-app/form.yaml) | Run your own `main.rb` on port 8080; supply the application with `--app`. |
| [ruby-example](../forms/ruby-example/form.yaml) | A sample Ruby web application. |
| [rust-example](../examples/rust/README.md) | A sample compiled Rust web application, with a tutorial. |
| [samba](../forms/samba/README.md) | SMB3 file sharing, with a directory per user and encryption required. |
| [sftpgo](../forms/sftpgo/README.md) | SFTP file transfer for configured users; no shell, FTP, WebDAV or web administration. |
| [sh-shim](../forms/sh-shim/form.yaml) | A helper for services that invoke `sh -c`; runs one program and its arguments, without shell syntax. |
| [squid](../forms/squid/README.md) | An outbound HTTPS proxy restricted to configured domains and client networks. |
| [sshd](../forms/sshd/form.yaml) | Interactive SSH access using security keys, for inclusion in your own form. |
| [step-ca](../forms/step-ca/README.md) | A private certificate authority with ACME support. Supply the root and intermediate certificates; keep the root key offline. |
| [suricata](../forms/suricata/README.md) | Network intrusion detection on a configured interface, writing alerts to persistent data. |
| [syncthing](../forms/syncthing/README.md) | Synchronize folders with your other devices, with the web interface behind Caddy. |
| [tailscale](../forms/tailscale/README.md) | A userspace Tailscale subnet router. Supply an auth key and the routes to advertise. |
| [umami](../forms/umami/README.md) | Website analytics without cookies. |
| [unbound](../forms/unbound/README.md) | A recursive DNS resolver with DNSSEC validation, for allowed client networks. |
| [valkey](../forms/valkey/README.md) | A cache or queue for services in the same VM, accessed through a UNIX socket. |
| [valkey-tcp](../forms/valkey-tcp/README.md) | Valkey for network clients on TCP port 6379, with a configured memory limit. |
| [vaultwarden](../forms/vaultwarden/README.md) | A Bitwarden-compatible password manager server. |
| [velociraptor](../forms/velociraptor/README.md) | A Velociraptor server for endpoint visibility and investigation. |
| [webshell-example](../forms/webshell-example/form.yaml) | A deliberately vulnerable Python application for testing confinement. |
| [wordpress](../forms/wordpress/README.md) | WordPress backed by SQLite, served through nginx. |
| [wordpress-mariadb](../forms/wordpress-mariadb/README.md) | WordPress backed by MariaDB on a local UNIX socket. |
| [zeek](../forms/zeek/README.md) | Network traffic analysis on a configured interface, writing JSON logs to persistent data. |
| [zot](../forms/zot/README.md) | A container image registry with authenticated pull access and explicit push and delete permissions. |

## Create your own form

The [form authoring guide](forms.md) explains how to define an application,
services and permissions. The [manifest reference](../forms/README.md) documents
`form.yaml` and the files a form can supply.
