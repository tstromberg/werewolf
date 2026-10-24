# Available forms

A form says what a werewolf machine is for: its packages, services and
permissions. Pick one below and follow its guide; a name links to the guide
where one exists, else to the form's manifest. For your own application,
start with the [language tutorials](../examples/README.md): the `-app` forms
take your code through `--app`, the `-example` forms carry a sample, and a
runtime form such as `python` supplies the interpreter and leaves the
service to you ([applications.md](applications.md)).

## Get started

```sh
howl forms                            # this checkout, or the signed catalog outside it
howl forms database                   # search names and descriptions
howl forms caddy                      # setup guide, architectures and commands
howl forms --published --arch arm64   # published images for one architecture
howl test --with caddy                # integration and production-variant boot checks
```

After the [installation steps](../README.md#try-it), try the Node.js sample
from the checkout:

```sh
howl run --build --with node-example
```

Open a service's guide first: many need credentials or certificates before
they start, and `howl pack --build --with FORM -h` lists the form's
configuration flags. `--build` uses this checkout. Secure deployment is the
default, and a prebuilt download needs a published protected image for the
form, host and architecture: see the [host support table](cloud.md#signed-boot)
and the [howl guide](../cmd/howl/README.md).

## Images and downloads

Browse the [image catalog](https://dist.werewolf-linux.org/boot/v1/index.html)
or run `howl forms --published`. Each form's page lists its targets (QEMU on
arm64 and x86_64, Lima on arm64) with downloads, package release notes,
signatures, test evidence and the latest attempt's status; a failed build,
test or gate keeps the previous published image. Unsupported architectures
are listed: Overleaf's upstream image is x86_64 only.
[form-images.md](form-images.md) explains how the
[workflow](../.github/workflows/form-images.yml) builds every form with every
protection, and why only gated targets are published.

`howl run` and `howl create` download a published target, today `playground`
([form-images.md](form-images.md#downloading-images)), and enroll
its firmware and TPM. For any other form, run `howl run --build --with FORM`
from the checkout and follow its guide: the same protections, signed with
your own keys.

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
| [langflow](../forms/langflow/README.md) | The full Langflow editor/API with authenticated access, hosted providers and offline ONNX embeddings on hardened Python. |
| [langflow-vuln-demo](../forms/langflow-vuln-demo/README.md) | Pinned vulnerable Langflow with public flow APIs on hardened Python. |
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
| [n8n](../forms/n8n/README.md) | Workflow automation with a private editor/API and a separate JavaScript Code runner on hardened Node.js. |
| [n8n-vuln-demo](../forms/n8n-vuln-demo/README.md) | Pinned vulnerable n8n with a public editor/API on hardened Node.js. |
| [nats](../forms/nats/README.md) | A message bus over TLS, with JetStream for persistent messages. |
| [nextcloud](../forms/nextcloud/README.md) | Files, calendars and contacts for a household. |
| [nginx](../forms/nginx/form.yaml) | Serve your static website on port 80. Supply the site with `--app`. |
| [node](../forms/node/form.yaml) | A Node.js runtime for your own service; no application service included. |
| [node-app](../forms/node-app/form.yaml) | Run your own `server.js` on port 8080; supply the application with `--app`. |
| [node-example](../examples/nodejs/README.md) | A sample Node.js web application, with a tutorial. |
| [oauth2-proxy](../forms/oauth2-proxy/README.md) | Put an OIDC login in front of another service. |
| [ollama](../forms/ollama/README.md) | Run and serve AI models on the CPU. Add authentication before exposing the API. |
| [onnx](../forms/onnx/README.md) | A source-built CPU inference runtime for hardened Python 3.15; applications supply their own service. |
| [onnx-minilm](../forms/onnx-minilm/README.md) | Read-only MiniLM model and tokenizer for offline ONNX embeddings; no service included. |
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
| [solr](../forms/solr/README.md) | Solr search and indexing on hardened OpenJDK 27, with a private API and no shell. |
| [solr-vuln-demo](../forms/solr-vuln-demo/README.md) | Pinned Solr with vulnerable Log4j on hardened OpenJDK 27, without a shell. |
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
| [vuln-demo](../forms/vuln-demo/README.md) | Three vulnerable products with a Go request/violation journal and any-password, command-only SSH; no shell. |
| [webshell-example](../forms/webshell-example/README.md) | A deliberately vulnerable Python application for testing confinement. |
| [wordpress](../forms/wordpress/README.md) | WordPress backed by SQLite, served through nginx. |
| [wordpress-mariadb](../forms/wordpress-mariadb/README.md) | WordPress backed by MariaDB on a local UNIX socket. |
| [zeek](../forms/zeek/README.md) | Network traffic analysis on a configured interface, writing JSON logs to persistent data. |
| [zot](../forms/zot/README.md) | A container image registry with authenticated pull access and explicit push and delete permissions. |

## Create your own form

[forms.md](forms.md) explains how to define an application, its services
and permissions; [forms/README.md](../forms/README.md) documents `form.yaml`
and the files a form can supply.
