# Service forms

Proposed, 2026-10-07. Built the same day: `caddy`, `valkey`, `openbao`,
`step-ca` and `wordpress` (order 1), each with its config, checks and a
page in docs/; `bastion` and `tailscale` were built before. Of order 0:
`/run/config/NAME` as leash's `config` and `setting` lines
([settings.md](settings.md)), with `config ... optional` for a file a
service runs without and a `json` key with dots reaching a nested key;
`answering` as "a socket listens", with `http-answering` where the port
speaks HTTP and each daemon's own check in test/checks-FORM; and a socket
bound to loopback alone counted as the machine's own by posture and the
listeners check (OpenBao's cluster port). `listen udp` waits with the
forms that need it. What differs from the plan below is noted in each
form's section.

Forms for the services people most want on a machine that is hard to take
over: wordpress and wordpress-mariadb, caddy, haproxy, bastion, wireguard,
tailscale, openbao, mariadb, step-ca, valkey and unbound. Each is `prod`
(or a runtime form) and one Wolfi package, run by leash as a user of its
own, as the runtime forms are ([forms.md](forms.md)).

Vault is not planned. Wolfi's `vault` is 1.14.1, the last release under the
MPL (2023), with nothing since; OpenBao is its API-compatible fork. MySQL
is MariaDB here (below, `mariadb`).

## What they need first

Four things the forms share, built once, before the forms that need them:

1. **`/run/config/NAME`.** Already open in forms.md: leash gives each
   service its part of the config, owned by its user. Nearly every form
   here takes a per-machine value from it: keys, certificates, peers,
   upstreams, an auth key. sshd's `StrictModes` and OpenBao's key files
   need the ownership to be right, not just the reading.
2. **UDP listeners.** fence takes `listen tcp/PORT` only, and refuses
   `listen udp` (cmd/fence/fence.zig's tests). unbound serves udp/53 and
   wireguard udp/51820. fence gains `listen udp/PORT`, with the arriving
   rules (300) admitting it; leash gains it too. Landlock has no UDP bind
   restriction, so for UDP the routing rules are the whole of it, and
   fence.md should say so.
3. **The `answering` check.** test/checks waits for HTTP on every declared
   TCP port but 22. mariadb, valkey, openbao (TLS) and haproxy's TCP mode do
   not answer plain HTTP. `answering` becomes "accepts a TCP connection",
   and each form brings a check of its own protocol, skipped elsewhere by
   `command -v`, as `data-encrypted` is.
4. **Packages that bring a shell.** Three closures carry one:

   | Package | Script | Brings |
   | --- | --- | --- |
   | `haproxy-3.4` | `haproxy-dump-certs`, `haproxy-reload` | bash |
   | `unbound` | `unbound-control-setup` | bash, as `/bin/sh` (`bash-binsh`) |
   | `mariadb-11.8` | `mariadb-install-db`, `mariadb-secure-installation`, a dozen more | bash, perl |

   None of the forms runs those scripts. The fix is upstream: Wolfi
   moves them into a subpackage, as Chainguard does for `-oci-entrypoint`.
   Pruning files after apko would make the image differ from what its
   lock names, and the updater would have to prune again on every slot, so
   it is not the plan. These three forms wait for Wolfi; the PRs go in
   first, since they take the longest.

The rest (wordpress, caddy, bastion, tailscale, openbao, step-ca) have
closures with no shell or interpreter beyond what their base already
carries. **valkey did not**, it turned out: Wolfi's `valkey-9.1` depends
on `posix-libc-utils`, whose `ldd` is a bash script, so bash came with it.
Rather than ship a shell nothing runs, or wait, forms gained `.prune`
([forms.md](../forms.md#files-a-form-leaves-out)): the build leaves the
named files out of the root, and the updater out of every slot it builds,
so the image stays what its lock names but for what the form says. That
is the answer for haproxy, unbound and mariadb too, once their scripts are
read: a shell a dependency drags in goes; a shell the package's own
scripts need, and the scripts with it, is more than a line.

## The forms

| Form | On | Package | User | Listens | Sends | posture |
| --- | --- | --- | --- | --- | --- | --- |
| `caddy` | `prod` | `caddy` 2.11 | `caddy` | tcp/80 tcp/443 | ACME and upstreams: tcp/443, DNS | passes |
| `haproxy` | `prod` | `haproxy-3.4` | `haproxy` | tcp/80 tcp/443 | the backends' ports | passes, once split |
| `bastion` | `prod` | `openssh-server` | `jump` | tcp/22 | tcp/22, to the hosts it forwards to | `network-no-login` |
| `wireguard` | `prod` | none: the kernel's module | (kernel) | udp/51820 | forwarded, to declared networks | passes |
| `tailscale` | `prod` | `tailscale` 1.102 | `tailscale` | nothing | tcp/443, udp/3478 | passes |
| `openbao` | `prod` | `openbao` 2.5 | `openbao` | tcp/8200 | nothing, or KMS on tcp/443 | passes |
| `step-ca` | `prod` | `step-ca` 0.30 | `step` | tcp/443 | tcp/80, ACME's http-01 | passes |
| `valkey` | `prod` | `valkey-9.1` | `valkey` | a UNIX socket | nothing | passes |
| `unbound` | `prod` | `unbound` 1.25 | `unbound` | udp/53 tcp/53 | udp/53 tcp/53 | passes, once split |
| `mariadb` | `prod` | `mariadb-11.8` | `mysql` | a UNIX socket | nothing | passes, once split |
| `wordpress` | `php` | `wordpress` 7.1 | `nginx`, `php` | tcp/80 | tcp/587, mail | `programs-no-interpreters`, as `php` |
| `wordpress-mariadb` | `wordpress` | and `mariadb-11.8`, `php-8.4-mysqli` | and `mysql` | tcp/80 | tcp/587, mail | as `wordpress`, once split |

Configuration that is code, such as a Caddyfile, haproxy.cfg or
unbound.conf, is in the image, from the form, and includes a per-machine
part from `/run/config/NAME` for what differs: names, upstreams, peers,
keys. Data is in `/data/svc/NAME`.

## Defaults

As secure as the common case allows without noticing. Where a stricter
setting would break what most people run, the default works, and the
stricter one is a line in the form or the config, documented beside it.
A DNS server answers on every address; a WordPress sends its mail.

For every form:

- **No unclaimed first boot.** A service that would wait for whoever
  connects first to set it up (WordPress's installer, OpenBao's `init`) is
  set up from the config before it serves.
- **A missing secret parks the service**, with one line naming the file
  (leash's `requires`), rather than starting with a self-signed
  certificate or a default password. An identity the machine can make for
  itself, an ssh host key, an ACME certificate, is made once, kept on
  `/data`, and its fingerprint printed at every boot.
- **State wants a disk.** On a RAM `/data` the stateful forms run, and
  say once on the console what a reboot will lose. Whether `/data` is
  encrypted is posture's to report (`data-encrypted`), not a reason to
  refuse.
- **No control interface on the network.** Admin APIs are off, or on a
  socket in `/run/svc/NAME` that only the service's user can reach.
- **No `exec` promise.** None of these services needs to start a
  program, so none may. `make seal-learn` finds the rest of each pledge.
- **Its own limit under leash's.** A service's own ceiling (`maxmemory`,
  `maxconn`, the buffer pool) sits below its `memory` line, so it refuses
  work rather than being killed for it.
- **The software's modern TLS defaults**, TLS 1.2 at least, and nothing
  weaker added.
- **Security events logged** to the console: logins, forwards, audit.
- **A check with an attack in it**, as the webshell demo has: each form's
  check in test/checks tries the attack its defaults are for.

### caddy

A web server that gets its own certificates. Built as planned
([caddy.md](../caddy.md)), with one site name as a setting (`domain`,
which the Caddyfile reads as `{$DOMAIN::80}`); more names, or upstreams,
are a form of your own with its Caddyfile in the image. Caddy logs JSON
to the console whatever stderr is. The RAM `/data` console line is not
built: Caddy's own log says when it asks the CA.

- `admin off`: the admin API on :2019 lets any local process rewrite the
  configuration.
- Automatic HTTPS as Caddy ships it: Let's Encrypt, ZeroSSL behind it,
  HTTP redirected to HTTPS.
- The placeholder site sends `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: strict-origin-when-cross-origin`, and no `Server`.
  HSTS is the site's to choose: it locks a name to HTTPS for months.
- `timeouts { read_header 10s idle 2m }`, against slowloris. No body or
  write timeout, which would cut off uploads and streams.
- On-demand TLS only with an `ask` endpoint, so a stranger cannot make it
  ask for certificates without limit.
- Certificates and the ACME account in `/data/svc/caddy`
  (`XDG_DATA_HOME`). On a RAM `/data`, every boot asks Let's Encrypt
  again, and the console says so, since its rate limits will notice.
- HTTP/3 off (`protocols h1 h2`) until fence serves UDP. No plugins:
  Wolfi's caddy is the standard build.

### haproxy

A load balancer: `haproxy -db -f /etc/haproxy -f /run/config/haproxy`,
in the foreground, without master-worker, whose reloads re-execute
haproxy.

- HAProxy's own refusals stay: no `insecure-fork-wanted`, no
  `insecure-setuid-wanted`, so no external checks, and with no `exec`
  promise, nothing Lua could start either. The image loads no Lua.
- Timeouts: connect 5s, client and server 30s, `http-request` 10s,
  `tunnel` 1h, so WebSockets live.
- `ssl-default-bind-options ssl-min-ver TLSv1.2`, with HAProxy's ciphers.
- `option forwardfor`, and `http-request del-header Proxy` (httpoxy).
- `maxconn` from the memory it is given.
- No stats socket. A stats page or Prometheus endpoint is a port a form
  adds, and declares.
- `haproxy-3.4-nocaps` if posture flags the file capability the plain
  package sets; leash gives the low port.

### bastion

ssh as a hop, never a login: `ssh -J jump@bastion host` opens a
`direct-tcpip` channel, which needs no shell. No busybox. `jump`'s shell
is one that does not exist, so a session request fails. sshd-start runs
it, as it does for `prod-ssh`.

- **Keys from the config tar**, `/run/config/bastion/authorized_keys`,
  which reaches the machine as every werewolf config does: on a disk, or
  in the cloud's user data, which `cloud-metadata` reads. Not cloud-init,
  and not GCP's `ssh-keys` metadata or OS Login: anyone with
  `compute.instances.setMetadata` could add a key there at runtime, and
  OS Login needs Google's NSS and PAM modules. A new key is a new config.
  Each key may carry `permitopen="host:22"` of its own. SSH certificates
  (`TrustedUserCAKeys`, `AuthorizedPrincipalsFile`) when the config brings
  a CA key, and `step-ca` can be that CA.
- **Any host's port 22 by default** (`connect jump tcp/22`). `PermitOpen`
  in the config narrows the hosts; a form that forwards to other ports
  declares them.
- **Post-quantum key exchange only**: `KexAlgorithms
  mlkem768x25519-sha256,sntrup761x25519-sha512`. Recorded traffic cannot
  be decrypted later by a quantum computer. Any OpenSSH from 8.5 (2021)
  connects, and PuTTY from 0.78. Older clients, and libraries without a
  hybrid exchange (Paramiko, which Ansible uses), are turned away, and
  the form's docs say so.
- `Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com`.
- `HostKeyAlgorithms` and `PubkeyAcceptedAlgorithms` Ed25519 only, with
  its FIDO form (`sk-ssh-ed25519@openssh.com`). OpenSSH has no
  post-quantum signatures yet; a signature is forged only at the time of
  the login, so the exchange is what must resist a recording.
- `ssh -J`'s session to the target is end to end, inside the hop, with
  its own key exchange. The bastion protects its hop; the target's
  `KexAlgorithms` decides whether the session itself is post-quantum.
- The host key from the config if it has one; otherwise made once in
  `/data/svc/sshd`, and its fingerprint printed at every boot.
- `UsePAM no`; passwords and keyboard-interactive off; `PermitListen
  none` (no remote forwards); no agent, X11, tunnel or sftp;
  `PermitUserEnvironment no`; `MaxAuthTries 3`, `LoginGraceTime 30`.
  OpenSSH's `PerSourcePenalties` as shipped.
- `LogLevel VERBOSE`: each login's key fingerprint, and each forward.

posture fails `network-no-login` by design, as on `prod-ssh`, and passes
`programs-no-shell`, which `prod-ssh` cannot. This is what roadmap item 3
("no sshd in production") leaves room for.

### wireguard

A VPN gateway. The kernel's `wireguard` module and nothing in userspace
at runtime. A new program, `wireguard-up`, in Zig, configures it: run by
init before fence, while root still holds `CAP_NET_ADMIN`, it reads
`/run/config/wireguard/wg0.conf` (the wg-quick keys: `PrivateKey`,
`Address`, `ListenPort`, and each `[Peer]`'s `PublicKey`,
`PresharedKey`, `AllowedIPs`, `Endpoint`, `PersistentKeepalive`), makes
the interface over generic netlink, and sets its addresses and routes.
`wg` stays out, or in `DEV=1` only.

A gateway forwards, and init sets `ip_forward=0` for every machine. So this
form needs a new allowance, `forward`, which posture names: init leaves
forwarding on, and fence adds rules for forwarded traffic.

- Forwarded from `wg0` to the networks the form declares, every port, as
  a VPN's users expect. Ports narrow it, per network, if the form says.
- Peers do not reach each other through it unless the form declares the
  tunnel's own network.
- `wireguard-up` refuses peers whose `AllowedIPs` overlap, which would
  quietly send one peer's traffic to another.
- `PresharedKey` taken, and recommended, against a future quantum
  attacker; not required.
- No NAT, since fence uses no netfilter: the network behind routes the
  tunnel's addresses back to the gateway. On a cloud that is one entry in
  its route table, which the form's docs show.
- No log of handshakes: reading the device needs `CAP_NET_ADMIN`, which
  nothing keeps after boot.

This is the largest form here: a program, an allowance and fence's
forwarding. It comes last. A tunnel *endpoint* on any form, reachable
only through WireGuard, is a different shape, a flag like `SSH=1`, and is
not planned here.

### tailscale

A subnet router in userspace: `tailscaled --tun=userspace-networking`,
with no tun device, no `CAP_NET_ADMIN`, as its own user. It relays
tailnet connections to the networks it advertises from its own sockets,
so fence decides what it may reach (`connect tailscale` the ports behind
it), and nothing is forwarded by the kernel.

- Configured by `--config /run/config/tailscale/tailscaled.json`: the
  auth key (`"authKey": "file:/run/config/tailscale/authkey"`), the
  routes it advertises, the control server for Headscale. A tagged,
  pre-approved key is what the docs suggest.
- State in `/data/svc/tailscale` (`--statedir`), socket in
  `/run/svc/tailscale`.
- Shields up: the router serves nothing on the tailnet itself.
- No Tailscale SSH, which runs a login shell; no exit node, Funnel, web
  client or self-update.
- Tailscale's own logging left on, as it ships, for its support;
  `--no-logs-no-support` is one line.
- Relayed through DERP on tcp/443, with STUN on udp/3478: peers' direct
  UDP ports are random, and fence names ports. Direct paths wait until
  fence can say "any UDP port, for this user".
- The docs show Tailnet Lock and an ACL that lets one group reach the
  router's tag.

### openbao

Secrets, on a machine where root cannot read another process's memory.
Integrated storage (raft) in `/data/svc/openbao`. Built as planned
([openbao.md](../openbao.md)); "the auth method the config names" is
`userpass`, with an `admin` user whose first password the `initialize`
stanza reads from the config's file through its `file` source, so no
secret is in the image or in settings.json; a bcrypt `password_hash`
there instead waits on an OpenBao after 2.5.4, which Wolfi ships (the
field arrived upstream in July 2026). The audit
device is OpenBao's `audit` configuration stanza, not an `initialize`
request: `sys/audit` refused the request from self-initialization, and a
device declared in the image cannot be disabled over the API, which is
better. raft's cluster listener is on 127.0.0.1:8201, which the policy
does not declare and fence lets no one reach.

- **Unsealed by a static key, and initialized by itself.** The key is
  `/run/config/openbao/unseal.key` (`seal "static"`), and the config's
  `initialize` stanza (OpenBao 2.4 and later) does what `bao operator
  init` and the first logins would: enables the stdout audit device and
  the auth method the config names, then revokes the root token. Self-
  initialization needs an auto-unseal, which the static seal is. werewolf
  reboots itself into every update; with Shamir shares, every update
  would leave the secrets sealed until enough operators came back. The
  cost is that whoever holds the config tar can unseal the data, the same
  trust the tar already carries for `data.key`.
- A cloud KMS is one stanza in place of the static one (`metadata
  openbao`, tcp/443). Shamir is for those who want a person at every
  unseal: they turn self-initialization off and unseal after each boot.
- The listener on every address, :8200, with its certificate from
  `/run/config/openbao`, and OpenBao's TLS defaults.
- The UI on: it is a client of the same API, behind the same TLS.
- `raw_storage_endpoint`, `introspection_endpoint` and
  `unauthenticated_metrics_access` off, as they ship, and said so in the
  file.
- No `disable_mlock`: OpenBao 2.5 knows no such field, and locks no
  memory (werewolf has no swap anyway).
- No `plugin_directory`, and no `exec` promise.
- Lease lifetimes as OpenBao ships them. Clustering adds tcp/8201.

### step-ca

An internal CA. Named for what runs, as `postgresql` is: "ca" says too
little. Built ([step-ca.md](../step-ca.md)) with ACME alone: a JWK
provisioner is a key, an object a setting cannot hold, so a form of your
own lays its `ca.json` over the image's to add one. The ACME names reach
`authority.policy.x509.allow.dns` through a dotted `json` key.

- The intermediate's key and certificate, the root's certificate and the
  intermediate's password (`--password-file`) from
  `/run/config/step-ca`. The root's key never comes to the machine.
- Two provisioners from the config: a JWK one for its operators, and
  ACME, which is most of why people run one. ACME is bound by an x509
  policy that allows only the domains the config lists, and the service
  parks without that list.
- `ca.json` from the config is the only way to change provisioners:
  remote administration (`enableAdmin`) is off.
- Certificates live 24 hours, as step-ca ships; a provisioner raises it
  in the config for clients that cannot renew daily.
- `connect step tcp/80`, so ACME's http-01 works without a form.
- Its database (badger) in `/data/svc/step-ca`.

### valkey

A cache or queue for the application on the same machine, on a UNIX
socket in `/run/svc/valkey`, as `postgresql` answers on one. The socket is
shared with the application's group, which the form on it names. Built
([valkey.md](../valkey.md)) with `valkey-9.1-cli` beside it, the
operator's client and the check's, and without the bash its package
drags in (above).

- The default user may do all but `-@admin`: no `CONFIG`, `DEBUG`,
  `MODULE`, `REPLICAOF`, `SHUTDOWN`, `MONITOR` or ACL changes. Lua stays
  on: Sidekiq and BullMQ are built on it, and a sandbox escape lands in a
  leashed process that can start nothing.
- `enable-module-command no`, `enable-debug-command no`,
  `enable-protected-configs no`, as they ship, and said so in the file.
- `maxmemory` below leash's `memory`, `noeviction` as shipped, so a full
  queue refuses writes rather than dropping jobs. A cache sets
  `allkeys-lru`.
- RDB snapshots in `/data/svc/valkey`; AOF a line away.
- The old attack, `CONFIG SET dir` to `~/.ssh` and then `SAVE`, is refused
  by the ACL, and would find Landlock holding it to `/data/svc/valkey`,
  and no sshd.
- A form that serves the network adds `listen tcp/6379`, and then a
  password is required (an ACL file from the config). TLS when the config
  brings a certificate; client certificates if it brings a CA.

### unbound

A recursive, validating resolver, for the networks it sits on.

- On every address, udp/53 and tcp/53.
- Answers loopback, RFC 1918, 100.64.0.0/10 (CGNAT, Tailscale), ULA and
  link-local; refuses the rest, so out of the box it is not an open
  resolver. A public one adds ranges in `/run/config/unbound`, and turns
  on `ip-ratelimit`.
- Full recursion, DNSSEC validation, QNAME minimisation, aggressive NSEC
  and unbound's `harden-*` defaults; `hide-identity`, `hide-version`.
- A cloud's private zones (Route 53's private hosted zones, GCP's
  `.internal`) are answered only by the cloud's own resolver: the config
  adds a `forward-zone` for each, and the docs show it.
- No rebinding protection (`private-address`) by default: it breaks
  internal names published in public DNS, which are common. One line
  turns it on.
- `remote-control` off. Caches sized within its `memory`.
- The DNSSEC trust anchor seeded from the image into
  `/data/svc/unbound/root.key` (`auto-trust-anchor-file`, RFC 5011 updates
  kept there). `unbound-anchor` is not run: it would need the network
  before unbound starts.

It waits on fence's UDP listeners and on Wolfi splitting
`unbound-control-setup`. An authoritative server is `nsd`, whose closure
is clean already, if someone asks for one.

### mariadb

MySQL, as MariaDB 11.8, an LTS supported into 2028. Wolfi has no MySQL
8.4 LTS, only Innovation releases (`mysql-9.7`), each supported until the
next, a few months later. A new series also upgrades the data dictionary
one way, so a slot rolled back after one could not read its data.

It works like `postgresql`, a database for the application on the same
machine:

- A UNIX socket in `/run/svc/mariadb`, and no TCP port.
- Local roles are system users, by the `unix_socket` plugin, as Postgres's
  peer authentication: no passwords to keep.
- `local_infile=0`; `secure_file_priv` its own empty directory, so
  `LOAD_FILE()` cannot read the rest of what `mysql` can.
- No application role gets `FILE`, `SUPER` or `PROCESS`. Plugins only from
  the image's plugin directory, which nothing can write.
- utf8mb4, MariaDB's strict `sql_mode`, and `innodb_buffer_pool_size`
  under its `memory`.
- The major version is in the package name; a new one is a new form.

`mariadb-install-db` is a shell script, so a new program,
`mariadb-init`, does what `pg-init` does: if the data directory is empty,
it runs `mariadbd --bootstrap` with the package's system-table SQL, and
what `mariadb-secure-installation` would do (no anonymous users, no
`test` database, `root` by `unix_socket` alone); then the SQL a form
brings in `/usr/share/werewolf-mariadb`. The build puts it in any image
whose chain carries `etc/sv/mariadb`, which is `mariadb` and
`wordpress-mariadb`, rather than keying it on a form's name as `pg-init`
is. It waits on Wolfi moving the scripts out.

A MariaDB that serves other machines adds tcp/3306,
`require_secure_transport`, and password users from the config. Not
planned here.

### wordpress

The worked example forms.md promised, on `php`. Wolfi installs WordPress
in `/usr/src/wordpress`, which becomes nginx's root; the form brings
`wp-config.php`. Built as planned ([wordpress.md](../wordpress.md)); the
installer is PHP, `usr/share/werewolf-wordpress/install.php`, run as a
`before` step, and the admin's password is a bcrypt hash in the config.
Wolfi's package resolves `php` to `php-8.4` once the form names it, and
carries the site's `.git` (58 MB), which nginx refuses as a dotfile.
SQLite wants a temporary directory the leash grants (`SQLITE_TMPDIR`),
and opcache its lock file there too, on php-fpm's command line.

- **Installed before it serves.** A `before` step, `php` calling
  `wp_install()`, sets up the site from `/run/config/wordpress`: its
  address, the admin's email and password hash. nginx always refuses
  `install.php` and `setup-config.php`. A fresh WordPress otherwise
  belongs to whoever finds it first.
- Salts from the config if it has them; otherwise made once on `/data`.
- `DISALLOW_FILE_MODS` and `AUTOMATIC_UPDATER_DISABLED`: plugins, themes
  and updates come with the image.
- XML-RPC stays, for the mobile apps and Jetpack, with pingbacks off.
  `limit_req` on `xmlrpc.php` and `wp-login.php`.
- Users are listed over REST only to those logged in, and `?author=`
  does not reveal names. Application passwords stay on, as WordPress has
  them, over HTTPS only.
- nginx refuses `.php` under uploads, dotfiles, `wp-config.php` and
  `readme.html`; sends `nosniff` everywhere, and `Content-Security-Policy:
  sandbox` on uploaded SVG, HTML and XML, against stored scripts. PDFs and
  images are served as they are.
- Mail goes out by SMTP submission (`connect php tcp/587`), from a
  must-use plugin that reads the relay from the config, since password
  resets need it. Nothing else leaves: `WP_HTTP_BLOCK_EXTERNAL`, and
  `allow_url_fopen` off. A form whose plugins call an API adds
  `connect php tcp/443` and the hosts to `WP_ACCESSIBLE_HOSTS`.
- PHP: `expose_php` and `allow_url_include` off, `open_basedir` to the
  site and its own directories, secure, HttpOnly and SameSite session
  cookies, `opcache.validate_timestamps=0` since the code cannot change.
- Uploads in `/data/svc/php-fpm/uploads`, through a link in the image.
- TLS is in front of it, a `caddy` machine or the cloud's load balancer;
  with an `https` site address, `FORCE_SSL_ADMIN` and secure cookies
  follow.

The database is SQLite, through WordPress's own SQLite plugin carried in
the form, on `/data`, as forms.md planned: one machine, no second server.
The plugin's drop-in, `wp-content/db.php`, is the one file that chooses
it.

Check that Wolfi's `wordpress`, which depends on `php`, resolves to
`php-8.4` and brings no second PHP.

### wordpress-mariadb

WordPress on MariaDB, on one machine, for the sites and plugins that
assume MySQL. It includes `wordpress` and adds `mariadb-11.8` and
`php-8.4-mysqli`. It carries MariaDB's service file itself, as `demo`
carries nginx's on `postgresql`, since a chain takes one base.

- **Its own `wp-config.php`.** `DB_HOST` is the socket,
  `localhost:/run/svc/mariadb/mysqld.sock`.
- **A `db.php` that does nothing,** over the SQLite one. A form can
  replace a file below it but not remove it, and WordPress uses its own
  MySQL driver when the drop-in sets no `$wpdb`.
- **php alone reaches the socket,** as nginx alone reaches php-fpm's. The
  database role is `php`, by `unix_socket`. The form's SQL makes the
  database and grants `php` everything on it, since plugins make their
  tables when they are activated, and nothing beyond it: no `FILE`.
- **Nothing on TCP.** MariaDB keeps no port, and fence's policy is
  `wordpress`'s.

A WordPress whose database is on another machine is a form of the user's
own on `wordpress`, with `connect php tcp/3306` and that machine's
address in `wp-config.php`.

It waits with `mariadb` on Wolfi's split, and on `mariadb-init`.

## Order

| | Forms | Waits on |
| --- | --- | --- |
| 0 | | `/run/config/NAME`, `answering` as a TCP check, `listen udp`; the Wolfi PRs filed |
| 1 | `valkey`, `caddy`, `openbao`, `step-ca`, `wordpress` | 0; built |
| 2 | `bastion`, `tailscale` | 0; built |
| 3 | `haproxy`, `mariadb` (with `mariadb-init`), `wordpress-mariadb`, `unbound` | Wolfi's splits |
| 4 | `wireguard` (with `wireguard-up`) | the `forward` allowance, fence's forwarding rules |

Each form lands with its check. `make check` boots every form in `forms/`
already, so a new form is booted and judged by posture as soon as it
exists. Its own protocol check, and its attack, go in test/checks; its
expected posture failures, where there are any, in test/posture-known.
`make seal-learn` finds each service's promises before its `pledge` line
is written.

## Open questions

- **Mixins.** An include chain is linear, so tailscale, wireguard and
  valkey cannot be added to another form, only built on. `sshd`'s service
  lives in `minimal` and parks itself where sshd is not installed; that
  pattern, or `SSH=1`-style flags (`TAILSCALE=1`), would let them combine.
  Not until a form needs it.
- **fence by destination.** fence names users and ports, not addresses.
  bastion, haproxy, tailscale and wordpress's mail would be tighter if it
  named networks too. sshd's `PermitOpen`, haproxy's backends and the
  mail relay's address hold them now.
- **Which are published.** Today `minimal`, `prod` and `prod-ssh`. Of
  these, `bastion`, `tailscale` and `wireguard` are useful unchanged, with
  only config. The rest are bases for a form of your own.
