# MediaWiki

The `mediawiki` form is `php` with [MediaWiki](https://www.mediawiki.org)
1.43, the long-term release, on SQLite: a wiki for a lab's or a
department's notes, on one machine. Only accounts edit, only an
administrator makes them, and by default only accounts read.

| | |
| --- | --- |
| Listens | tcp/80, nginx. TLS is in front of it: a `caddy` machine or the cloud's load balancer, which says so in `X-Forwarded-Proto` |
| Sends | nothing: no mail, no usage reports, no images or files fetched by URL |
| Runs as | nginx as `nginx`; php-fpm as `php`, leashed to the code, `/etc/mediawiki`, `/run/svc/php-fpm` and `/data/svc/php-fpm` |
| Keeps | in `/data/svc/php-fpm`: the database (`database/wiki.sqlite` and its caches), uploads (`images`), the interface's message cache (`cache`) and the secret key, made once |
| Config | `mediawiki/admin-password` (required); settings `url` (required), `name`, `language` (`en`), `admin` (`Admin`), `public-read` (`false`) |

```sh
umask 077; mkdir -p config/mediawiki
openssl rand -base64 24 >config/mediawiki/admin-password   # you log in with it
build/host/howl pack --with mediawiki -o config.tar --config config \
	--url https://wiki.lab.example.edu --name 'Lab notes' --admin Alice
```

## Installed before it serves

A fresh MediaWiki's web installer belongs to whoever finds it first; this
form has none (the package leaves out `mw-config`). Before php-fpm starts,
`usr/share/werewolf-mediawiki/setup.php` runs as `php`, inside its leash:
it makes the data directories and the secret key, then runs MediaWiki's
own installer with the settings' name, language and address and the
config's administrator, into `database.new`, renamed once it finishes, so
a start cut short leaves nothing half made. After an update of the image
it runs `update.php` once, when the code or `LocalSettings.php` differ
from what the database last met (`database/schema`). A missing password
parks the service with a line naming the file. A later start keeps the
administrator as it is: change the password in the wiki.

## Defaults

- **Who may do what.** No one signs up: the administrator makes accounts
  at Special:CreateAccount. Strangers neither edit nor, unless
  `public-read` is set, read, and uploads are handed out by `img_auth.php`
  to those who may read, never served from the disk. Two-factor logins
  (OATHAuth) are there for each account to turn on. Failed logins are
  throttled: five in five minutes for a name.
- **Uploads** are PNG, GIF, JPEG, WebP and PDF alone, their types checked
  by content: no SVG, HTML or anything else a browser runs. Thumbnails are
  made in PHP, by GD.
- **No programs.** PHP's process functions are off, in the pool and for
  the setup, and the leash grants no exec; MediaWiki's shell-outs (diff3,
  git, ImageMagick) are off too.
- **Code in the image**, read-only, `LocalSettings.php` and the extension
  list in `/etc/mediawiki`. nginx serves the entry points, `/wiki/` and
  the skins' assets, and nothing else of the code.
- **Extensions**, from MediaWiki's own tarball: VisualEditor, WikiEditor,
  CodeEditor, Cite, ParserFunctions, CategoryTree, TemplateData,
  ReplaceText, Nuke and a few more ([extensions.php](rootfs/etc/mediawiki/extensions.php)).
  Those that run a program or reach another server are left out: Math,
  SyntaxHighlight, Scribunto, PdfHandler, SpamBlacklist.
- **PHP** (`etc/php/php-fpm.conf`): `open_basedir` to the code and its own
  directories, URL fopen off, uploads to 64 MB, the opcode cache never
  checking for changed files, and APCu for the cache and the login
  throttle.

## Drawbacks

- No mail: no password resets by mail, no watchlist notices.
- Formulas, highlighted code and Lua modules wait on extensions that run
  programs; a form of your own may add them, with an exec promise.
- SQLite serves a lab or a department. A wiki with many writers at once
  wants MariaDB (`with: [mariadb]`), not yet built here.
- Single sign-on (a university's SAML or OIDC) needs an extension this
  form does not carry yet.

## Checked

`make check-mediawiki` gives it `http://localhost`, its name and an
administrator ([test/config](test/config)) and runs
[test/checks](test/checks): a stranger reads nothing from the API; the
administrator logs in and sees the main page, and a wrong password does
not; a stranger's edit and sign-up are refused and leave no page or
account; an SVG, an HTML file with a script in it and the same file
named `.png` are refused even from the administrator, while a PDF is
taken and handed out to accounts alone; the code and configuration are 404; the password, key and uploads
are `php`'s alone; after five wrong guesses the right password is
refused too; and a stale `database/schema` makes a restart run
`update.php`. `make check-shellfree-mediawiki` boots it with no config:
php-fpm parks, naming the missing password, before anything is installed.
