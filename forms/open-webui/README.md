# Open WebUI

The `open-webui` form is a chat interface for language models you run
yourself: [Open WebUI](https://openwebui.com) 0.11, with Ollama running
the models, PostgreSQL keeping the chats, and Caddy in front, serving
HTTPS at your URL with a certificate from Let's Encrypt, each part on a
leash of its own ([design/self-hosting.md](../../docs/design/self-hosting.md)).

## Run your own

You need a domain name you can point at the machine, and memory for the
models you mean to run: 8 GiB runs a 4B model comfortably.

```sh
openssl rand -base64 24 >admin-password      # you sign in with it; keep it
howl create chat --with open-webui --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://chat.example.com --admin-email you@example.com \
	--webui-admin-password admin-password
```

Point `chat.example.com` at the address howl prints, sign in there, and
pull a model under Admin Panel, Settings, Models (`gemma3:4b`, say) and
`nomic-embed-text`, which Open WebUI uses to search documents you give it.

| Flag | |
| --- | --- |
| `--base-url URL` | required. Where it is served, `https://NAME`, no path: Caddy's site, and the one origin browsers may call the API from |
| `--admin-email ADDRESS` | required. The administrator, made on the first start |
| `--webui-admin-password FILE` | required. Its password, never printed or logged |

The administrator is made before Open WebUI serves anything, so no
visitor claims a fresh machine: upstream gives the first to sign up the
whole instance. A later start keeps the administrator as it is: change
its password in Open WebUI. More users are the administrator's to add.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Open WebUI on loopback; the ACME CA |
| Open WebUI | `open-webui` | Ollama on loopback; PostgreSQL's socket; public addresses on 80 and 443 |
| Ollama | `ollama` | public addresses on 443, to pull models |
| PostgreSQL | `postgres` | nothing |

- **Nobody signs up.** Sign-up is off, and the administrator adds each
  user. Tools and functions, which are Python the server runs, are the
  administrator's alone, as upstream ships them.
- **Nothing sent home.** No version check, telemetry or chat sharing to
  openwebui.com; no OpenAI until the administrator adds a connection
  (Admin Panel, Settings, Connections), which settings then keep.
- **Fetches from public addresses alone.** A page a user names is fetched
  by fence's leave to reach public addresses on 80 and 443, never the
  machine or its network (SSRF); Open WebUI refuses local ones too.
- **Ollama on loopback.** Its API has no login; Open WebUI's has.
- **The slim build.** Upstream's own variant without torch: no local
  speech-to-text, document models or reranking. Embeddings come from
  Ollama, vectors go in PostgreSQL by pgvector, in the schema
  `open-webui` ([rootfs/usr/share/werewolf-postgres/open-webui.sql](rootfs/usr/share/werewolf-postgres/open-webui.sql)).
- **Built here.** Wolfi's Open WebUI is the full build and months
  behind: melange installs the release, upstream's slim requirements and
  their dependencies as PyPI stood on a fixed date, on Wolfi's Python
  ([melange/open-webui.yaml](melange/open-webui.yaml)). The wheels bring
  their own libraries, as upstream's image does; a new pin updates them.
- Its signing key is made once with `secrets`, 0600, on `/data`;
  upstream's command makes it with `random`. Cookies are secure.
- PostgreSQL's `allow: [jit]` turns MDWE off for the whole machine, and
  Python is an interpreter: weaknesses this form names.

## Drawbacks

- Plugins load, but a plugin that needs a package the image lacks fails:
  nothing pip-installs at run time, and `/data` cannot hold programs.
- Web search, image generation and speech are off until the
  administrator configures a service for each.
- Models run on the CPU: a GPU is a device no form carries yet.

## Checked

`make check-open-webui` boots it with its test config ([test/config](test/config)),
base URL `https://localhost`, for which Caddy's own CA signs: Open WebUI
answers through Caddy over HTTPS, HTTP is sent to HTTPS, the
administrator signs in and a wrong password does not, its data is in
PostgreSQL, it reaches Ollama, which listens on loopback alone, another
site's browser gets no CORS grant, a stranger cannot sign up or call the
API, and a user the administrator adds cannot add a function or a tool.
`make check-shellfree-open-webui` boots it as it ships, with no config:
no posture failure but those named, and Open WebUI parked, saying it has
no administrator's password, before it serves anything.
