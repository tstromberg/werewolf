# Ollama

The `ollama` form is `prod` with Ollama serving models to a network.

| | |
| --- | --- |
| Listens | tcp/11434, Ollama's API, which has no login of its own: `oauth2-proxy`, `caddy` or a tailnet in front to serve it beyond the machine |
| Sends | HTTPS and DNS, to pull models from `registry.ollama.ai` |
| Runs as | `ollama` (a uid of its own, its name's hash), leashed; it starts its own runner for a loaded model, so it pledges `exec` and may run only itself |
| Keeps | models in `/data/svc/ollama` |

```sh
curl http://ollama.internal:11434/api/pull -d '{"model": "gemma3:4b"}'
```

Models run on the CPU: a GPU is a device no form carries yet. `memory
8192` in the service file is the leash's ceiling; the models decide the
rest. Browsers on other origins are refused (`OLLAMA_ORIGINS`).

## Checked

`make check-ollama` runs [forms/ollama/test/checks](test/checks): the
API answers with no models, a cross-origin request is 403, a pull of a
model that cannot exist fails cleanly, and the model directory is
`ollama`'s on `/data`. No model is pulled: the registry is not a check's
to depend on.
