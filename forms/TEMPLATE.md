# Name

<<<NOTE on style: prose like Wietse Venema. No more than 75 lines. Pragmatic, easy to read. No unnecessary words or sentences. Assume reader is familiar with Linux, but not an expert.>>>>

One sentence description of what this form is, with a link to the upstream project and the manifest file.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

One fenced `sh` block. It is the whole setup, and `make example-NAME` runs it ([docs/design/examples.md](../docs/design/examples.md)). Leave `--on` out: howl picks Lima, bhyve, Firecracker, or QEMU. The machine's name is the form's name. A secret is a command (`openssl rand`). A file the command reads is written in the fence, or lives in `forms/NAME/example/`. A variant is a `text` block. 

```sh
howl create NAME --with NAME
```

Describe the post-install configuration required to actually use the tool.
Keep it short and not scary. The aim is to get the user handed off from
our custom installation to the official documentation. If it spins up an admin console,
publish the URL or how to find it.

End with a link describing
where to pick up from here documentation wise.

### Cloud production deployment (aws, gcp, azure, proxmox)

One fenced `sh` block, run by `make examples-gcp`. It passes `--on gcp` and `--allow-from me`. When this form is more often used on Proxmox, or another cloud, say so here and put that command in a `text` block.

```sh
howl create NAME --with NAME --on gcp --allow-from me
```

If different than the local test deployment, describe post-install configuration
that would be required for a production deployment. Keep it short and not scary.
Don't repeat prose that's in the local test deployment text.  If it spins up an admin console,
publish the URL or how to find it.

### Known Quirks

Configuration choices that differ from a normal deployment on an Debian or Alpine
environment go here. No more than 5 bullet points. Examples include no-shell; no outbound traffic allowed, unusual paths.
Anything that significantly differs from the generic deployment instructions provided by the software provider could be considered a quirk.

### Network Exposure

Any listening sockets - localhost or remote go here. If empty, remove this section header.
Write each as `tcp/PORT` or `udp/PORT`. The example run connects to every `tcp/PORT`.

### Security Weaknesses

Any concerns or posture violations go here. Concise bullets. If empty, remove this section header.
