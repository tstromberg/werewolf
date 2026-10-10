# Name

<<<NOTE on style: prose like Wietse Venema. No more than 75 lines. Pragmatic, easy to read. No unnecessary words or sentences. Assume reader is familiar with Linux, but not an expert.>>>>

One sentence description of what this form is, with a link to the upstream project.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

<cut and pasteable howl command>

Describe the post-install configuration required to actually use the tool.
Keep it short and not scary. Link to official documentation where applicable.

### Cloud production deployment (aws, gcp, azure, proxmox)

<cut and paste command for the environment this is most likely to be used in>

If different than the local test deployment, describe post-install configuration
that would be required for a production deployment. Keep it short and not scary.

### Known Quirks

Configuration choices that differ from a normal deployment on an Debian or Alpine
environment go here. No more than 5 bullet points. Examples include no-shell; no outbound traffic allowed, unusual paths. 

### Network Exposure

Any listening sockets - localhost or remote go here. If empty, remove this section header.

### Security Weaknesses

Any concerns or posture violations go here. Concise bullets. If empty, remove this section header.
