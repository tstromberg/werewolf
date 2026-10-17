# Solr vulnerable demonstration

[Apache Solr](https://solr.apache.org/) 8.11.0 with Log4j 2.14.1, running on hardened
OpenJDK 27; see [form.yaml](form.yaml). The current product is the `solr` form.

## Security Posture

- No Bash, BusyBox, shell entrypoint, or bundled JVM.
- The signed hardened-packages JVM, a separate service UID and bounded memory.
- Writable state confined to Solr's own persistent home and runtime directory.
- No outbound connections. Log4Shell's normal outbound lookup is contained.
- This deliberately pinned application has updates disabled.

## Getting Started

See [image availability](../../docs/forms-catalog.md#images-and-downloads).

```sh
howl create solr-vuln-demo --with solr-vuln-demo --build
```

The administrator UI is `/solr/` on port 8983. This form intentionally exposes its
unauthenticated administrator interface. Use `vuln-demo` for the combined request,
application, command, and containment event dashboard.

The service may execute only packaged `id`, `uname`, and `cat`; there is no shell.
The hardened JVM and network policy can stop vulnerable application behavior before
it reaches command execution. The old Log4j library does not imply a bypass of Java
27's modern JNDI restrictions. Tests verify real indexing and persistence separately
from the deliberately vulnerable dependency.

### Known Quirks

- Data and private configsets live under `/data/svc/solr/home`.
- Java starts `server/start.jar` directly; upstream shell launchers are absent.
- NIO file access and LRU caches avoid the Unsafe operations hardened Java refuses.
- SolrCloud and arbitrary network backends need a separately reviewed declaration.

### Network Exposure

- `listen: tcp/8983 *`

Use `howl test --with solr-vuln-demo --iterate --driver test-solr` for a retained
local VM, or `howl test --with solr-vuln-demo` for the clean release gate.
