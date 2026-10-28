# Data export endpoint

Include `data-export` with the application form to enable `howl export` while the
VM remains powered on. Root's authorized security keys grant read access to the
exported data and explicit stop/start of known applications. The login program
implements only the fixed native operations; it provides no interactive root
session, shell, PTY, SFTP or forwarding.

The operator must keep application services administratively down throughout the
transfer. The owner can request a graceful stop and explicit restart without a shell:

```sh
howl ssh root@database -- service-down-v1 postgres
howl export database --output backup.tar.zst
howl ssh root@database -- service-up-v1 postgres
```

Stop application clients before their database. A stop waits up to 60 seconds and
never sends KILL. A timeout leaves the stop requested. Export checks supervision and
empty service cgroups, and rejects a capture if a service starts during it. Export
never changes service state.
The data reader runs as UID 78, with read/search privilege, Landlock and seccomp;
it cannot change source data, execute programs, use the network or control services.
Compression and PostgreSQL control-file checking run separately without privileges.

Archives remain plaintext on the receiving machine. See
[data storage](../../docs/data.md) and the
[export design](../../docs/design/pending/data-export.md).
