# Data export endpoint

Include `data-export` with the application form to enable `howl export` while the
VM remains powered on. Root's authorized security keys grant read access to the
exported data. The root account's login program implements only the fixed native
operation; it provides no interactive root session, shell, PTY, SFTP or forwarding.

The operator must keep application services administratively down throughout the
transfer. The endpoint checks supervision records and empty service cgroups, and
rejects a capture if a service starts during it. It never stops or restarts services.
The data reader runs as UID 78, with read/search privilege, Landlock and seccomp;
it cannot change source data, execute programs, use the network or control services.
Compression and PostgreSQL control-file checking run separately without privileges.

Archives remain plaintext on the receiving machine. See [data storage]
(../../docs/data.md) and the [export design](../../docs/design/pending/data-export.md).
