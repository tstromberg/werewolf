# Roadmap

1. Verified boot: a read-only root, signed releases built in CI, and our
   own kernel with IPE, so only code we signed runs. Lockdown, the
   ptrace and memfd settings, and the read-only root are done; see
   [design/verified-boot.md](../design/verified-boot.md).
2. Disk images of `prod` and `prod-ssh` in releases: qcow2, and GCP's
   `.tar.gz` (design/native-boot.md). DHCP and the config from a cloud's
   metadata server, which they need, are done: `dhcp/dhcp.zig`,
   `cloud/cloud.zig`.
3. No sshd in production. Default-deny in both directions is done: a
   machine sends and receives only what its form declares
   ([design/fence.md](../design/fence.md)).
4. Shipping the update log off the machine.
5. bite on x86, and drivers beyond virtio (NVMe, ENA, Hyper-V).
