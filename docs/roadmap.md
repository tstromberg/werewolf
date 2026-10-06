# Roadmap

1. Verified boot: a read-only root, signed releases built in CI, and our
   own kernel with IPE, so only code we signed runs. Lockdown, the
   ptrace and memfd settings, and the read-only root are done; see
   [design/verified-boot.md](../design/verified-boot.md).
2. Disk images of `prod` and `prod-ssh` in releases: qcow2, and GCP's
   `.tar.gz` (design/native-boot.md). DHCP and the config from a cloud's
   metadata server, which they need, are done: `dhcp/dhcp.zig`,
   `cloud/cloud.zig`.
3. No sshd in production. Default-deny inbound is done: only the TCP ports
   a form declares can be bound ([design/fence.md](../design/fence.md));
   UDP waits for Landlock's UDP rules or the seal.
4. Shipping the update log off the machine.
5. bite on x86, and drivers beyond virtio (NVMe, ENA, Hyper-V).
