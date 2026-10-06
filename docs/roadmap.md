# Roadmap

1. Verified boot: a read-only root, signed releases built in CI, and our
   own kernel with IPE, so only code we signed runs. Lockdown and the
   ptrace and memfd settings are done; see
   [design/verified-boot.md](../design/verified-boot.md).
2. Disk images of `prod` and `prod-ssh` in releases: qcow2, and GCP's
   `.tar.gz` (design/native-boot.md). DHCP and the config from a cloud's
   metadata server, which they need, are done: `dhcp/dhcp.zig`,
   `cloud/cloud.zig`.
3. No sshd in production, and nftables default-deny inbound.
4. Shipping the update log off the machine.
5. bite on x86, and drivers beyond virtio (NVMe, ENA, Hyper-V).
