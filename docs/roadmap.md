# Roadmap

1. Verified boot: a read-only root, signed releases built in CI, and our
   own kernel with IPE, so only code we signed runs. Lockdown, the
   ptrace and memfd settings, and the read-only root are done; see
   [docs/design/verified-boot.md](design/verified-boot.md).
2. Disk images of `prod` and `prod-ssh` in releases: qcow2, and GCP's
   `.tar.gz` (docs/design/native-boot.md). DHCP and the config from a cloud's
   metadata server, which they need, are done: `cmd/dhcp-client/dhcp-client.zig`,
   `cmd/cloud-metadata/cloud-metadata.zig`.
3. No sshd in production. Default-deny in both directions is done: a
   machine sends and receives only what its form declares
   ([docs/design/fence.md](design/fence.md)).
4. Shipping the update log off the machine.
5. Hourly checks, rebooting by how urgent the fix is: minutes for an
   exploited CVE, hours for a high one, and a week or four in the
   maintenance window for the rest
   ([docs/design/update-policy.md](design/update-policy.md)).
6. bite on x86, and drivers beyond virtio (NVMe, ENA, Hyper-V).
