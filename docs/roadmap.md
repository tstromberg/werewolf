# Roadmap

1. Verified boot: a read-only root, signed releases built in CI, and our
   own kernel with IPE, so only code we signed runs. Lockdown and the
   ptrace and memfd settings are done; see
   [design/verified-boot.md](../design/verified-boot.md).
2. DHCP: busybox with udhcpc, or a systemd form.
3. No sshd in production, and nftables default-deny inbound.
4. A static `finit_module(2)` helper in place of kmod, removing libcrypto
   from forms that do no cryptography.
5. Shipping the update log off the machine.
6. bite on x86, and drivers beyond virtio (NVMe, ENA, Hyper-V).
