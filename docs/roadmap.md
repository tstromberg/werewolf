# Roadmap

1. werewolf's own files as apks, so autoupdate can update werewolf itself.
2. DHCP: busybox with udhcpc, or a systemd form.
3. dm-verity under `root.erofs`, with the root hash on the command line.
4. Lockdown: `lockdown=integrity`, no sshd in production, nftables
   default-deny inbound.
5. A static `finit_module(2)` helper in place of kmod, removing libcrypto
   from forms that do no cryptography.
6. Shipping the update log off the machine.
7. bite on x86, and drivers beyond virtio (NVMe, ENA, Hyper-V).
