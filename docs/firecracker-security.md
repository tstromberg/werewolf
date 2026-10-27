# Firecracker security

Firecracker cannot expose UEFI Secure Boot or the TPM used for the release floor. Its
default mode retains IPE, dm-verity, the seal and fence. Before the first boot, howl
records the freshly built kernel, stage0 (including its root hash and signed IPE
policy) and boot entry in `firecracker-boot.json` outside the guest. Each boot checks
them against that record and ignores other guest-written boot entries. Missing or
malformed records and changed boot files fail closed. Existing unprotected disks are
never enrolled automatically. Image changes require a host rebuild; `IPE_UPDATES` and
protected UEFI downloads selected with `--version` are refused in this mode. Security
fixes therefore require an operator to rebuild on the host. After an update attempt,
posture reports `update-held: IpeSignedImageRequired`; this is the updater refusing
an unsigned replacement, not a loss of IPE enforcement.

This host check does not supply firmware Secure Boot or a TPM: the trusted host can
replace the record, and restoring older host state can restore an older vulnerable
release. Keep that state outside guest access. The warning and guest command line
name both missing protections. `--disable=secureboot,tpm` explicitly selects the same
mode. `--disable=secureboot,tpm,ipe` selects the legacy Firecracker path, including
its guest-controlled A/B updates, and does not pin its boot files.

Every Firecracker launch uses bubblewrap namespaces with no capabilities, no new
privileges and Firecracker's default seccomp filters. Only that VM's disk is
writable; boot inputs, configuration and imported data are read-only. Host homes,
signing keys, boot-trust records, agent sockets and other machines are absent.
User, mount, PID, IPC, UTS and cgroup namespaces are private. The host network
namespace is retained to open the tap. Guest-writable FAT metadata is parsed in
a separate sandbox with no network and bounded CPU time, memory and output.
Failure to create either sandbox refuses the boot; it never falls back to an
unconfined process. Linux user namespaces must be enabled.

The host tap policy rejects spoofed IPv4 sources, guest connections to host
services other than DNS, traffic to other Firecracker taps, link-local metadata
addresses and all IPv6 traffic. Replies to host-initiated SSH and guest egress
remain available. These rules apply before general host firewall accepts and
replace the older unrestricted tap forwarding rules automatically.

Console and VMM logs each retain at most 8 MiB, continuing to drain after filling.
Core dumps are disabled; the VMM has 256 descriptors and an address-space limit
of guest RAM plus 1 GiB. Disk I/O and network traffic are rate-limited to 160 MiB/s,
with 10,000 disk operations per second. These limits and sandboxing are automatic;
they do not provide protection from a compromised host kernel or administrator.

See the [security guide](security.md) for guest protections and
[hypervisor tests](testing-hypervisors.md#firecracker) for live validation.
