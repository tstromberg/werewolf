# werewolf: a Wolfi userland on an Alpine kernel, for virtual machines.
#
# Build
#   make install-deps    install apko, Zig, QEMU, erofs-utils and the rest, after
#                        asking: macOS, Debian, Ubuntu, Fedora, Arch; FreeBSD and
#                        NetBSD, experimental, with gmake (tools/install-deps)
#   make                 the image: build/<arch>/vmlinuz, build/<arch>/<form>/initramfs.zst
#   make slot            build/<arch>/<form>/slot/: vmlinuz, stage0, root.erofs, for bite
#   make disk            build/<arch>/<form>/disk.img: a UEFI boot disk of the slot;
#                        DISK_MIB sets its size (8192), DISK_ARGS adds kernel arguments
#   make config-tar      pack config/ (ssh keys, hostname, data.key) into the tar run attaches
#   make list-forms      each form and the forms it includes
#   make howl            the howl command, for this machine: build/host/howl;
#                        howl pack --with FORM packs a config tar from flags (docs/design/cli.md)
#   make install         that command on your PATH, to run in a werewolf checkout,
#                        after make install-deps if any is missing; make uninstall removes it
#
# Boot
#   make run             build and boot it under QEMU, the console here
#   make run-ssh         ssh as root into make run's machine (:2222; http is :8080)
#   make lima            build and boot the lima form under Lima; limactl shell werewolf
#   make lima-delete     delete that VM and its /data: needed before a rebuild boots
#   make demo            build and boot the demo's disk under Lima (macOS on Apple silicon)
#   make demo-delete     delete the demo's VM and its /data
#   make demo-gcp        the demo on a Google Compute Engine VM; demo-gcp-delete deletes it
#   make webshell-gcp    the webshell-example form on a GCP VM; webshell-gcp-delete deletes it
#
# Take over
#   make bite-me         on a Debian, Ubuntu, Fedora or Rocky VM: build a slot,
#                        install it with bite, open a shell in it, offer to reboot
#
# Test
#   make test            the Zig programs' unit tests: seconds, no VM
#   make precommit       what a commit must pass: test, lint and one boot, sshd
#   make hooks           have git run that (tools/git-hooks) before each commit
#   make lint            check the Zig and YAML; make fix repairs what it can
#   make check           boot every form and a slot under QEMU, and attack each;
#                        make -j check boots them side by side
#   make check-FORM      one form's boot, built with a shell for the checks;
#                        check-shellfree-FORM boots it as it ships, without one
#   make check-updater   a whole update, fetched from Wolfi and Alpine;
#                        check-updater-staged cuts the power once it is staged,
#                        and the next boot must take it
#   make check-gcp       prod-ssh's disk on a Google Compute Engine VM, then deleted
#   make check-aws       the same on an EC2 instance
#   make check-azure     the same on an Azure VM
#   make ci              CI's check job, in an Ubuntu VM under Lima
#   make posture         build posture; on Linux, run it here with sudo
#
# Release
#   make relock          re-resolve the lock a FREEZE=1 or release build pins to
#                        (default builds resolve the current packages, unpinned)
#   make release-inputs  relock the released forms and digest what they build from;
#                        CI releases when the digest changes
#   make dist            the released forms' files and unsigned manifests, in dist/
#   make check-dist      boot dist/'s disks as published, under UEFI
#   make cve-tiers       build the CVE tiers feed here, in build/tiers/; needs an NVD
#                        API key in NVD_API_KEY, or the file NVD_API_KEY_FILE names
#   make clean           remove build/, but for the package pins in build/lock
#
# FORM picks the form (default sshd; make lima implies lima, make bite-me
# prod-ssh). DEV=1 adds a
# shell, busybox, to a form that ships without one: for debugging, never
# for release. ARCH defaults to the host; ARCH=x86_64 on an arm64 host
# builds fine and boots under TCG, slowly, for checking, not for working in.

# Asked of uname once: `ARCH ?= $(shell ...)` would ask again at every use
# of $(ARCH), some two hundred times a run, seconds of every make.
HOST_ARCH := $(shell uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
ARCH ?= $(HOST_ARCH)
HOST_OS := $(shell uname -s)

# --- forms --------------------------------------------------------------------
# A form is a directory, forms/NAME (forms/README.md): apko.yaml, the apko
# config of its packages and accounts; form.yaml, what werewolf adds that
# apko cannot say, from the form it is built on (base) and the forms it
# takes beside it (with) to its network policy; and rootfs/, its files,
# laid over its packages. A form has its chain's parts, base first, its
# own last, so they win. CHAIN is that chain, FORM_DIRS its directories,
# as build/host/form reads them (tools/form.zig, lib/form.zig), which also
# merges the chain's apko configs into the one apko builds from. FORM may
# be a directory outside the tree, `make FORM=../myapp`: a form named
# after it, built on forms in forms/.
FORM ?= $(if $(filter lima,$(MAKECMDGOALS)),lima,$(if $(filter bite-me,$(MAKECMDGOALS)),prod-ssh,sshd))
FORM_TOOL = build/host/form
# Its sources, and the libraries it is built with: lib/form.zig, the
# forms; lib/allow.zig, the allowances form.yaml may name; lib/service.zig,
# the service files whose pledges make the machine's promises, and what
# that imports.
FORM_TOOL_SOURCES = tools/form.zig lib/form.zig lib/allow.zig lib/sshd.zig lib/service.zig lib/seal.zig lib/settings.zig
FORM_TOOL_MODULES = --dep form --dep service --dep seal --dep sshd -Mroot=tools/form.zig \
	--dep allow --dep sshd -Mform=lib/form.zig -Mallow=lib/allow.zig --dep settings -Msshd=lib/sshd.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig
# Built before anything else is read, since everything about a form is
# read through it; each make asks it a few questions, in milliseconds.
FORM_TOOL_BUILT := $(shell [ -x $(FORM_TOOL) ] && [ -z "$$(find $(FORM_TOOL_SOURCES) -newer $(FORM_TOOL))" ] || \
	{ mkdir -p build/host && zig build-exe -O ReleaseSafe $(FORM_TOOL_MODULES) \
		-femit-bin=$(FORM_TOOL).$$$$ >&2 && mv $(FORM_TOOL).$$$$ $(FORM_TOOL); })
ifeq ($(wildcard $(FORM_TOOL)),)
$(error no $(FORM_TOOL), as zig says above; `make install-deps` installs zig)
endif
CHAIN := $(shell $(FORM_TOOL) names $(FORM_REF))
ifeq ($(CHAIN),)
$(error no form $(FORM_REF), as build/host/form says above; `make list-forms` lists them)
endif
endif
FORM_DIRS := $(shell $(FORM_ASK) dirs $(FORM_REF))
FORM_DIR := $(lastword $(FORM_DIRS))
ROOTFS_DIRS := $(wildcard $(addsuffix /rootfs,$(FORM_DIRS)))
# rootfs_find ARGS: find ARGS over the chain's rootfs/ directories; with
# none, in a make that asked no form, nothing, rather than find's usage.
rootfs_find = $(if $(ROOTFS_DIRS),$(shell find $(ROOTFS_DIRS) $(1)))
FORM_FILES := $(wildcard $(addsuffix /apko.yaml,$(FORM_DIRS)) $(addsuffix /form.yaml,$(FORM_DIRS)))
# form_list KEY: form.yaml's KEY along the chain; form_check KEY: the
# form's own check KEY.
form_list = $(shell $(FORM_ASK) list $(FORM_REF) $(1))
form_check = $(shell $(FORM_ASK) check $(FORM_REF) $(1))

# --- allowances ---------------------------------------------------------------
# What a form may take back of werewolf's defaults, and only when it is
# built: form.yaml's `allow`, added to along the chain, so no form drops
# what one it is built on was given; lib/allow.zig says what each is, and
# build/host/form refuses a name it does not know. meta writes them into
# the image, /etc/werewolf/allow/NAME, where init, fence and posture read
# them. Nothing on the machine reads an allowance from its command line,
# config or metadata, which root can rewrite: the build turns them into
# the image's kernel arguments and module parameters, below, and the image
# is what decides (docs/design/lockdown.md, Allowances).
ALLOW := $(sort $(call form_list,allow))
ifneq ($(filter nested-kvm,$(ALLOW)),)
ifeq ($(filter kvm,$(ALLOW)),)
$(error form $(FORM) allows nested-kvm without kvm)
endif
endif

# The kernel's hardening that has no runtime switch, on the command line of
# every way the image boots: bite's and boot/mkdisk's entries, which read it
# from the slot's cmdline; the updater's, from the image's
# /usr/share/werewolf/cmdline; and run, check and Lima, here. No debugfs; no
# forced writes through /proc/PID/mem, how a program rewrites its own code;
# on x86_64 no 32-bit system calls; on aarch64 no KVM, which the kernel
# builds in and starts whenever a host lends the guest EL2, unless the form
# allows it, and nested only if it allows that too. Each kernel cache kept
# apart (slab_nomerge), so an object freed in one cannot be taken over by
# an attacker's of another type that shares it, and pages handed out in a
# shuffled order: neither costs a program anything. init_on_alloc and the
# kernel stack's random offset are Alpine's kernel's defaults already;
# init_on_free, which costs allocation-heavy work, is left off by choice
# (docs/security.md). No IPv6, unless the form allows it.
KERNEL_ARGS = debugfs=off proc_mem.force_override=never slab_nomerge page_alloc.shuffle=1
KERNEL_ARGS += $(if $(filter ipv6,$(ALLOW)),,ipv6.disable=1)
ifeq ($(ARCH),aarch64)
KERNEL_ARGS += $(if $(filter nested-kvm,$(ALLOW)),kvm-arm.mode=nested,$(if $(filter kvm,$(ALLOW)),,kvm-arm.mode=none))
else
KERNEL_ARGS += ia32_emulation=0
endif
# The console shows the kernel's warnings and worse; dmesg keeps every
# message. The kernel writes its console as it goes, and a cloud's serial
# port takes a millisecond a line: on GCP its boot's notices and info took
# half its time (0.23 s against 0.11 s). Panics, stalls, BUG and the
# power-down line, which test/boot reads, are all errors or worse.
KERNEL_ARGS += loglevel=5
# Parameters the image loads modules with, MODULE:KEY=VALUE, one a word: on
# x86_64, KVM's nested virtualization, which Linux turns on by default.
# A parameter for a module the form does not carry fails the build.
MODULE_PARAMS = $(if $(and $(filter x86_64,$(ARCH)),$(filter kvm,$(ALLOW))),$(foreach m,kvm-intel kvm-amd,$(m):nested=$(if $(filter nested-kvm,$(ALLOW)),1,0)))

# werewolf's own programs, cmd/NAME/NAME.zig, are built, not checked in, and
# laid in like forms' rootfs (docs/programs.md). init, stage0, the module
# loader (modload), the network setup (iface-up) and policy (fence), the
# one-way mount and the mount broker, posture, the SHELLFREE programs
# and bite-cleanup are in every form; the rest only in forms whose chain
# names them in form.yaml's programs: prod's dhcp-client, cloud-metadata,
# slot-update and service-config, sshd's sshd-start, and postgresql's
# popen-shim.so, a library. A program one form alone needs is that form's own,
# forms/NAME/cmd/PROGRAM/PROGRAM.zig, built the same way, and in every form
# built on it: gitea's gitea-init and gitea-hook, postgresql's pg-init,
# demo's status-page.
# What they share to confine themselves is lib/sandbox.zig, and to mount,
# lib/broker.zig. Zig is pre-1.0 and changes between releases, so the build
# insists on the version the code is written for.
ZIG_VERSION = 0.17.0
# Each is built into its own folder under PROGRAMS, apart from the forms',
# so a form may share a program's name.
PROGRAMS = build/$(ARCH)/programs
# program_bin NAME: where cmd/NAME is built, NAME.so, a library, too.
program_bin = $(PROGRAMS)/$(basename $(1))/usr/lib/werewolf/$(1)
# form_bin DIR: where a form's own program, forms/F/cmd/P, is built.
form_bin = $(PROGRAMS)/forms/$(notdir $(patsubst %/cmd/$(notdir $(1)),%,$(1)))/usr/lib/werewolf/$(notdir $(1))
FORM_PROGRAMS := $(call form_list,programs)
ifneq ($(filter-out $(patsubst cmd/%/,%,$(wildcard cmd/*/)),$(basename $(FORM_PROGRAMS))),)
$(error form $(FORM) runs $(filter-out $(patsubst cmd/%/,%,$(wildcard cmd/*/)),$(basename $(FORM_PROGRAMS))), which cmd/ has no program for)
endif
FORM_OWN_PROGRAMS := $(foreach d,$(FORM_DIRS),$(patsubst %/,%,$(wildcard $(d)/cmd/*/)))
PROGRAM_BINS := $(foreach p,$(FORM_PROGRAMS),$(call program_bin,$(p))) $(foreach c,$(FORM_OWN_PROGRAMS),$(call form_bin,$(c)))
# Every form's, for the checks to build before forms build side by side.
ALL_PROGRAM_BINS := $(foreach p,$(shell $(FORM_ASK) every programs),$(call program_bin,$(p))) \
	$(foreach c,$(patsubst %/,%,$(wildcard forms/*/cmd/*/)),$(call form_bin,$(c)))
BITE_CLEANUP := $(PROGRAMS)/bite-cleanup/usr/bin/bite-cleanup
MOUNT_BIN := $(PROGRAMS)/mount/usr/lib/werewolf/mount
# The mount broker (cmd/mount-broker), which init starts before fence: the
# mounts root's programs need once fence's Landlock domain forbids their own.
BROKER_BIN := $(PROGRAMS)/mount-broker/usr/lib/werewolf/mount-broker
LOADER_BIN := $(PROGRAMS)/modload/usr/lib/werewolf/modload
# stage0's own /init (cmd/stage0/stage0.zig): the kernel's first process on every
# machine. In stage0's initramfs, not the root's.
STAGE0_BIN := $(PROGRAMS)/stage0/init
# The root's /init (cmd/init/init.zig), which stage0 hands over to: PID 1 until
# runit, in every form.
INIT_BIN := $(PROGRAMS)/init/init
NET_BIN := $(PROGRAMS)/iface-up/usr/lib/werewolf/iface-up
FENCE_BIN := $(PROGRAMS)/fence/usr/lib/werewolf/fence
POSTURE_BIN := $(PROGRAMS)/posture/usr/lib/werewolf/posture
# The seal's other half (cmd/seal-watch), which init starts to refuse, and
# say, what the image's list does not allow; and `seal`, which shows it.
SEAL_PROGRAMS := seal-watch seal
SEAL_BINS := $(foreach p,$(SEAL_PROGRAMS),$(PROGRAMS)/$(p)/usr/lib/werewolf/$(p))
# What a shell script used to do, one small program each (docs/design/shell-free.md):
# runit's stages, reboot and poweroff, GRUB's environment block, and the
# slot-keep, power-button and debug-shell services, and the host key a
# leashed sshd makes on first boot (ssh-host-key); and leash, which starts
# a service someone else wrote. The forms link to them. The sshd service,
# sshd-start, is the sshd form's (programs:).
SHELLFREE := runit-stage reboot grub-setenv slot-keep power-button debug-shell ssh-host-key leash leash-reap
SHELLFREE_BINS := $(foreach p,$(SHELLFREE),$(PROGRAMS)/$(p)/usr/lib/werewolf/$(p))
OVERLAY_DIRS = $(ROOTFS_DIRS) $(OUT)/ro $(PROGRAMS)/init $(PROGRAMS)/modload $(PROGRAMS)/iface-up $(PROGRAMS)/fence $(PROGRAMS)/mount $(PROGRAMS)/mount-broker $(PROGRAMS)/posture $(addprefix $(PROGRAMS)/,$(SEAL_PROGRAMS) $(SHELLFREE)) $(PROGRAMS)/bite-cleanup \
	$(sort $(foreach b,$(PROGRAM_BINS),$(patsubst %/usr/lib/werewolf/$(notdir $(b)),%,$(b))))

# --- locks --------------------------------------------------------------------
# Every package in an image is pinned by a lock, apko's own, covering both
# architectures: one for the form and one for the kernel, Alpine's
# linux-virt from the branch boot/kernel.yaml names; stage0 has no
# packages (cmd/stage0/stage0.mtree). A build installs exactly what its
# locks name, and everything after apko depends
# only on its input, so the same locks and the same tree give the same
# bytes. A lock is resolved from the repositories as they are when it is
# missing or older than its config; `make relock` resolves the form's again.
# CI does that every 15 minutes, and releases when the result changes.
LOCK = build/lock
LOCKS = $(FORM_LOCK) $(LOCK)/kernel.lock.json $(LOCK)/boot.lock.json

# DEV=1 builds a form with a shell, for debugging and for test/checks, which
# run as root on the console: busybox-full on top of the form's packages,
# locked apart, and built apart, in build/<arch>/<form>-dev. No form needs
# it to work; the forms that log people in carry busybox-full themselves.
# A check that speaks the daemon's own protocol needs its client (mc,
# mosquitto_sub, nats): form.yaml's dev names such packages, along the
# chain, for DEV=1 builds alone. What ships never has them.
DEV ?=
FORM_LOCK = $(LOCK)/$(FORM)$(if $(DEV),-dev).lock.json
DEV_PACKAGES := busybox-full $(call form_list,dev)

# apko_retry COMMAND: COMMAND, tried again 15, 30 and 45 seconds on if it
# fails reaching the package server: Wolfi's turns a burst of requests away
# for a few seconds (HTTP 403), as CI's runners resolving forms at once can
# make. Any other failure, a package no repository has among them, fails
# at once. Its output streams as it comes, and is kept to be read after.
APKO_NETWORK = status code (403|408|429|5[0-9][0-9])|connection reset|i/o timeout|TLS handshake|deadline exceeded|unexpected EOF|failed to fetch
apko_retry = o=$(CURDIR)/$@.apko && for t in 1 2 3 4; do \
	{ $(1); echo $$? >$$o.rc; } 2>&1 | tee $$o; rc=$$(cat $$o.rc); \
	if [ "$$rc" = 0 ]; then rm -f $$o $$o.rc; break; fi; \
	if ! grep -Eq '$(APKO_NETWORK)' $$o || [ $$t -eq 4 ]; then rm -f $$o $$o.rc; exit 1; fi; \
	echo "apko could not reach the package server; trying again in $$((t * 15))s" >&2; sleep $$((t * 15)); done

# apko lock CONFIG, from CONFIG's directory, where apko resolves the
# config's relative paths (boot/kernel.yaml's keys).
apko_lock = mkdir -p $(LOCK) && cd $(dir $(1)) && \
	$(call apko_retry,apko lock --arch aarch64$(,)x86_64 --output $(CURDIR)/$@ $(notdir $(1)))

# apko build-minirootfs CONFIG into $@, resolving each package to the version
# the repositories hold now and verifying it against CONFIG's keyring. Versions
# are not pinned by default: Wolfi keeps only the latest, so a pin breaks the
# moment a package moves, and a werewolf instance updates itself at first boot
# (forms/prod, cmd/slot-update) anyway -- so the published, signed image, not a
# source rebuild, is the artifact of record. FREEZE=1 pins to the versions LOCK
# ($(2)) names, for a reproducible build.
define apko_build
pins=$(if $(FREEZE),$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(.*\)-\([^-]*-r[0-9]*\)\.apk".*|-p \1=\2|p' $(2))) && \
	mkdir -p $(dir $@) && cd $(dir $(1)) && \
	$(call apko_retry,apko build-minirootfs --build-arch $(ARCH) $$pins $(notdir $(1)) $(CURDIR)/$@)
endef

# A tar of directories laid over one another in order, whose bytes depend
# only on the files' contents and whether each is executable: sorted, owned
# by root, modes 644 or 755, dated 1970 as apko dates its own files, and
# carrying nothing of the builder's (owners, extended attributes,
# .DS_Store). Images are made from tars alone, so no inode number or
# timestamp of the build host reaches one.
define layer
rm -rf $@.d && mkdir -p $@.d && \
	for d in $(1); do cp -R $$d/. $@.d/ || exit 1; done && \
	find $@.d -name .DS_Store -delete && chmod -R u=rwX,go=rX $@.d && \
	TZ=UTC find $@.d -exec touch -h -t 197001010000 {} + && \
	(cd $@.d && find . -mindepth 1 | sed 's|^\./||' | LC_ALL=C sort | \
		COPYFILE_DISABLE=1 $(TAR) -cf $(CURDIR)/$@ --format ustar --uid 0 --gid 0 \
		--numeric-owner --no-xattrs --no-acls --no-fflags -n -T -) && \
	rm -rf $@.d
endef

# Leaf modules a form carries, from form.yaml's modules along its chain,
# as its files are. A line may start with an arch, `aarch64 virtio_mmio`,
# to apply to that arch alone, and then with a tag, `@xfs xfs`, for
# modules only a machine stage0 names so needs, a word `@xfs:xfs` here: a
# slot on that filesystem, or, `@hyperv`, a machine on Hyper-V, as in
# `aarch64 @hyperv hv_netvsc`.
# modules.dep lists each leaf's transitive dependencies; read back to front
# that is a load order, which is what werewolf.modules holds and modload
# loads. A dependency only such a filesystem needs is a line `@xfs PATH`,
# which modload loads only when stage0 finds the slot on xfs. No kmod index
# files travel, so there is nothing describing the 880 modules that stay
# behind. modload closes the loader once these are in.
MODULES := $(shell $(FORM_ASK) list $(FORM_REF) modules | \
	awk -v a=$(ARCH) '{ c = index($$0, sprintf("%c", 35)); if (c) $$0 = substr($$0, 1, c - 1) } \
		$$1 == "aarch64" || $$1 == "x86_64" { if ($$1 != a) next; $$1 = ""; $$0 = $$0 } \
		$$1 ~ /^@[a-z0-9]+$$/ { for (i = 2; i <= NF; i++) printf "%s:%s ", $$1, $$i; print ""; next } { print }')

# Tags for what only a distro's disk needs, after bite: the modules of its
# filesystem (Rocky's xfs, Fedora's btrfs). The slot has two stage0s:
# stage0.zst, for werewolf's own disk and a direct boot, which leaves
# them out, so no machine carries code none of its boots can load, and
# stage0-bitten.zst, which bite installs, with them. Booted under
# Firecracker, the 13 MB less to unpack brought the machine up 25 ms
# sooner. The image records both lists (meta: modules, modules-bitten), so
# the updater builds a slot's stage0 as the build does.
BITTEN_TAGS = xfs btrfs
BITTEN_MODULES = $(filter $(foreach t,$(BITTEN_TAGS),@$(t):%),$(MODULES))
NATIVE_MODULES = $(filter-out $(BITTEN_MODULES),$(MODULES))

# Files a form leaves out of its packages, from form.yaml's prune along
# the chain: a path an item, as it is in the image (usr/bin/bash). For what a package declares it needs and nothing on the
# machine runs: Wolfi's valkey brings bash, for posix-libc-utils' ldd. The
# root is made without them, the image records them
# (/usr/share/werewolf/prune) and the updater removes them from every slot
# it builds, so a slot built on the machine holds what the build's did.
# The packages stay installed as far as apk's database and the release's
# manifest know. A path must be relative and clean.
PRUNE := $(call form_list,prune)
ifneq ($(filter /% ./% ../% %/ %/.. %/.,$(PRUNE)),)
$(error form $(FORM) prunes $(filter /% ./% ../% %/ %/.. %/.,$(PRUNE)): a path is relative and clean, usr/bin/bash)
endif

# The network policy, from form.yaml's net along the chain: `listen tcp/PORT`
# for what a form serves, a trailing `loopback` for a port its own processes
# may bind and reach but the network never does (a database a service
# beside it uses), `connect USER|all tcp/PORT udp/PORT icmp` for what
# its programs may send, by the user they run as, a trailing `public` keeping
# those ports to public addresses (never private, loopback or link-local),
# and `metadata USER` for who may reach the cloud's metadata server. Nothing
# undeclared is sent or received. meta compiles it to numbers, users to uids from the
# image's own /etc/passwd, in /usr/share/werewolf/net, which fence enforces
# (docs/design/fence.md). A line it cannot compile fails the build.

BUILD = build/$(ARCH)
# APP: an application's files, staged by howl build, run or create
# --app (cmd/howl/app.zig) and laid over the image where the form keeps
# its application (etc/werewolf/app). An image with one builds apart.
APP ?=
OUT = $(BUILD)/$(FORM)$(if $(DEV),-dev)$(if $(APP),-app)
TAR ?=$(shell command -v bsdtar || echo tar)
SHA256 ?= $(shell command -v sha256sum || echo shasum -a 256)

# --- hypervisor ---------------------------------------------------------------
ifeq ($(ARCH),aarch64)
MACHINE = virt
CONSOLE = ttyAMA0
else
MACHINE = q35
CONSOLE = ttyS0
endif
# A Linux host without /dev/kvm (some CI runners) emulates, slowly, and so
# does FreeBSD, since QEMU has no bhyve (howl create --on bhyve has).
# NetBSD accelerates with NVMM once loaded (modload nvmm): experimental.
ifeq ($(ARCH),$(HOST_ARCH))
ACCEL = $(if $(filter Darwin,$(HOST_OS)),hvf,$(if $(wildcard /dev/kvm),kvm,$(if $(wildcard /dev/nvmm),nvmm,tcg)))
CPU = $(if $(filter tcg,$(ACCEL)),max,host)
VMTYPE = $(if $(filter Darwin,$(HOST_OS)),vz,qemu)
else
ACCEL = tcg
CPU = max
VMTYPE = qemu
endif
LIMA_CONSOLE = $(if $(filter vz,$(VMTYPE)),hvc0,$(CONSOLE))

# A recipe that fails takes what it half-made with it: a compiler's empty
# output, a lock apko stopped writing. Otherwise the next make would find
# it newer than its sources and call it built.
.DELETE_ON_ERROR:

# A target whose name starts with _ is a step another target runs, with
# FORM set for it; `make help` lists the ones to type.
.PHONY: all install uninstall install-deps precommit hooks check-adhoc image slot bite-me disk run run-ssh lima lima-delete demo demo-delete webshell-demo _webshell-demo config-tar list-forms test check seal-learn check-slot check-updater check-updater-staged check-updater-release _check-updater check-nodata check-lease check-static check-unsigned check-verity check-deadman check-metadata check-dist check-gcp check-aws check-azure demo-gcp demo-gcp-delete webshell-gcp webshell-gcp-delete ci relock release-inputs dist posture clean help \
	_check-form _check-shellfree-boot _check-slot-boot _check-updater-boot _check-nodata-boot _check-lease-boot _check-static-boot _check-unsigned-boot _check-unsigned-slot _check-metadata-boots _dist-form _check-dist-disk _check-cloud

all: image

# What the build, run and check need, from the system's package manager
# and, pinned, from upstream: see tools/install-deps.
install-deps:
	@tools/install-deps

# What a commit must pass, as git's pre-commit hook runs it, by hand.
precommit:
	@tools/git-hooks/pre-commit

# Git's hooks from tools/git-hooks: pre-commit runs the unit tests, lint and
# one boot, sshd.
hooks:
	git config core.hooksPath tools/git-hooks
	@echo "hooks: git runs tools/git-hooks/pre-commit before each commit: test, lint, check-sshd"

# Compiled tutorial applications; their toolchains stay on the build host.
include examples/build.mk
# Packages Wolfi does not ship, built with melange from a form's recipes.
include melange.mk
ifneq ($(APP),)
OVERLAY_DIRS += $(APP)
$(OUT)/meta.stamp $(OUT)/overlay.tar: $(shell find $(APP) -type f -o -type d)
endif

image: $(BUILD)/vmlinuz $(OUT)/initramfs.zst

# The apko config a form is built from: its chain's apko.yaml files merged,
# base first, by the rules apko's own include merged by (lib/form.zig),
# and, under DEV, the dev packages after the rest.
FORM_APKO = $(BUILD)/form/$(FORM)$(if $(DEV),-dev).yaml

# A lock is resolved again when the form's files change, not when the tool
# that merges them does: what apko is asked for is the same.
$(FORM_LOCK): $(FORM_FILES) | $(FORM_APKO)
	$(call apko_lock,$(FORM_APKO))

$(FORM_APKO): $(FORM_FILES) $(FORM_TOOL)
	mkdir -p $(dir $@) && $(FORM_TOOL) apko $(FORM_REF) $(if $(DEV),$(DEV_PACKAGES)) >$@.tmp && mv $@.tmp $@

$(LOCK)/kernel.lock.json: boot/kernel.yaml
	$(call apko_lock,$<)

relock:
	rm -f $(LOCKS)
	$(MAKE) --no-print-directory FORM=$(FORM) $(LOCKS)

# --- kernel -------------------------------------------------------------------
# Alpine's linux-virt, installed by apko with the rest of what it depends on,
# checked against the Alpine keys in forms/prod. Only the kernel and
# its modules are kept.
$(BUILD)/kernel/rootfs.tar: $(LOCK)/kernel.lock.json
	$(call apko_build,boot/kernel.yaml,$<)

# Alpine's config, checked for what werewolf relies on it to leave out
# (tools/kernel-config-check.zig): built in, code the module loader keeps
# out today would be in every machine.
KERNEL_CONFIG_CHECK = build/host/kernel-config-check
$(BUILD)/vmlinuz: $(BUILD)/kernel/rootfs.tar $(KERNEL_CONFIG_CHECK)
	rm -rf $(BUILD)/kernel/x
	mkdir -p $(BUILD)/kernel/x
	config=$$($(TAR) -tf $< | grep '^boot/config-') && \
		$(TAR) -xf $< -C $(BUILD)/kernel/x boot/vmlinuz-virt lib/modules $$config && \
		$(KERNEL_CONFIG_CHECK) $(BUILD)/kernel/x/$$config
	cp $(BUILD)/kernel/x/boot/vmlinuz-virt $(BUILD)/vmlinuz
	# On aarch64 Alpine ships an EFI zboot image: a PE whose payload is the
	# gzipped Image, unpacked by its own EFI stub. QEMU understands it;
	# Apple's Virtualization framework does not, so unwrap it. The header
	# is "MZ", "zimg", then payload offset and size as little-endian u32.
	@if [ "$$(dd if=$(BUILD)/vmlinuz bs=1 skip=4 count=4 2>/dev/null)" = zimg ]; then \
		off=$$(od -An -t u4 -j 8 -N 4 $(BUILD)/vmlinuz | tr -d ' '); \
		size=$$(od -An -t u4 -j 12 -N 4 $(BUILD)/vmlinuz | tr -d ' '); \
		echo "unwrapping EFI zboot image (payload at $$off, $$size bytes)"; \
		tail -c +$$((off + 1)) $(BUILD)/vmlinuz | head -c $$size | gunzip > $(BUILD)/vmlinuz.tmp && \
		mv $(BUILD)/vmlinuz.tmp $(BUILD)/vmlinuz; \
	fi

# x86_64's kernel unpacked for Firecracker, which boots an ELF vmlinux
# as it is. Given the bzImage instead, it waits while the bzImage's own stub
# gunzips its 39 MB: on bare-metal KVM, start to werewolf up took 0.35 s
# against 0.25 s with this. The setup header gives the gzipped payload: the
# setup sectors at 0x1f1 (0 meaning 4), then the payload's offset from the
# end of setup and its length, little-endian u32s at 0x248 and 0x24c.
$(BUILD)/vmlinux: $(BUILD)/vmlinuz
	sects=$$(od -An -t u1 -j 497 -N 1 $< | tr -d ' '); [ "$$sects" != 0 ] || sects=4; \
		off=$$(od -An -t u4 -j 584 -N 4 $< | tr -d ' '); \
		len=$$(od -An -t u4 -j 588 -N 4 $< | tr -d ' '); \
		tail -c +$$(( (sects + 1) * 512 + off + 1 )) $< | head -c $$len | gunzip > $@.tmp && \
		[ "$$(head -c 4 $@.tmp | od -An -t x1 | tr -d ' ')" = 7f454c46 ] && mv $@.tmp $@

# Decompressed here: Alpine's kernel cannot (MODULE_DECOMPRESS is off), and
# the loader hands it each file as it is. The initramfs is compressed whole.
# modules.tar for werewolf's own stage0, modules-bitten.tar for bite's.
$(OUT)/modules.tar: STAGE0_MODULES = $(NATIVE_MODULES)
$(OUT)/modules-bitten.tar: STAGE0_MODULES = $(MODULES)
$(OUT)/modules.tar $(OUT)/modules-bitten.tar: $(BUILD)/vmlinuz $(FORM_FILES) Makefile
	rm -rf $(@:.tar=)
	kver=$$(ls $(BUILD)/kernel/x/lib/modules); \
	src=$(BUILD)/kernel/x/lib/modules/$$kver; \
	dst=$(@:.tar=)/usr/lib/modules/$$kver; \
	mkdir -p $$dst && : > $$dst/all && \
	for m in $(STAGE0_MODULES); do \
		case $$m in @*) tag="$${m%%:*} " n=$${m#*:} ;; *) tag= n=$$m ;; esac; \
		paths=$$(awk -v m="$$n" '$$1 ~ ("/" m "\\.ko\\.gz:$$") { sub(":", "", $$1); for (i = NF; i >= 1; i--) print $$i }' $$src/modules.dep); \
		[ -n "$$paths" ] || { echo "module $$n not in $$src/modules.dep" >&2; exit 1; }; \
		echo "$$paths" | sed "s|^|$$tag|" >> $$dst/all; \
	done && \
	awk 'NR == FNR { if (NF == 1) base[$$1] = 1; next } \
		NF == 1 ? !seen[$$0]++ : !($$2 in base) && !seen[$$0]++' $$dst/all $$dst/all > $$dst/all.gz && rm $$dst/all && \
	sed 's/\.gz$$//' $$dst/all.gz | awk -v params='$(MODULE_PARAMS)' ' \
		BEGIN { n = split(params, p, " "); for (i = 1; i <= n; i++) { c = index(p[i], ":"); \
			m = substr(p[i], 1, c - 1); want[m] = want[m] " " substr(p[i], c + 1) } } \
		{ m = $$0; sub(".*/", "", m); sub("\\.ko$$", "", m); if (m in want) { $$0 = $$0 want[m]; delete want[m] } print } \
		END { for (m in want) { printf "module parameters for %s, which the form does not carry\n", m > "/dev/stderr"; exit 1 } }' \
		> $$dst/werewolf.modules && \
	for p in $$(awk '{ print $$NF }' $$dst/all.gz | sort -u); do mkdir -p $$dst/$$(dirname $$p) && gunzip -c $$src/$$p > $$dst/$${p%.gz}; done && \
	rm $$dst/all.gz
	$(call layer,$(@:.tar=))

# Under DEV, busybox-full brings the shell, a package of the config, under
# FREEZE pinned by the -dev lock ($(FORM_LOCK)) like the rest.
$(OUT)/rootfs.tar: $(FORM_LOCK) $(FORM_APKO)
	$(call apko_build,$(FORM_APKO),$<)

# werewolf's own files: each form's rootfs along the chain, then meta.
$(OUT)/overlay.tar: $(OUT)/meta.stamp $(OUT)/ro.stamp $(call rootfs_find,-type f) $(PROGRAM_BINS) $(BITE_CLEANUP) $(LOADER_BIN) $(NET_BIN) $(FENCE_BIN) $(MOUNT_BIN) $(BROKER_BIN) $(POSTURE_BIN) $(INIT_BIN) $(SEAL_BINS) $(SHELLFREE_BINS)
	$(call layer,$(OVERLAY_DIRS) $(OUT)/meta)

# Booted directly, the machine boots as a slot does, through stage0, onto
# the same root.erofs, read-only: the slot's stage0, then a second cpio
# holding root.erofs, which the kernel unpacks after it and stage0 mounts.
# The cpio is made from a tar, as every image is: a cpio made from the file
# would carry its inode and device numbers on this host, and two builds of
# the same release would differ.
$(OUT)/initramfs.zst: $(OUT)/slot/stage0.zst $(OUT)/slot/root.erofs
	@[ "$(firstword $(CHAIN))" = minimal ] || \
		{ echo "form $(FORM) does not include minimal, which carries /init" >&2; exit 1; }
	rm -rf $(OUT)/direct && mkdir -p $(OUT)/direct && cp $(OUT)/slot/root.erofs $(OUT)/direct/ && \
		TZ=UTC touch -t 197001010000 $(OUT)/direct/root.erofs && \
		(cd $(OUT)/direct && COPYFILE_DISABLE=1 $(TAR) -cf - --format ustar --uid 0 --gid 0 --numeric-owner \
			--no-xattrs --no-acls --no-fflags root.erofs) | \
		$(TAR) -cf - --format newc @- | zstd -1 -q -c > $(OUT)/direct.cpio.zst && \
		cat $(OUT)/slot/stage0.zst $(OUT)/direct.cpio.zst > $@
	rm -rf $(OUT)/direct $(OUT)/direct.cpio.zst
	@echo "form $(FORM): $(CHAIN)"
	@ls -la $(BUILD)/vmlinuz $@

# What a read-only root needs that a form cannot spell out by hand: each
# service's supervise directory, along the chain, as a link into
# /run/runit, and apko's accounts, from which init seeds /run/werewolf
# (the image's /etc/passwd, group and shadow link there). Alpine's old
# accounts sync, shutdown, halt and operator have root's group, which
# reads /etc/shadow: they get nogroup, so only root has gid 0 (posture's
# files-accounts). And the form's allowances, an empty file each in
# etc/werewolf/allow; its sshd: keywords, as etc/ssh/sshd_config.d/form.conf,
# which sshd reads before the policy; and, where the chain has the bastion,
# its users, as etc/ssh/bastion/authorized_keys and permit-open (lib/sshd.zig),
# and its service file, connecting where its net says (lib/form.zig).
# A layer of the overlay, so the updater carries it forward too.
# The etc/sv directories are prerequisites too: a service removed or renamed
# changes nothing else Make can see, and its supervise link would stay.
$(OUT)/ro.stamp: $(OUT)/rootfs.tar $(shell find $(ROOTFS_DIRS) \( -type d \( -path '*/etc/sv' -o -path '*/etc/sv/*' \) \) -o -path '*/etc/sv/sshd/service') $(FORM_FILES) Makefile
	rm -rf $(OUT)/ro && mkdir -p $(OUT)/ro/usr/share/werewolf/etc $(OUT)/ro/etc/werewolf/allow && \
	for a in $(ALLOW); do touch $(OUT)/ro/etc/werewolf/allow/$$a || exit 1; done && \
	s=$$($(FORM_TOOL) sshd $(FORM_REF)) && { [ -z "$$s" ] || { mkdir -p $(OUT)/ro/etc/ssh/sshd_config.d && \
		printf '%s\n' "$$s" > $(OUT)/ro/etc/ssh/sshd_config.d/form.conf; }; } && \
	$(if $(filter bastion,$(CHAIN)),mkdir -p $(OUT)/ro/etc/ssh/bastion && \
		$(FORM_TOOL) bastion-keys $(FORM_REF) > $(OUT)/ro/etc/ssh/bastion/authorized_keys && \
		$(FORM_TOOL) bastion-permit $(FORM_REF) > $(OUT)/ro/etc/ssh/bastion/permit-open && \
		mkdir -p $(OUT)/ro/etc/sv/sshd && \
		$(FORM_TOOL) bastion-service $(FORM_REF) > $(OUT)/ro/etc/sv/sshd/service &&) \
	for f in passwd group shadow; do \
		$(TAR) -xOf $(OUT)/rootfs.tar etc/$$f > $(OUT)/ro/usr/share/werewolf/etc/$$f || exit 1; \
	done && \
	awk -F: -v OFS=: '$$3 != 0 && $$4 == 0 { $$4 = 65533 } { print }' $(OUT)/ro/usr/share/werewolf/etc/passwd \
		> $(OUT)/ro/usr/share/werewolf/etc/passwd.tmp && \
	mv $(OUT)/ro/usr/share/werewolf/etc/passwd.tmp $(OUT)/ro/usr/share/werewolf/etc/passwd && \
	for f in passwd group; do \
		awk -F: -v f=$$f 'n[$$1]++ || i[$$3]++ { printf "%s: %s or its id %s is there twice: a bundle'"'"'s forms disagree\n", f, $$1, $$3 > "/dev/stderr"; bad = 1 } END { exit bad }' \
			$(OUT)/ro/usr/share/werewolf/etc/$$f || exit 1; \
	done && \
	for s in $$(for c in $(ROOTFS_DIRS); do [ -d $$c/etc/sv ] && ls $$c/etc/sv; done | LC_ALL=C sort -u); do \
		mkdir -p $(OUT)/ro/etc/sv/$$s && ln -s /run/runit/supervise.$$s $(OUT)/ro/etc/sv/$$s/supervise || exit 1; \
	done
	touch $@

# --- zig ----------------------------------------------------------------------
define zig_check
@[ "$$(zig version)" = "$(ZIG_VERSION)" ] || \
	{ echo "$< is written for zig $(ZIG_VERSION), not $$(zig version)" >&2; exit 1; }
mkdir -p $(dir $@)
endef

# A program is cmd/NAME/NAME.zig, or a form's forms/F/cmd/NAME/NAME.zig,
# and the files beside it, and may import
# lib/sandbox.zig as "sandbox", lib/broker.zig, the mount broker's client,
# as "broker", lib/dm.zig, the device mapper, as "dm", lib/verity.zig,
# dm-verity's hash tree, as "verity", lib/seal.zig, what the seal's
# programs share, as "seal", lib/settings.zig, a service's declared
# settings, as "settings", lib/update-policy.zig, when a staged update
# boots, as "update-policy", lib/network.zig, a config tar's static
# network, as "network", lib/form.zig, a form's files (howl's), as
# "form", lib/audit.zig, the kernel's audit of refused execs, as "audit",
# lib/service.zig, a service file, as "service", lib/allow.zig, a form's
# allowances and root's capabilities, as "allow", lib/cve.zig, the CVE
# sources as the tiers feed and the updater read them, as "cve", and
# lib/cmdline.zig, the kernel command line's werewolf.* words, as
# "cmdline", and lib/sshd.zig, what form.yaml writes into sshd, as "sshd",
# compiled with them, as ReleaseSafe as it is. A library may
# import another, as its --dep says (LIB_MODULES).
LIB_MODULES = --dep seal -Msandbox=lib/sandbox.zig -Mbroker=lib/broker.zig -Mdm=lib/dm.zig \
	-Mverity=lib/verity.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig \
	-Mupdate-policy=lib/update-policy.zig -Mnetwork=lib/network.zig -Mhostkey=lib/hostkey.zig \
	--dep allow --dep sshd -Mform=lib/form.zig --dep seal -Maudit=lib/audit.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mallow=lib/allow.zig -Mcve=lib/cve.zig \
	--dep network -Mcmdline=lib/cmdline.zig --dep settings -Msshd=lib/sshd.zig
ZIG_MODULES = --dep sandbox --dep broker --dep dm --dep verity --dep seal --dep settings \
	--dep update-policy --dep network --dep hostkey --dep form --dep audit --dep service \
	--dep allow --dep cve --dep cmdline --dep sshd -Mroot=$(1) $(LIB_MODULES)

define zig_build
$(zig_check)
zig build-exe -O ReleaseSafe -fstrip -target $(ARCH)-linux-musl $(call ZIG_MODULES,$<) -femit-bin=$@
endef

# program NAME, BINARY, DIR: the rule that builds DIR, cmd/NAME unless
# given, into BINARY.
define program
$(2): $(or $(3),cmd/$(1))/$(1).zig $$(wildcard $(or $(3),cmd/$(1))/*.zig) $$(wildcard lib/*.zig)
	$$(zig_build)
endef
$(foreach p,dhcp-client cloud-metadata service-config sshd-start mount mount-broker modload iface-up fence posture slot-update $(SEAL_PROGRAMS) $(SHELLFREE),\
	$(eval $(call program,$(p),$(call program_bin,$(p)))))
$(foreach c,$(sort $(patsubst %/,%,$(wildcard forms/*/cmd/*/)) $(FORM_OWN_PROGRAMS)),\
	$(eval $(call program,$(notdir $(c)),$(call form_bin,$(c)),$(c))))
$(eval $(call program,bite-cleanup,$(BITE_CLEANUP)))
$(eval $(call program,init,$(INIT_BIN)))
$(eval $(call program,stage0,$(STAGE0_BIN)))

# popen-shim.so, which pg-init preloads into initdb in place of a shell,
# built against glibc, as initdb is.
$(call program_bin,popen-shim.so): cmd/popen-shim/popen-shim.zig
	$(zig_check)
	zig build-lib -dynamic -O ReleaseSafe -fstrip -target $(ARCH)-linux-gnu -lc -femit-bin=$@ $<

# Each library's and tool's tests from its own file, and each program's,
# with the modules it is built with; popen-shim's need libc, as it does. A
# suite is a target of its own, _test/FILE, so `make -j test` runs them
# side by side: each compiles for seconds, and CI has the cores.
PROGRAM_SOURCES = $(foreach d,$(wildcard cmd/* forms/*/cmd/*),$(d)/$(notdir $(d)).zig)
TEST_SOURCES = lib/sandbox.zig lib/seal.zig lib/dm.zig lib/verity.zig lib/settings.zig \
	lib/update-policy.zig lib/network.zig lib/cmdline.zig lib/hostkey.zig lib/audit.zig \
	lib/form.zig lib/allow.zig lib/service.zig lib/cve.zig lib/sshd.zig tools/form.zig boot/gpt.zig \
	tools/cve-tiers.zig tools/kernel-config-check.zig tools/test-sk.zig $(PROGRAM_SOURCES)
test: $(addprefix _test/,$(TEST_SOURCES)) _test/howl-smoke
	@echo "test: $(words $(TEST_SOURCES)) suites passed, and howl's lines"
_test/lib/sandbox.zig:
	zig test --dep seal -Mroot=lib/sandbox.zig -Mseal=lib/seal.zig
_test/lib/cmdline.zig:
	zig test --dep network -Mroot=lib/cmdline.zig -Mnetwork=lib/network.zig
_test/lib/audit.zig:
	zig test --dep seal -Mroot=lib/audit.zig -Mseal=lib/seal.zig
_test/lib/form.zig:
	zig test --dep allow --dep sshd -Mroot=lib/form.zig -Mallow=lib/allow.zig --dep settings \
		-Msshd=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/sshd.zig:
	zig test --dep settings -Mroot=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/service.zig:
	zig test --dep seal --dep settings -Mroot=lib/service.zig -Mseal=lib/seal.zig \
		-Msettings=lib/settings.zig
_test/tools/form.zig:
	zig test $(FORM_TOOL_MODULES)
_test/tools/cve-tiers.zig:
	zig test $(call ZIG_MODULES,tools/cve-tiers.zig)
_test/cmd/popen-shim/popen-shim.zig:
	zig test cmd/popen-shim/popen-shim.zig -lc
_test/tools/test-sk.zig:
	zig test tools/test-sk.zig -lc
_test/cmd/%.zig:
	zig test $(call ZIG_MODULES,cmd/$*.zig)
_test/forms/%.zig:
	zig test $(call ZIG_MODULES,forms/$*.zig)
_test/%.zig:
	zig test $*.zig

# The lines the README and the docs advertise, run as a user runs them, as
# far as a line goes with nothing built or booted: -h and -n. A regression
# in how the verbs take a form shows here, not on someone's first try.
.PHONY: _test/howl-smoke
_test/howl-smoke: build/host/howl
	@fail() { echo "howl-smoke: $$1"; exit 1; }; \
	$(HOWL) run -h >/dev/null 2>&1 || fail "howl run -h"; \
	$(HOWL) run -n 2>&1 | grep -q 'as it is' || fail "howl run -n should name its environment's form"; \
	$(HOWL) run --on qemu -n 2>&1 | grep -q 'prod-ssh as it is' || fail "howl run --on qemu -n should be prod-ssh"; \
	$(HOWL) run --on qemu -h >/dev/null 2>&1 || fail "howl run --on qemu -h"; \
	$(HOWL) create smoke --with prod -h >/dev/null 2>&1 || fail "howl create smoke --with prod -h"; \
	$(HOWL) pack --with prod -h >/dev/null 2>&1 || fail "howl pack --with prod -h"; \
	out=$$($(HOWL) run --with caddy,valkey -n 2>&1) || fail "howl run --with caddy,valkey -n: $$out"; \
	echo "$$out" | grep -q 'with: \[caddy, valkey\]' || fail "run --with caddy,valkey -n did not show the form: $$out"; \
	out=$$($(HOWL) run --with caddy -n 2>&1) || fail "howl run --with caddy -n: $$out"; \
	echo "$$out" | grep -q 'as it is' || fail "one form alone should run as it is: $$out"; \
	rm -rf $(BUILD)/adhoc/smoke; \
	$(HOWL) form --with caddy --package curl -o $(BUILD)/adhoc/smoke -n >/dev/null 2>&1 || fail "howl form -n"; \
	[ ! -e $(BUILD)/adhoc/smoke ] || fail "form -n left $(BUILD)/adhoc/smoke"; \
	! $(HOWL) run caddy >/dev/null 2>&1 || fail "howl run caddy (a positional form) was taken"; \
	echo "howl-smoke: the advertised lines take their forms"

# posture (docs/posture.md) assumes nothing of werewolf: run here, as root,
# it says how this Linux, whatever its distribution, protects itself. Built
# elsewhere, or for another ARCH, it is a static binary to copy over.
posture: $(POSTURE_BIN)
ifeq ($(HOST_OS)-$(HOST_ARCH),Linux-$(ARCH))
	$(if $(filter 0,$(shell id -u)),,sudo) $(POSTURE_BIN)
else
	@echo "$(POSTURE_BIN): copy it to a Linux $(ARCH) machine and run it there, as root"
endif

# --- meta ---------------------------------------------------------------------
# What the build knows that the image will need to rebuild itself: the
# update in forms/prod rebuilds a slot as `make slot` does, from these.
# In every image, in /usr/share/werewolf. Nothing here says when or where it
# was built, so a rebuild matches.
$(OUT)/meta.stamp: $(OUT)/ro.stamp $(OUT)/rootfs.tar $(BUILD)/kernel/rootfs.tar $(STAGE0_BIN) $(FORM_FILES) $(call rootfs_find,-type f) $(PROGRAM_BINS) $(BITE_CLEANUP) $(LOADER_BIN) $(NET_BIN) $(FENCE_BIN) $(MOUNT_BIN) $(BROKER_BIN) $(POSTURE_BIN) $(INIT_BIN) $(SEAL_BINS) $(SHELLFREE_BINS) release/image.pub release/tiers.pub release/advisories test/posture-known Makefile
	rm -rf $(OUT)/meta
	d=$(OUT)/meta/usr/share/werewolf && mkdir -p $$d $(OUT)/meta/etc/apk && \
	kernel=$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(linux-virt-[^/]*\)\.apk".*|\1|p' $(LOCK)/kernel.lock.json) && \
	echo $(FORM) > $$d/form && \
	for m in $(NATIVE_MODULES); do echo $$m; done > $$d/modules && \
	for m in $(BITTEN_MODULES); do echo $$m; done > $$d/modules-bitten && \
	{ for p in $(PRUNE); do echo $$p; done; } > $$d/prune && \
	{ $(FORM_TOOL) excuses $(FORM_REF) && for id in $(POSTURE_KNOWN_KIND); do \
		echo "$$id $(if $(DEV),a DEV=1 build: busybox-full and the debug shell,every form on $(ARCH) (test/posture-known))"; \
	done; } > $$d/weaknesses && \
	$(FORM_TOOL) pledge $(FORM_REF) > $$d/pledge && \
	$(FORM_TOOL) oci $(FORM_REF) > $$d/oci && { [ -s $$d/oci ] || rm $$d/oci; } && \
	$(if $(DEV),echo dev > $$d/dev &&) \
	for p in $(MODULE_PARAMS); do echo "$${p%%:*} $${p#*:}"; done > $$d/module-params && \
	echo $(KERNEL_ARGS) > $$d/cmdline && \
	echo $$kernel > $$d/kernel && \
	$(TAR) -xOf $(BUILD)/kernel/rootfs.tar etc/apk/repositories > $$d/alpine && \
	for c in $(OVERLAY_DIRS); do (cd $$c && find . \( -type f -o -type l \) ! -name .DS_Store | sed 's|^\./||'); done | LC_ALL=C sort -u > $$d/overlay && \
	$(TAR) -xOf $(OUT)/rootfs.tar etc/apk/world | grep -v = > $(OUT)/meta/etc/apk/world && \
	cp $(STAGE0_BIN) $$d/stage0.init && \
	echo "$(FORM) $$kernel built-by-make" > $$d/release && \
	cp release/image.pub $$d/image.pub && \
	cp release/tiers.pub $$d/tiers.pub && echo $(TIERS_URL) > $$d/tiers && \
	cp release/advisories $$d/advisories && \
	$(if $(and $(filter $(FORM),$(RELEASE_FORMS)),$(if $(DEV),,y)),echo $(RELEASES_URL) > $$d/releases &&) \
	$(TAR) -xOf $(OUT)/rootfs.tar etc/passwd > $(OUT)/passwd && \
	$(FORM_TOOL) list $(FORM_REF) net > $(OUT)/net.lines && \
	awk -v pw=$(OUT)/passwd ' \
		FILENAME == pw { split($$0, a, ":"); uid[a[1]] = a[3]; next } \
		{ c = index($$0, sprintf("%c", 35)); if (c) $$0 = substr($$0, 1, c - 1) } \
		NF == 0 { next } \
		$$1 == "listen" && NF > 1 { last = NF; lo = ""; if ($$NF == "loopback") { last = NF - 1; lo = " loopback" }; if (last < 2) bad(); \
			for (i = 2; i <= last; i++) { \
			if ($$i !~ /^tcp\/[0-9]+$$/ || substr($$i, 5) + 0 < 1 || substr($$i, 5) + 0 > 65535) bad(); \
			print "listen tcp " substr($$i, 5) + 0 lo } next } \
		$$1 == "metadata" && NF > 1 { for (i = 2; i <= NF; i++) { if (!($$i in uid)) bad(); print "metadata " uid[$$i] } next } \
		$$1 == "connect" && NF > 2 { who = $$2 == "all" ? "all" : ($$2 in uid ? uid[$$2] : bad()); \
			last = NF; pub = ""; if ($$NF == "public") { last = NF - 1; pub = " public" }; if (last < 3) bad(); \
			for (i = 3; i <= last; i++) { \
				if ($$i == "icmp") { if (pub != "") bad(); print "connect " who " icmp"; continue } \
				if ($$i !~ /^(tcp|udp)\/[0-9]+$$/ || substr($$i, 5) + 0 < 1 || substr($$i, 5) + 0 > 65535) bad(); \
				print "connect " who " " substr($$i, 1, 3) " " substr($$i, 5) + 0 pub } next } \
		{ bad() } \
		function bad() { printf "form $(FORM): form.yaml'"'"'s net cannot compile: %s\n", $$0 > "/dev/stderr"; exit 1 }' \
		$(OUT)/passwd $(OUT)/net.lines > $(OUT)/net && \
	LC_ALL=C sort -u $(OUT)/net > $$d/net && rm $(OUT)/net $(OUT)/net.lines $(OUT)/passwd
	touch $@

# --- disk ---------------------------------------------------------------------
# werewolf's own boot disk (docs/design/native-boot.md): GPT, an EFI partition
# holding systemd-boot and slot a's kernel and stage0, and an ext4 partition
# holding slot a's root.erofs, laid out as bite leaves a distro's. UEFI
# firmware boots it anywhere, and a form that includes prod updates itself
# there as on a machine bite installed. systemd-boot comes from Wolfi,
# pinned by a lock like the kernel's; the partition table is written by
# boot/gpt.zig, built for this host. DISK_MIB is the disk's size;
# DISK_ARGS go on the kernel command line, and updates carry them over.
DISK ?= $(OUT)/disk.img
DISK_MIB ?= 8192
DISK_ARGS ?=
GPT_BIN = build/host/gpt

$(LOCK)/boot.lock.json: boot/boot.yaml
	$(call apko_lock,$<)

$(BUILD)/boot/rootfs.tar: $(LOCK)/boot.lock.json
	$(call apko_build,boot/boot.yaml,$<)

$(GPT_BIN): boot/gpt.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -femit-bin=$@ $<

$(KERNEL_CONFIG_CHECK): tools/kernel-config-check.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -femit-bin=$@ $<

VERITY_BIN = build/host/verity
$(VERITY_BIN): tools/verity.zig lib/verity.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep verity -Mroot=$< -Mverity=lib/verity.zig -femit-bin=$@

# The CVE tiers feed (docs/design/update-policy.md), which CI builds, signs
# and publishes with release/tiers; here, for the kernel the lock pins, into
# build/tiers/cve-tiers.json, unsigned. NVD's scores stay in build/tiers/nvd,
# so a second run asks NVD only for what changed. The key never reaches the
# command line make prints.
CVE_TIERS_BIN = build/host/cve-tiers
NVD_API_KEY_FILE ?= $(HOME)/.tok/werewolf-nvd
.PHONY: cve-tiers
$(CVE_TIERS_BIN): tools/cve-tiers.zig lib/cve.zig lib/update-policy.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$@

cve-tiers: $(CVE_TIERS_BIN) $(LOCK)/kernel.lock.json
	mkdir -p build/tiers && FORM_TOOL=$(FORM_TOOL) release/origins build/tiers/origins
	@kernel=$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(linux-virt-[^/]*\)\.apk".*|\1|p' $(LOCK)/kernel.lock.json) && \
	NVD_API_KEY=$${NVD_API_KEY:-$$(cat $(NVD_API_KEY_FILE))} \
	$(CVE_TIERS_BIN) "$$kernel" build/tiers/origins build/tiers/nvd build/tiers/in build/tiers/cve-tiers.json

# The howl command (cmd/howl), built for this machine, not the image.
.PHONY: howl
howl: $(HOWL)
$(HOWL): cmd/howl/howl.zig $(wildcard cmd/howl/*.zig) lib/settings.zig lib/update-policy.zig \
	lib/network.zig lib/form.zig lib/allow.zig lib/service.zig lib/seal.zig
	$(zig_check)
	@# Beside it, then renamed over it: a build while werewolf runs (a
	@# check rebuilds it) never leaves an empty file, which a shell would run
	@# as an empty script, exiting 0 having done nothing. Beside it under a
	@# name of its own, the shell's pid, so two builds at once do not write
	@# one file.
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@

# A security key in software (tools/test-sk.zig), for make check alone: the
# OpenSSH provider its keys are made and used with, so a check logs in to
# a machine that takes security keys alone. This host's, never an image's.
TEST_SK = build/host/test-sk.so
$(TEST_SK): tools/test-sk.zig
	$(zig_check)
	t=$@.$$$$ && zig build-lib -dynamic -O ReleaseSafe -lc -femit-bin=$$t $< && mv -f $$t $@

# The howl command on your PATH: in the first of ~/bin, ~/.local/bin and
# /usr/local/bin that is on it and yours to write, or else in
# ~/.local/bin, made, with a word that it is not on your PATH. Beside the
# old one, then renamed over it, as above. It reads ./forms and runs make,
# so it runs in a werewolf checkout, as build/host/howl does. The command
# was called werewolf once: one of those that make install put there goes.
# First it installs what the build needs and is missing (install-deps,
# which does nothing when nothing is), before howl builds, as Zig builds
# it: an order-only prerequisite, so make -j keeps that order too.
INSTALL_DIRS = $(HOME)/bin $(HOME)/.local/bin /usr/local/bin
$(HOWL): | $(if $(filter install,$(MAKECMDGOALS)),install-deps)
install: install-deps $(HOWL)
	@set -e; bindir=; \
	for d in $(INSTALL_DIRS); do \
		if echo "$$PATH" | tr ':' '\n' | grep -qx "$$d" && [ -d "$$d" ] && [ -w "$$d" ]; then bindir=$$d; break; fi; \
	done; \
	if [ -z "$$bindir" ]; then \
		bindir=$(HOME)/.local/bin; mkdir -p "$$bindir"; \
		echo "install: $$bindir is not on your PATH; add it"; \
	fi; \
	install -m 755 $(HOWL) "$$bindir/howl.new" && mv -f "$$bindir/howl.new" "$$bindir/howl"; \
	echo "installed $$bindir/howl"; \
	for d in $(INSTALL_DIRS); do \
		[ -x "$$d/werewolf" ] && "$$d/werewolf" 2>&1 | grep -q 'usage: werewolf build FORM' && \
			rm -f "$$d/werewolf" && echo "removed $$d/werewolf, as howl was once called"; \
	done; true

# Removes what make install put there: a howl that answers as this one
# does, never another program of the name.
uninstall:
	@for d in $(INSTALL_DIRS); do \
		[ -x "$$d/howl" ] || continue; \
		if "$$d/howl" 2>&1 | grep -q 'usage: howl build FORM'; then \
			rm -f "$$d/howl" && echo "removed $$d/howl"; \
		else echo "uninstall: $$d/howl is another program; left it"; fi; \
	done

disk: $(DISK)

DISK_INPUTS = $(OUT)/slot/vmlinuz $(OUT)/slot/stage0.zst $(OUT)/slot/root.erofs $(OUT)/slot/cmdline \
	$(BUILD)/boot/rootfs.tar $(GPT_BIN) boot/mkdisk

$(DISK): $(DISK_INPUTS)
	boot/mkdisk $(ARCH) $(BUILD)/boot/rootfs.tar $(GPT_BIN) $(OUT)/slot $@ $(DISK_MIB) $(DISK_ARGS)

# The disk a release publishes (docs/releases.md): made afresh, never with
# DISK_ARGS, as compressed qcow2. zlib is named rather than left to
# qemu-img's default, which a later qemu-img may change.
$(OUT)/disk.qcow2: $(DISK_INPUTS)
	boot/mkdisk $(ARCH) $(BUILD)/boot/rootfs.tar $(GPT_BIN) $(OUT)/slot $(OUT)/disk.raw $(DISK_MIB)
	qemu-img convert -f raw -O qcow2 -c -o compression_type=zlib $(OUT)/disk.raw $@
	rm -f $(OUT)/disk.raw

# --- slot ---------------------------------------------------------------------
# The same rootfs, booted from disk: a small stage0 initramfs that loads the
# modules and mounts root.erofs read-only at / (cmd/stage0/stage0.zig).
# This is what bite installs, and what the updater rebuilds on the machine.
# root.erofs is made straight from the tar, as the cpio is; the modules stay
# in stage0, since they are loaded before the root exists.
slot: $(OUT)/slot/vmlinuz $(OUT)/slot/stage0.zst $(OUT)/slot/stage0-bitten.zst $(OUT)/slot/root.erofs $(OUT)/slot/cmdline
	@ls -la $(OUT)/slot

# The kernel arguments the image asks for, beside it, for bite and
# boot/mkdisk to boot it with: the same as its /usr/share/werewolf/cmdline.
$(OUT)/slot/cmdline: $(OUT)/meta.stamp
	mkdir -p $(dir $@)
	cp $(OUT)/meta/usr/share/werewolf/cmdline $@

$(BUILD)/stage0/init.tar: $(STAGE0_BIN) $(LOADER_BIN)
	rm -rf $(BUILD)/stage0/files && mkdir -p $(BUILD)/stage0/files/usr/lib/werewolf && \
		cp $(STAGE0_BIN) $(BUILD)/stage0/files/init && cp $(LOADER_BIN) $(BUILD)/stage0/files/usr/lib/werewolf/
	$(call layer,$(BUILD)/stage0/files)

# stage0's /verity: what it opens this form's root.erofs with, made with it.
$(OUT)/verity.tar: $(OUT)/slot/root.erofs
	$(call layer,$(OUT)/verity)

# stage0, werewolf's own and bite's (BITTEN_TAGS): the same but for the
# modules. No packages: /dev's nodes (cmd/stage0/stage0.mtree), /init and
# the loader, the modules and /verity are all it holds.
$(OUT)/slot/stage0.zst: $(OUT)/modules.tar
$(OUT)/slot/stage0-bitten.zst: $(OUT)/modules-bitten.tar
$(OUT)/slot/stage0.zst $(OUT)/slot/stage0-bitten.zst: cmd/stage0/stage0.mtree $(BUILD)/stage0/init.tar $(OUT)/verity.tar
	mkdir -p $(dir $@)
	$(TAR) -cf $(@:.zst=.cpio) --format newc --uid 0 --gid 0 --numeric-owner \
		@cmd/stage0/stage0.mtree @$(BUILD)/stage0/init.tar @$(filter %modules.tar %modules-bitten.tar,$^) @$(OUT)/verity.tar
	zstd -19 -T0 -q -f -o $@ $(@:.zst=.cpio)
	rm $(@:.zst=.cpio)

# zstd in 64 KiB clusters, with small files packed together and duplicates
# kept once: what a boot waits on least. Every file a boot first reads
# costs at least a cluster's decompression, through dm-verity, before the
# page cache holds it, and a boot first reads most of what it runs. Booted
# under Lima (the lima form, 2 vCPUs), userland took 0.36 s, against 0.74 s
# in LZMA's 1 MiB clusters (smaller LZMA clusters were no faster); lz4hc
# was as fast and a quarter larger, and no compression no faster, at three
# times the size (57 MB, against this 19.7 MB and LZMA's 12.4). The update
# downloads the root as it is (docs/releases.md), so it stays compressed.
# Level 9 writes it in 7 s and level 19 in 88 s for 2 MB less; zstd reads
# as fast at any level. Homebrew's erofs-utils has no zstd, so
# tools/install-deps builds one that has. -b 4096 because mkfs.erofs
# otherwise takes the builder's page size, 16 KiB on Apple silicon, which a
# 4 KiB-page kernel will not mount. -T0 dates every file and the image
# 1970, and the UUID is fixed (stage0 finds the image by path), so a rebuild
# matches, on macOS as on Wolfi. erofs-utils before 1.9 (Ubuntu 24.04 has
# 1.7.1) take -Eall-fragments from a tar and write every file empty,
# without an error, so older ones are refused, as are ones without zstd.
#
# After the image, its dm-verity hash tree, which stage0 opens it through,
# with the root hash and salt tools/verity writes to $(OUT)/verity/verity
# for stage0's /verity (lib/verity.zig, the same tree veritysetup makes).
EROFS_OPTS = -b 4096 -zzstd,level=9 -C65536 -Eall-fragments,dedupe
$(OUT)/slot/root.erofs: $(OUT)/rootfs.tar $(OUT)/overlay.tar $(VERITY_BIN) $(FORM_FILES)
	mkdir -p $(dir $@)
	@# The root directory itself, first: without an entry for it, mkfs.erofs
	@# gives / the builder's uid and mode 0777, which sshd's StrictModes
	@# rightly refuses keys under.
	printf '#mtree\n./ type=dir uid=0 gid=0 uname=root gname=root mode=0755 time=0.0\n' >$(OUT)/root.mtree
	$(TAR) -cf $(OUT)/root.tar --uid 0 --gid 0 --numeric-owner $(foreach p,$(PRUNE),--exclude $(p)) @$(OUT)/root.mtree @$(OUT)/rootfs.tar @$(OUT)/overlay.tar
	rm -f $@
	@v=$$(mkfs.erofs --version 2>/dev/null | sed -n 's/.*erofs-utils) *//p'); case $$v in '' | 1.[0-8] | 1.[0-8].*) \
		echo "mkfs.erofs $${v:-before 1.9}: 1.9 or later is needed; older ones write an image of empty files" >&2; exit 1 ;; esac
	@{ mkfs.erofs --version; mkfs.erofs --help; } 2>&1 | grep -q 'available compressors:.*zstd' || \
		{ echo "mkfs.erofs has no zstd: make install-deps builds an erofs-utils with it" >&2; exit 1; }
	mkfs.erofs $(EROFS_OPTS) -T0 -U 00000000-0000-0000-0000-000000000000 --tar=f $@ $(OUT)/root.tar >/dev/null
	rm $(OUT)/root.tar $(OUT)/root.mtree
	mkdir -p $(OUT)/verity && $(VERITY_BIN) $@ $(OUT)/verity/verity

# The slot's kernel as Alpine ships it, not $(BUILD)/vmlinuz: on aarch64
# an EFI zboot image, 10 MB to the raw Image's 36. A UEFI machine's
# firmware reads it from the disk on every boot, and on GCP the raw one
# cost 0.55 s more a boot (4.32 s against 3.76 s from reboot to the
# kernel's start, eight boots on two machines each). systemd-boot runs it
# and its EFI stub unpacks it; QEMU takes it as it is; GRUB cannot, so
# bite and the updater give GRUB the Image inside. On x86_64 both are the
# same bzImage.
$(OUT)/slot/vmlinuz: $(BUILD)/vmlinuz
	mkdir -p $(dir $@)
	cp $(BUILD)/kernel/x/boot/vmlinuz-virt $@

# On the machine to take over: build its slot here and install it with
# bite -i, which opens a shell in the new root and then offers to reboot
# into it (docs/bite.md). prod-ssh by default, the form that can still be
# reached once it has taken over. config/, if there is one, joins the
# config tar. Refused before the build where it could not work.
ifneq ($(filter bite-me,$(MAKECMDGOALS)),)
ifneq ($(HOST_OS)-$(HOST_ARCH),Linux-$(ARCH))
$(error bite-me runs on the Linux $(ARCH) machine it takes over)
endif
endif
bite-me: slot
	$(if $(filter 0,$(shell id -u)),,sudo) ./bite -i $(if $(wildcard config/*),--config config) $(OUT)/slot

# --- release ------------------------------------------------------------------
# CI publishes these forms for both architectures (docs/releases.md). `make
# release-inputs` resolves their locks afresh and writes what the release would be
# built from: a digest of the files that build it, and every package's URL.
# CI builds only when that changes. `make dist` puts each form's files in
# dist/ as a release names them, with its manifest, unsigned.
RELEASE_FORMS = minimal prod prod-ssh
# minimal is published whole, for direct boot, with the kernel arguments its
# host passes; the rest as the slot the updater follows, and as a disk to
# boot a VM from.
DIST_DIRECT_FORMS = minimal
DIST_DIRECT = $(filter $(DIST_DIRECT_FORMS),$(FORM))
# Where a published form's updater finds its releases (docs/updater.md): the
# latest release's FORM-ARCH.json and files, which only a form built as it
# ships follows, not a DEV=1 build.
RELEASES_URL = https://github.com/werewolf-linux/werewolf/releases/latest/download/
# Where every form's updater finds the CVE tiers feed, signed with the key
# in release/tiers.pub (docs/design/update-policy.md).
TIERS_URL = https://raw.githubusercontent.com/werewolf-linux/cve-feed/main/
DIST = dist
# What a release is built from: the build, the forms, the boot configs,
# the programs, what they share, the keys the image trusts, and werewolf's
# own advisories, which the image carries.
RELEASE_SOURCES = Makefile melange.mk forms boot cmd lib tools/form.zig release/image.pub release/tiers.pub release/advisories

# Every lock a release is built from: each form's, the kernel's, and the
# boot disk's (systemd-boot, on each form's disk.qcow2), resolved again,
# each once and all at once: CI asks this every 15 minutes, so it is fast.
RELEASE_LOCKS = $(addprefix $(LOCK)/,$(addsuffix .lock.json,$(RELEASE_FORMS) kernel boot))
release-inputs:
	rm -f $(RELEASE_LOCKS)
	$(MAKE) --no-print-directory -j $(addprefix _lock/,$(RELEASE_FORMS)) $(LOCK)/kernel.lock.json $(LOCK)/boot.lock.json
	{ echo "tree $$(src='$(RELEASE_SOURCES)'; \
		{ find $$src -type f ! -name .DS_Store | LC_ALL=C sort | xargs $(SHA256); \
		  find $$src -type f -perm -100 | LC_ALL=C sort; } | $(SHA256) | cut -c1-64)"; \
	  sed -n 's|.*"url": "\([^"]*\.apk\)".*|\1|p' \
		$(RELEASE_LOCKS) | LC_ALL=C sort -u; \
	} > $(LOCK)/inputs
	@echo "inputs: $$($(SHA256) < $(LOCK)/inputs | cut -c1-16), $$(grep -c '^https' $(LOCK)/inputs) packages"
_lock/%:
	@$(MAKE) --no-print-directory FORM=$* $(LOCK)/$*.lock.json

# FREEZE=1: a release pins to the versions release-inputs resolved and
# digested above, so the two runners that build each architecture match byte
# for byte (docs/releases.md) and the published image is reproducible. Dev and
# CI builds stay unpinned (apko_build); only what is published is frozen.
dist:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FREEZE=1 FORM=$$f _dist-form || exit 1; done

_dist-form: $(if $(DIST_DIRECT),image $(OUT)/slot/cmdline,slot $(OUT)/disk.qcow2) $(OUT)/meta.stamp
	@# A DEV=1 build has a root shell on its console (cmd/debug-shell): never one to publish.
	@[ -z "$(DEV)" ] && [ ! -e $(OUT)/meta/usr/share/werewolf/dev ] || \
		{ echo "dist: refused: $(FORM) is a DEV=1 build, with a root shell on its console" >&2; exit 1; }
	release/manifest $(FORM) $(ARCH) $(OUT)/rootfs.tar $(OUT)/meta/usr/share/werewolf/kernel $(DIST) \
		$(if $(DIST_DIRECT),vmlinuz=$(BUILD)/vmlinuz initramfs.zst=$(OUT)/initramfs.zst cmdline=$(OUT)/slot/cmdline,vmlinuz=$(OUT)/slot/vmlinuz stage0.zst=$(OUT)/slot/stage0.zst stage0-bitten.zst=$(OUT)/slot/stage0-bitten.zst root.erofs=$(OUT)/slot/root.erofs cmdline=$(OUT)/slot/cmdline disk.qcow2=$(OUT)/disk.qcow2)

list-forms:
	@$(FORM_TOOL) tree

# --- config -------------------------------------------------------------------
# config/ is a directory you keep (gitignored); `make config-tar` packs it into a
# tar that is attached to the VM as a raw disk. init finds it by the ustar
# magic, so it can sit on any block device on any provider. See README for
# the files init honours.
config-tar: $(BUILD)/config.tar

# The directories are prerequisites too: deleting a file (data.key, say)
# changes nothing else Make can see, and the old tar would keep it. They are
# spelled config/. because `config` is the phony target above, and Make
# silently drops the cycle that name would make.
$(BUILD)/config.tar: $(shell find config/. -type d -o -type f 2>/dev/null)
	@test -d config || { echo "config/ is missing; see README" >&2; exit 1; }
	mkdir -p $(BUILD)
	COPYFILE_DISABLE=1 $(TAR) --uid 0 --gid 0 --numeric-owner --exclude .DS_Store -cf $@ -C config .

# --- QEMU ---------------------------------------------------------------------
# data.img is a sparse 8 GiB disk shared by every form of an arch, attached
# first so it is vda. It outlives `make run`, which is the point: delete it
# to start from a blank disk. Forms without mke2fs ignore it.
QEMU_CONFIG = $(if $(wildcard config),-drive file=$(BUILD)/config.tar$(,)format=raw$(,)if=virtio$(,)readonly=on)
, := ,

# dd's report goes to /dev/null, since NetBSD's dd has no status=none.
$(BUILD)/data.img:
	mkdir -p $(BUILD)
	dd if=/dev/zero of=$@ bs=1048576 count=0 seek=8192 2>/dev/null

# Given EL2, an aarch64 guest's kernel starts its built-in KVM unless told
# not to (kvm-arm.mode=none), so werewolf boots with EL2 wherever the host
# can lend it: TCG always, HVF on Apple M3 and later, KVM where the host
# nests. Then posture's kernel-no-hypervisor proves the argument works,
# rather than passing because no EL2 was there. QEMU, started paused and
# told to quit, says in milliseconds whether it can.
EL2 = $(if $(filter aarch64,$(ARCH)),$(shell echo quit | qemu-system-aarch64 -M virt,virtualization=on -accel $(ACCEL) -cpu $(CPU) -nodefaults -display none -monitor stdio -S >/dev/null 2>&1 && echo ,virtualization=on))
QEMU = qemu-system-$(ARCH) -M $(MACHINE)$(EL2) -accel $(ACCEL) -cpu $(CPU) -nographic

# The TCP ports the form serves, as its chain's net declares them
# (build/host/form listens): what run and check forward to it.
FORM_LISTENS := $(shell $(FORM_TOOL) listens $(FORM_REF))

# The machine's port that this host's 127.0.0.1:8080 reaches: the last one,
# but ssh's, its chain's net listens on (python's 8080, nginx's 80),
# or 80.
RUN_PORT ?= $(or $(lastword $(filter-out 22,$(FORM_LISTENS))),80)

# RUN_DIR=DIR, absolute, as howl run gives it: the machine in the
# background, its console on DIR/console.sock and in DIR/console.log, QEMU's
# monitor on DIR/monitor.sock and its pid in DIR/qemu.pid; make returns once
# QEMU has started. Without it, as ever: the console is this terminal's.
RUN_DIR ?=
# This host's ports that reach the machine's ssh and its RUN_PORT; werewolf
# run picks free ones when these are taken.
RUN_SSH_PORT ?= 2222
RUN_WEB_PORT ?= 8080
# The machine's /data: every make run's, or one of its own, as each machine
# werewolf keeps under QEMU has.
RUN_DATA ?= $(BUILD)/data.img
RUN_IO = $(if $(RUN_DIR),-display none -daemonize -pidfile $(RUN_DIR)/qemu.pid \
	-chardev socket$(,)id=con$(,)path=$(RUN_DIR)/console.sock$(,)server=on$(,)wait=off$(,)logfile=$(RUN_DIR)/console.log \
	-serial chardev:con -monitor unix:$(RUN_DIR)/monitor.sock$(,)server$(,)nowait)
run: image $(BUILD)/data.img $(if $(wildcard config),config-tar)
	$(if $(RUN_DIR),mkdir -p $(RUN_DIR) && rm -f $(RUN_DIR)/console.log $(RUN_DIR)/*.sock &&) \
	$(if $(RUN_DIR),$(subst -nographic,,$(QEMU)),$(QEMU)) $(RUN_IO) -smp 4 -m 2048 \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst \
		-append "console=$(CONSOLE) $(KERNEL_ARGS) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 werewolf.data=vda werewolf.debug=1" \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:$(RUN_SSH_PORT)-:22,hostfwd=tcp:127.0.0.1:$(RUN_WEB_PORT)-:$(RUN_PORT) -device virtio-net-pci,netdev=n0 \
		-device virtio-rng-pci -drive file=$(RUN_DATA),format=raw,if=virtio $(QEMU_CONFIG)

# No host key to check: this reaches only the port `run` forwards on this
# host's loopback (the machine keeps its key in /data, which run's disk holds).
run-ssh:
	ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1

# --- checks -------------------------------------------------------------------
# `make check` boots every form under QEMU, then a slot as bite leaves one,
# and runs test/checks on each as root on its console (test/boot). Each
# machine gets a blank disk and a config disk of its own, and nothing listens
# on the host, so `make -j check` runs them side by side. The config holds
# data.key, a fixed test key, so prod and the forms on it put /data in
# LUKS2, and what a form's services need (its test/config writes it: a
# bastion's key, OpenBao's unseal key, a CA). Builds and
# consoles are logged in build/<arch>/check/. See docs/testing.md. What
# a form's check needs beyond that is form.yaml's check: its own, never
# inherited (forms/README.md).
FORMS := $(patsubst forms/%/apko.yaml,%,$(wildcard forms/*/apko.yaml))
CHECK = $(BUILD)/check$(if $(SEAL_LEARN),-learn)
# Every form is checked as built with DEV=1, since test/checks needs a root
# shell on the console, and booted as it ships too (check-shellfree-%),
# where its posture may fail only as its form.yaml's weaknesses excuse.
CHECK_MAKE = $(MAKE) --no-print-directory DEV=1
SHELLFREE_FORMS = $(FORMS)
SHELLFREE_CHECKS = $(addprefix check-shellfree-,$(SHELLFREE_FORMS))
# romfile= because direct boot needs no network boot ROM, and CI has none.
# 1 GB keeps a form's memory honest, unless its check's memory says more
# (demo's grype holds its ~700 MB vulnerability database in memory while it
# scans). A form whose check is offline, a daemon that would reach its
# service on the Internet and exit when refused (cloudflared's tunnel, with
# a token the check cannot have), is checked with no way out
# (restrict=on): it keeps trying, which is what the check wants to see,
# and the host's ports still reach it.
CHECK_MEMORY := $(or $(call form_check,memory),1024)
CHECK_OFFLINE := $(if $(filter true,$(call form_check,offline)),$(,)restrict=on)
CHECK_QEMU = $(QEMU) -smp 2 -m $(CHECK_MEMORY) -no-reboot -device virtio-rng-pci \
	-netdev user,id=n0$(CHECK_OFFLINE) -device virtio-net-pci,netdev=n0,romfile=
# panic=1 with -no-reboot: a panic ends QEMU at once rather than hanging.
# werewolf.check=1 adds posture's attacks, which write to the kernel log.
# A check boot that stalls panics, so the run fails in seconds with the
# kernel's own reason (test/boot reports it), not a silent timeout: a CPU
# stalled 20 s (the kernel's default waits 60), a task blocked two minutes,
# or a soft lockup. Only here: a machine in use rides out a slow moment.
CHECK_STALLS = rcupdate.rcu_cpu_stall_timeout=20 sysctl.kernel.panic_on_rcu_stall=1 \
	sysctl.kernel.hung_task_timeout_secs=120 sysctl.kernel.hung_task_panic=1 sysctl.kernel.softlockup_panic=1
# SEAL_LEARN=1, as make seal-learn sets it: what no promise allows is
# allowed, and said with its promise (docs/design/pledge.md).
SEAL_ARGS = $(if $(SEAL_LEARN),werewolf.seal=learn)
CHECK_BOOT = console=$(CONSOLE) $(KERNEL_ARGS) panic=1 werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) $(SEAL_ARGS)
# The posture checks known to fail on every form of a kind, as
# test/posture-known says: a DEV=1 build's, or a shipped one's, and the
# architecture's.
POSTURE_KNOWN_KIND := $(shell awk -v b=$(if $(DEV),dev,*) -v a=$(ARCH) '$$1 == b || $$1 == a { $$1 = ""; k = k $$0 } END { print k }' test/posture-known)
# The posture checks known to fail on the form and architecture, for
# test/boot to expect: those, and the form's own weaknesses.
export POSTURE_KNOWN := $(POSTURE_KNOWN_KIND) $(shell $(FORM_ASK) weaknesses $(FORM_REF))
# The posture checks test/cage expects to fail in a container, beyond the
# kernel-* checks it allows by their area (the container shares the host's
# kernel; only kernel-seal and kernel-write-xor-execute, werewolf's own,
# set on PID 1, must hold there) and
# those POSTURE_KNOWN names for the form, what it carries by design. These
# are the rest a container cannot hold, nspawn's own mounts chief among
# them, all asserted in emulation. The host sysctls
# behind files-* checks test/cage judges by the host itself, raising them
# where it may (CAGE_HARDEN_HOST=1, CI's runners).
export POSTURE_KNOWN_NATIVE = files-root-readonly files-root-verity files-nosuid-everywhere files-noexec-everywhere files-nodev-everywhere files-nosymfollow-everywhere files-system-writes processes-mem-attack
CHECK_CMDLINE = $(CHECK_BOOT) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3
# What every form shares, built once before the forms build side by side.
CHECK_SHARED = $(BUILD)/vmlinuz $(BUILD)/stage0/init.tar $(ALL_PROGRAM_BINS) $(BITE_CLEANUP) $(LOADER_BIN) $(NET_BIN) $(FENCE_BIN) $(MOUNT_BIN) $(BROKER_BIN) $(POSTURE_BIN) $(INIT_BIN) $(SEAL_BINS) $(SHELLFREE_BINS)
# minimal has no updater, which would fetch from the network once committed.
CHECK_SLOT_FORM = minimal
VICTIM_UUID = 0e7e1f00-c4ec-4b00-8000-00000000c4ec
# debugfs, from e2fsprogs, which Homebrew keeps off the PATH.
DEBUGFS = $(firstword $(shell command -v debugfs) $(wildcard /opt/homebrew/opt/e2fsprogs/sbin/debugfs /usr/local/opt/e2fsprogs/sbin/debugfs))

# The suite splits into groups so CI (.github/workflows/check.yml) runs each
# as its own job, in parallel, and a failure names the area it is in. Each
# group is a target of its own: `make check-cloud` runs just those. `make
# check` runs them all, as before. SHARD=K/N runs the Kth of N slices of
# check-forms, check-shellfree and check-native, every Nth form from the
# Kth in name order, so CI splits each over N runners and every runner
# slices alike.
ifneq ($(SHARD),)
ifeq ($(shell echo '$(SHARD)' | awk -F/ '/^[1-9][0-9]*\/[1-9][0-9]*$$/ && $$1 <= $$2'),)
$(error SHARD=$(SHARD): K/N, the Kth of N, 1 <= K <= N)
endif
endif
shard = $(if $(SHARD),$(shell echo $(sort $(1)) | tr ' ' '\n' | \
	awk -F/ -v s=$(SHARD) 'BEGIN { split(s, a, "/") } (NR - 1) % a[2] == a[1] - 1'),$(1))
.PHONY: check-forms check-shellfree check-integrity check-cloud
check-forms:     $(addprefix check-,$(call shard,$(FORMS)))
check-shellfree: $(addprefix check-shellfree-,$(call shard,$(SHELLFREE_FORMS)))
check-integrity: check-slot check-unsigned check-verity check-deadman
# cloud takes the ad-hoc form too, which pulls its OCI image over the
# network as the others reach a metadata server; not on emulated arm64,
# where a full form's boot is too slow, as forms' are (check.yml).
check-cloud:     check-metadata check-nodata check-lease check-static $(if $(filter aarch64-tcg,$(ARCH)-$(ACCEL)),,check-adhoc)

check: check-forms check-shellfree check-integrity check-cloud check-persist
	@echo "check: every form, and a slot, passed"

# check-native boots each form's root under systemd-nspawn on this kernel --
# no virtual machine -- and judges its posture (test/cage). It is the fast
# half of the arm64 checks (.github/workflows/check.yml), where a full boot
# emulates slowly: werewolf's runtime protections are the host kernel's own
# features and hold in a container, so cage asserts them directly, while
# check-integrity and check-cloud emulate minimal and prod for the kernel and
# boot-chain hardening -- and the attacks -- a container cannot carry. cage
# runs nothing on the machine, only reads its posture line, so each form is
# built as it ships, without DEV. Every form is checked so, but one whose
# form.yaml says `check: native: false`, with why it cannot be.
NATIVE_FORMS := $(filter-out $(shell $(FORM_ASK) having native false),$(FORMS))
NATIVE_CHECKS = $(addprefix check-native-,$(NATIVE_FORMS))
.PHONY: check-native $(NATIVE_CHECKS) _check-native
check-native: $(addprefix check-native-,$(call shard,$(NATIVE_FORMS)))
$(NATIVE_CHECKS): check-native-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(MAKE) --no-print-directory FORM=$* DEV= slot >$(CHECK)/$*-native-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/$*-native-build.log; echo "FAIL   $*-native build: see $(CHECK)/$*-native-build.log"; exit 1; }
	@$(MAKE) --no-print-directory FORM=$* DEV= _check-native
_check-native:
	@test/cage $(FORM) $(OUT)/slot/root.erofs $(CHECK)/$(FORM)-native.log

# What the forms' services would need that their pledges do not promise:
# make check's boots of DEV=1 builds, the seal and each pledge allowing
# what they would refuse and saying so (werewolf.seal=learn), their
# consoles kept in build/ARCH/check-learn; then each call once, by service
# and the promise that would allow it. A boot that fails still says what
# it called.
SEAL_LEARN_CHECKS = $(addprefix check-,$(FORMS)) check-slot check-persist check-nodata check-lease check-static check-unsigned check-metadata
seal-learn: | $(CHECK_SHARED)
	-@$(MAKE) --no-print-directory -k SEAL_LEARN=1 $(SEAL_LEARN_CHECKS)
	@grep -aho 'seal-watch: {"event":"learned"[^}]*}' $(BUILD)/check-learn/*.log | \
		sed 's/.*"call":"\([^"]*\)","promise":"\([^"]*\)","service":"\([^"]*\)","exe":"\([^"]*\)".*/\3 \2 \1 \4/' | \
		LC_ALL=C sort -u | awk 'BEGIN { print "service promise call program" } { print }' | column -t

# One form's two boots, REPEAT times (10 unless given), for a failure that
# comes and goes: each failing first boot's console is kept as
# FORM-one-N.log.
# make check-one FORM=prod REPEAT=20; add ACCEL=tcg to rule the
# hypervisor out.
REPEAT ?= 10
.PHONY: check-one
check-one: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(CHECK_MAKE) FORM=$(FORM) image >$(CHECK)/$(FORM)-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/$(FORM)-build.log; echo "FAIL   $(FORM) build: see $(CHECK)/$(FORM)-build.log"; exit 1; }
	@failed=0; for i in $$(seq $(REPEAT)); do \
		$(CHECK_MAKE) FORM=$(FORM) _check-form >$(CHECK)/$(FORM)-one.out 2>&1 || { \
			failed=$$((failed + 1)); cp $(CHECK)/$(FORM).log $(CHECK)/$(FORM)-one-$$i.log; \
			echo "boot $$i of $(REPEAT):"; grep -E -A6 '^FAIL' $(CHECK)/$(FORM)-one.out | head -8; }; \
	done; echo "$(FORM): $$failed of $(REPEAT) boots failed"; [ $$failed -eq 0 ]

check-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(CHECK_MAKE) FORM=$* image >$(CHECK)/$*-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/$*-build.log; echo "FAIL   $* build: see $(CHECK)/$*-build.log"; exit 1; }
	@$(CHECK_MAKE) FORM=$* _check-form

# An ad-hoc form, generated by howl from flags alone (docs/design/adhoc.md):
# a stock OCI image baked in, booted and checked as any form is. Needs
# crane on the host (tools/install-deps) and the network for the pull, as
# apko lock does. The cloud group runs it.
check-adhoc: $(HOWL) | $(CHECK_SHARED)
	@mkdir -p $(CHECK) && rm -rf $(BUILD)/adhoc/check-oci
	@$(HOWL) form --with prod --oci web=cgr.dev/chainguard/nginx --web.listen tcp/8080 --web.write /var/lib/nginx/tmp -o $(BUILD)/adhoc/check-oci >$(CHECK)/check-oci-form.log 2>&1 || \
		{ tail -n 20 $(CHECK)/check-oci-form.log; echo "FAIL   check-oci form: see $(CHECK)/check-oci-form.log"; exit 1; }
	@$(CHECK_MAKE) FORM=$(BUILD)/adhoc/check-oci image >$(CHECK)/check-oci-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/check-oci-build.log; echo "FAIL   check-oci build: see $(CHECK)/check-oci-build.log"; exit 1; }
	@$(CHECK_MAKE) FORM=$(BUILD)/adhoc/check-oci _check-form

# Where the form serves ssh, root gets two keys: a key file, and a security
# key's, made with the software one (TEST_SK). A form that takes security
# keys alone must log the second in and refuse the first (test/boot).
# CHECK_KEPT_KEYS: the keys are made already, for a form that bakes them in
# (check-bastion).
# check_keys PREFIX: PREFIX-key, a key file, and PREFIX-sk-key, a security key's.
check_keys = rm -f $(1)-key $(1)-key.pub $(1)-sk-key $(1)-sk-key.pub && \
	ssh-keygen -q -t ed25519 -N '' -C werewolf-check -f $(1)-key && \
	ssh-keygen -q -t ed25519-sk -w $(CURDIR)/$(TEST_SK) -N '' -C werewolf-check-sk -f $(1)-sk-key
_check-form: $(HOWL) $(TEST_SK)
	@rm -f $(CHECK)/$(FORM).img && dd if=/dev/zero of=$(CHECK)/$(FORM).img bs=1048576 count=0 seek=1024 2>/dev/null
	@rm -rf $(CHECK)/$(FORM)-config && mkdir -p $(CHECK)/$(FORM)-config && \
		head -c 64 /dev/zero | tr '\0' k >$(CHECK)/$(FORM)-config/data.key && \
		$(if $(CHECK_SSH),$(if $(CHECK_KEPT_KEYS),,$(call check_keys,$(CHECK)/$(FORM)) &&) \
			cat $(CHECK)/$(FORM)-key.pub $(CHECK)/$(FORM)-sk-key.pub >$(CHECK)/$(FORM)-config/authorized_keys &&) \
		$(if $(wildcard $(FORM_DIR)/test/config),$(FORM_DIR)/test/config $(CHECK)/$(FORM)-config &&) \
		$(HOWL) pack --with $(FORM_REF) -o $(CHECK)/$(FORM)-config.tar --config $(CHECK)/$(FORM)-config >/dev/null
	@awk '$(foreach c,$(call form_check,skip),$$2 != "$(c)" &&) 1' test/checks $(wildcard $(FORM_DIR)/test/checks) >$(CHECK)/$(FORM)-checks
	@SSH_MODE=$(FORM) SSH_PORT=$(CHECK_SSH) SSH_KEY=$(CHECK)/$(FORM)-key SSH_SK_KEY=$(CHECK)/$(FORM)-sk-key SSH_SK_PROVIDER=$(CURDIR)/$(TEST_SK) GITEA_PORT=$(CHECK_WEB) test/boot $(FORM) $(CHECK)/$(FORM)-checks $(CHECK)/$(FORM).log $(CHECK_FORM_QEMU)
	@$(if $(filter $(AGAIN_FORMS),$(FORM)),$(CHECK_MAKE) FORM=$(FORM) _check-form-again,:)

# The second boot, from the disk the first left: what it kept. The code is
# every form's (cmd/init's data, sshd-start's host key), so a few forms
# stand for all, chosen for what they keep: minimal nothing (its /data is
# RAM), sshd a host key, prod-ssh a key under an updater, gitea and
# vaultwarden an application's data, demo PostgreSQL's (and the persist
# group cuts its power). AGAIN_FORMS=all boots every form twice.
AGAIN_FORMS ?= minimal sshd prod-ssh gitea vaultwarden demo
ifeq ($(AGAIN_FORMS),all)
override AGAIN_FORMS := $(FORMS)
endif
_check-form-again:
	@SSH_MODE=$(FORM) SSH_PORT=$(CHECK_SSH) SSH_KEY=$(CHECK)/$(FORM)-key SSH_SK_KEY=$(CHECK)/$(FORM)-sk-key SSH_SK_PROVIDER=$(CURDIR)/$(TEST_SK) GITEA_PORT=$(CHECK_WEB) test/boot $(FORM)-again test/checks-again $(CHECK)/$(FORM)-again.log $(CHECK_FORM_QEMU)
	@! grep -a -E 'werewolf: (formatting|making LUKS2) ' $(CHECK)/$(FORM)-again.log || \
		{ echo "FAIL   $(FORM)-again        formatted the disk its first boot left"; exit 1; }
	@# An ssh host key made and kept on the first boot is the one the second
	@# offers (sshd-start, ssh-host-key); a form whose /data is RAM keeps none.
	@a=$$(grep -a '"event":"host-key"' $(CHECK)/$(FORM).log | grep -a 'kept in /data' | \
		grep -ao '"fingerprint":"[^"]*"' | head -n 1); \
	b=$$(grep -a '"event":"host-key"' $(CHECK)/$(FORM)-again.log | grep -ao '"fingerprint":"[^"]*"' | head -n 1); \
	[ -z "$$a" ] || [ "$$a" = "$$b" ] || \
		{ echo "FAIL   $(FORM)-again        host key not kept: [$$a] then [$$b]"; exit 1; }

# The bastion as an operator makes one: its own image has no users and lets
# no one in, so its check boots a form on it naming two, their keys made
# here and baked in: check, root's security key in test/boot, reaching
# 127.0.0.1:22, and narrow, reaching 127.0.0.2:22, which check must not
# (forms/bastion/test/checks, test/boot). An explicit rule, so that it, not
# check-%, makes check-bastion.
CHECK_BASTION = $(CHECK)/bastion-check
CHECK_BASTION_SSH = $(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x bastion | cut -d: -f1 | awk '{ print 22200 + $$1 }')
check-bastion: $(HOWL) $(TEST_SK) | $(CHECK_SHARED)
	@mkdir -p $(CHECK) && rm -rf $(CHECK_BASTION) && mkdir -p $(CHECK_BASTION)/test && \
		$(call check_keys,$(CHECK_BASTION)) && $(call check_keys,$(CHECK)/bastion-narrow) && \
		cp forms/bastion/test/checks $(CHECK_BASTION)/test/checks && \
		echo '# make check-bastion: the bastion, with two users.' >$(CHECK_BASTION)/apko.yaml && \
		{ echo 'base: bastion' && echo 'bastion:' && echo '  users:' && \
		echo '    check:' && echo "      keys: [\"$$(cut -d' ' -f1,2 $(CHECK_BASTION)-sk-key.pub)\"]" && \
		echo '      destinations: [127.0.0.1:22]' && \
		echo '    narrow:' && echo "      keys: [\"$$(cut -d' ' -f1,2 $(CHECK)/bastion-narrow-sk-key.pub)\"]" && \
		echo '      destinations: [127.0.0.2:22]' && \
		echo 'weaknesses:' && $(FORM_TOOL) excuses bastion | sed 's/^\([^ ]*\) \(.*\)/  \1: "\2"/'; \
		} >$(CHECK_BASTION)/form.yaml
	@$(CHECK_MAKE) FORM=$(CHECK_BASTION) image >$(CHECK)/bastion-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/bastion-build.log; echo "FAIL   bastion build: see $(CHECK)/bastion-build.log"; exit 1; }
	@$(CHECK_MAKE) FORM=$(CHECK_BASTION) CHECK_SSH=$(CHECK_BASTION_SSH) CHECK_KEPT_KEYS=1 _check-form

# Every form booted as it ships, without DEV: test/boot judges the machine
# by its posture line, which may fail only as the form's weaknesses
# excuse, and by the console lines in its test/console, where there is
# one. A static pattern, so that it, not check-%, makes these.
$(SHELLFREE_CHECKS): check-shellfree-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(MAKE) --no-print-directory FORM=$* DEV= image >$(CHECK)/$*-shellfree-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/$*-shellfree-build.log; echo "FAIL   $*-shellfree build: see $(CHECK)/$*-shellfree-build.log"; exit 1; }
	@$(MAKE) --no-print-directory FORM=$* DEV= _check-shellfree-boot

_check-shellfree-boot:
	@rm -f $(CHECK)/$(FORM)-shellfree.img && dd if=/dev/zero of=$(CHECK)/$(FORM)-shellfree.img bs=1048576 count=0 seek=1024 2>/dev/null
	@test/boot $(FORM)-shellfree $(or $(wildcard $(FORM_DIR)/test/console),-) $(CHECK)/$(FORM)-shellfree.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
		-drive file=$(CHECK)/$(FORM)-shellfree.img,format=raw,if=virtio

# The same disks both times: the second boot must find what the first left.
# A form that serves ssh, as its policy declares, is logged into from here
# on both its boots (test/boot): with a key made for the run, in its config,
# through port 22 forwarded from a port of its own, so forms boot side by
# side.
comma := ,
CHECK_SSH := $(if $(filter 22,$(FORM_LISTENS)),$(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x '$(FORM)' | cut -d: -f1 | awk '{ print 22200 + $$1 }'))
# A form test/boot drives through its web API from the host too (gitea),
# its check's web port: forwarded beside ssh's, from a range of its own.
CHECK_WEB_PORT := $(call form_check,web)
CHECK_WEB := $(if $(CHECK_WEB_PORT),$(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x '$(FORM)' | cut -d: -f1 | awk '{ print 23200 + $$1 }'))
CHECK_FORM_QEMU = $(if $(CHECK_SSH),$(subst user$(comma)id=n0,user$(comma)id=n0$(comma)hostfwd=tcp:127.0.0.1:$(CHECK_SSH)-:22$(if $(CHECK_WEB),$(comma)hostfwd=tcp:127.0.0.1:$(CHECK_WEB)-:$(CHECK_WEB_PORT)),$(CHECK_QEMU)),$(CHECK_QEMU)) \
	-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
	-drive file=$(CHECK)/$(FORM).img,format=raw,if=virtio \
	-drive file=$(CHECK)/$(FORM)-config.tar,format=raw,if=virtio,readonly=on

# prod with no werewolf.ip: an address from QEMU's DHCP server, and the
# client split as it says it is. After prod's own check, which builds the
# same form in the same place.
check-lease: | $(CHECK_SHARED) check-prod
	@$(CHECK_MAKE) FORM=prod _check-lease-boot

_check-lease-boot:
	@test/boot lease test/checks-lease $(CHECK)/lease.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_BOOT)"
	@grep -a -q 'dhcp-client: {.*"event":"bound"' $(CHECK)/lease.log || \
		{ echo "FAIL   lease              no \"bound\" event on the console"; exit 1; }

# minimal, which has no DHCP client, with no werewolf.ip: its address from
# the config tar's network file, as howl pack --ip writes it, read
# before the network comes up. After minimal's own check, which builds the
# same form in the same place.
check-static: | $(CHECK_SHARED) check-minimal
	@$(CHECK_MAKE) FORM=minimal _check-static-boot

_check-static-boot: $(HOWL)
	@$(HOWL) pack --with minimal -o $(CHECK)/static-config.tar \
		--ip 10.0.2.15/24 --gw 10.0.2.2 --dns 10.0.2.3 >/dev/null
	@test/boot static test/checks-static $(CHECK)/static.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_BOOT)" \
		-drive file=$(CHECK)/static-config.tar,format=raw,if=virtio,readonly=on

# A root image changed after its build must not boot: minimal's stage0,
# then its root.erofs with one byte of the superblock changed, must stop
# in stage0, dm-verity failing the block, before erofs ever uses it. After
# minimal's own check, which builds the same form in the same place.
check-verity: | $(CHECK_SHARED) check-minimal
	@$(CHECK_MAKE) FORM=minimal _check-verity-boot

# The security property is that stage0 refuses the changed image and the
# machine never hands over -- stage0 says so itself, synchronously, before
# it panics. dm-verity's own "data block N is corrupted" line is the cause
# and is checked too, but loosely: its device id and block number, and the
# exact wording, vary by kernel and by whether the run is accelerated, and
# the test is about the refusal, not the kernel's phrasing.
_check-verity-boot:
	@rm -rf $(CHECK)/verity && mkdir -p $(CHECK)/verity && cp $(OUT)/slot/root.erofs $(CHECK)/verity/ && \
		printf x | dd of=$(CHECK)/verity/root.erofs bs=1 seek=1024 conv=notrunc 2>/dev/null && \
		(cd $(CHECK)/verity && $(TAR) -cf - --format newc --uid 0 --gid 0 --numeric-owner root.erofs) | \
		zstd -1 -q -c | cat $(OUT)/slot/stage0.zst - >$(CHECK)/verity.zst && rm -r $(CHECK)/verity
	@! test/boot verity - $(CHECK)/verity.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(CHECK)/verity.zst -append "$(CHECK_CMDLINE)" >/dev/null
	@grep -a -q 'stage0: cannot mount /root.erofs' $(CHECK)/verity.log || \
		{ echo "FAIL   verity             stage0 did not refuse the changed image; see $(CHECK)/verity.log"; exit 1; }
	@! grep -a -q 'handing over to runit' $(CHECK)/verity.log || \
		{ echo "FAIL   verity             the changed image booted; see $(CHECK)/verity.log"; exit 1; }
	@grep -a -E -q 'device-mapper: verity:.* corrupted|cannot read erofs superblock' $(CHECK)/verity.log || \
		{ echo "FAIL   verity             no dm-verity corruption reported; see $(CHECK)/verity.log"; exit 1; }
	@echo "pass   verity             a changed root image does not boot"

# A slot that boots but never commits must be taken back: stage0's deadman
# reboots it, and the loader then boots the slot that last committed. Its
# ten minutes are 20 s here (werewolf.deadman), which stage0 takes from a
# DEV build's root alone, and no loader is named, so slot-keep has nothing
# to commit to. The deadman must say why on the console, the kernel must
# reset (-no-reboot ends QEMU, which no clean power-off preceded), and
# nothing must have committed.
# After check-slot, which builds the same slot in the same place: under
# -j, two sub-makes building it at once each remove the other's
# modules-bitten directory mid-recipe.
check-deadman: | $(CHECK_SHARED) check-$(CHECK_SLOT_FORM) check-slot
	@mkdir -p $(CHECK)
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) DEV=1 slot >$(CHECK)/deadman-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/deadman-build.log; echo "FAIL   deadman build: see $(CHECK)/deadman-build.log"; exit 1; }
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) DEV=1 _check-deadman-boot

_check-deadman-boot:
	@rm -rf $(CHECK)/deadman $(CHECK)/deadman.img && mkdir -p $(CHECK)/deadman/var/lib/werewolf/a && \
		cp $(OUT)/slot/root.erofs $(CHECK)/deadman/var/lib/werewolf/a/ && \
		mke2fs -q -F -t ext4 -U $(VICTIM_UUID) -d $(CHECK)/deadman $(CHECK)/deadman.img 128M && rm -r $(CHECK)/deadman
	@# Not test/boot, which would check the machine and power it off first:
	@# the machine is left alone, and -no-reboot ends QEMU at the reset.
	@timeout 180 $(CHECK_QEMU) -kernel $(OUT)/slot/vmlinuz -initrd $(OUT)/slot/stage0.zst \
		-append "$(CHECK_CMDLINE) init=/init werewolf.slot=a werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.deadman=20" \
		-drive file=$(CHECK)/deadman.img,format=raw,if=virtio </dev/null >$(CHECK)/deadman.log 2>&1; \
		[ $$? -ne 124 ] || { echo "FAIL   deadman            no reset in 180 s; see $(CHECK)/deadman.log"; exit 1; }
	@grep -a -q 'stage0: the deadman waits 20s' $(CHECK)/deadman.log || \
		{ echo "FAIL   deadman            stage0 did not take werewolf.deadman; see $(CHECK)/deadman.log"; exit 1; }
	@grep -a -q 'stage0: slot a did not commit in 20s; rebooting into the last good slot' $(CHECK)/deadman.log || \
		{ echo "FAIL   deadman            the deadman did not say why; see $(CHECK)/deadman.log"; exit 1; }
	@! grep -a -q 'reboot: Power down' $(CHECK)/deadman.log || \
		{ echo "FAIL   deadman            the machine powered off rather than reset; see $(CHECK)/deadman.log"; exit 1; }
	@! grep -a -q 'slot-keep: healthy' $(CHECK)/deadman.log || \
		{ echo "FAIL   deadman            the slot committed; see $(CHECK)/deadman.log"; exit 1; }
	@echo "pass   deadman            a slot that does not commit is rebooted, and says why"

# An unsigned module offered at boot must be refused: by init on a RAM root,
# and by stage0 on a slot. test/unsign cuts the signature off evdev, in a
# cpio appended to the initramfs, which the kernel unpacks last. After the
# checks that build the same forms in the same places.
check-unsigned: | $(CHECK_SHARED) check-minimal check-slot
	@$(CHECK_MAKE) FORM=minimal _check-unsigned-boot
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) _check-unsigned-slot

_check-unsigned-boot:
	@test/unsign $(OUT)/modules.tar evdev $(CHECK)/unsigned-$(FORM).cpio.zst
	@cat $(OUT)/initramfs.zst $(CHECK)/unsigned-$(FORM).cpio.zst >$(CHECK)/unsigned-$(FORM).zst
	@test/boot unsigned test/checks-unsigned $(CHECK)/unsigned.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(CHECK)/unsigned-$(FORM).zst -append "$(CHECK_CMDLINE)"

_check-unsigned-slot:
	@test/unsign $(OUT)/modules.tar evdev $(CHECK)/unsigned-$(FORM).cpio.zst
	@cat $(OUT)/slot/stage0.zst $(CHECK)/unsigned-$(FORM).cpio.zst >$(CHECK)/unsigned-$(FORM).zst
	@cp $(CHECK)/victim.img $(CHECK)/unsigned-victim.img
	@test/boot unsigned-slot test/checks-unsigned $(CHECK)/unsigned-slot.log $(CHECK_QEMU) \
		-kernel $(OUT)/slot/vmlinuz -initrd $(CHECK)/unsigned-$(FORM).zst \
		-append "$(CHECK_CMDLINE) init=/init werewolf.slot=a werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.grubenv=$(VICTIM_UUID):/boot/grub/grubenv" \
		-drive file=$(CHECK)/unsigned-victim.img,format=raw,if=virtio

# prod against a stand-in metadata server (test/metadata), seven
# ways: a good config on GCP, AWS, Hetzner and Azure must be taken; a
# hostile one refused whole; and a machine on no cloud, or on Hyper-V that
# is not Azure, must not ask at all (test/cloud-boot). arm64 guests have
# SMBIOS only under UEFI firmware.
CLOUD_FIRMWARE = $(if $(filter aarch64,$(ARCH)),$(firstword $(wildcard \
	/opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/local/share/qemu/edk2-aarch64-code.fd \
	/usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd)))
METADATA_QEMU = $(QEMU) -smp 2 -m 1024 -no-reboot -device virtio-rng-pci \
	-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_BOOT)"
METADATA_BOOTS = "gcp good metadata" "aws good metadata" "hetzner good metadata" "azure good metadata" \
	"gcp hostile metadata-refused" "none good metadata-refused" "hyperv good metadata-refused"

check-metadata: | $(CHECK_SHARED) check-prod
	@$(CHECK_MAKE) FORM=prod _check-metadata-boots

_check-metadata-boots:
	@[ "$(ARCH)" != aarch64 ] || [ -n "$(CLOUD_FIRMWARE)" ] || \
		{ echo "FAIL   metadata           no UEFI firmware for arm64 (edk2-aarch64-code.fd)"; exit 1; }
	@failed=0; for b in $(METADATA_BOOTS); do set -- $$b; \
		test/cloud-boot meta-$$1-$$2 $$1 $$2 test/checks-$$3 $(CHECK)/meta-$$1-$$2.log "$(CLOUD_FIRMWARE)" $(METADATA_QEMU) || failed=1; \
	done; exit $$failed

# The release's disks, booted as published, after `make dist`: UEFI
# firmware, systemd-boot, slot a, and the posture line on the serial port,
# as a cloud records it, judged against the form as it ships
# (test/posture-known). -snapshot leaves the published bytes as they are,
# and a network with no way out keeps the updater from installing the
# latest release over them. Not on emulated arm64, as for persist: CI's arm
# runners have no KVM, and edk2 there never reaches systemd-boot in time.
DIST_DISK_QEMU = qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic \
	-smp 2 -m 2048 -snapshot -no-reboot $(UEFI_FLAGS) -device virtio-rng-pci \
	-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile=
check-dist:
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   dist               emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@failed=0; for f in $(filter-out $(DIST_DIRECT_FORMS),$(RELEASE_FORMS)); do \
		$(MAKE) --no-print-directory FORM=$$f _check-dist-disk || failed=1; \
	done; exit $$failed
endif

_check-dist-disk:
	@[ -n "$(UEFI_FIRMWARE)" ] || { echo "FAIL   dist-$(FORM)     no UEFI firmware for $(ARCH) (edk2 or OVMF)"; exit 1; }
	@[ "$(ARCH)" = aarch64 ] || [ -n "$(UEFI_VARS)" ] || { echo "FAIL   dist-$(FORM)     no UEFI variables template for $(ARCH)"; exit 1; }
	@[ -f $(DIST)/$(FORM)-$(ARCH)-disk.qcow2 ] || \
		{ echo "FAIL   dist-$(FORM)     no $(DIST)/$(FORM)-$(ARCH)-disk.qcow2: make dist first"; exit 1; }
	@mkdir -p $(CHECK)
	@$(uefi-vars)
	@test/boot dist-$(FORM) - $(CHECK)/dist.log $(DIST_DISK_QEMU) \
		-drive file=$(DIST)/$(FORM)-$(ARCH)-disk.qcow2,format=qcow2,if=virtio

# prod-ssh's disk on a real cloud (test/cloud), as `howl create` makes
# it: its image, a machine booted with a config in its user data, judged
# from the cloud's record of its serial port and an ssh login from this
# host alone, a second create with a new config, and delete leaving
# nothing; then all of it deleted. Each needs its CLI logged in and costs
# a few cents; not part of check. ARCH picks the machine (Azure: the
# resource group's location must offer it).
check-gcp check-aws check-azure: check-%:
	@$(MAKE) --no-print-directory FORM=prod-ssh CLOUD=$* _check-cloud

_check-cloud: $(HOWL)
	@test/cloud $(CLOUD) $(FORM) $(ARCH)

# prod's LUKS2 disk, as its own check left it, booted with no data.key:
# it must refuse the disk, not format it again. After prod's own check,
# which builds the same form in the same place and makes the disk.
check-nodata: | $(CHECK_SHARED) check-prod
	@$(CHECK_MAKE) FORM=prod _check-nodata-boot

_check-nodata-boot:
	@cp $(CHECK)/prod.img $(CHECK)/nodata.img
	@test/boot nodata test/checks-nodata $(CHECK)/nodata.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
		-drive file=$(CHECK)/nodata.img,format=raw,if=virtio

# The slot path: stage0 finding root.erofs by filesystem UUID, the overlay,
# /victim read-only, and commit making the slot GRUB's default, which takes
# the minute commit waits. The victim is a small ext4 holding what bite
# leaves: the root image in slot a, and GRUB's environment block.
# After minimal's own check, which builds the same form in the same place.
check-slot: | $(CHECK_SHARED) check-$(CHECK_SLOT_FORM)
	@mkdir -p $(CHECK)
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) slot >$(CHECK)/slot-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/slot-build.log; echo "FAIL   slot build: see $(CHECK)/slot-build.log"; exit 1; }
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) _check-slot-boot

_check-slot-boot:
	@rm -rf $(CHECK)/victim $(CHECK)/victim.img
	@mkdir -p $(CHECK)/victim/var/lib/werewolf/a $(CHECK)/victim/boot/grub $(CHECK)/victim/boot/werewolf/a
	@cp $(OUT)/slot/root.erofs $(CHECK)/victim/var/lib/werewolf/a/
	@# bite lays the slot's kernel beside GRUB's directory; this boot takes
	@# its own, so a stand-in, which bite-cleanup must find before it deletes.
	@echo kernel >$(CHECK)/victim/boot/werewolf/a/vmlinuz
	@# A distro beside werewolf, for bite-cleanup: what it must delete, a
	@# name that only begins like one it keeps, links that lead out, and
	@# (below) a file it may not delete.
	@v=$(CHECK)/victim; mkdir -p $$v/etc $$v/home/user/.ssh $$v/var/log $$v/var/lib/werewolf2 && \
		echo ID=debian >$$v/etc/os-release && echo secret >$$v/home/user/.ssh/id && echo log >$$v/var/log/syslog && \
		echo nameserver 10.0.2.3 >$$v/etc/resolv.conf && \
		touch $$v/bootx && ln -s /run/werewolf $$v/etc/escape && ln -s ../../.. $$v/var/lib/up
	@env=$(CHECK)/victim/boot/grub/grubenv; \
		printf '# GRUB Environment Block\nsaved_entry=werewolf-b\nnext_entry=werewolf-a\n' >$$env; \
		head -c $$((1024 - $$(wc -c <$$env))) /dev/zero | tr '\0' '#' >>$$env
	@mke2fs -q -F -t ext4 -U $(VICTIM_UUID) -d $(CHECK)/victim $(CHECK)/victim.img 128M
	@# resolv.conf immutable (chattr +i), as some cloud agents leave it:
	@# bite-cleanup must delete the rest of /etc around it, and name it.
	@d="$(DEBUGFS)"; img=$(CHECK)/victim.img; [ -n "$$d" ] || { echo "FAIL   slot               no debugfs (e2fsprogs)"; exit 1; }; \
		flags() { "$$d" -R "stat /etc/resolv.conf" $$img 2>/dev/null | sed -n 's/.*Flags: \(0x[0-9a-f]*\).*/\1/p'; }; \
		f=$$(flags); [ -n "$$f" ] && "$$d" -w -R "set_inode_field /etc/resolv.conf flags $$((f | 0x10))" $$img 2>/dev/null && \
		f=$$(flags) && [ -n "$$f" ] && [ $$((f & 0x10)) -ne 0 ] || \
		{ echo "FAIL   slot               /etc/resolv.conf not made immutable"; exit 1; }
	@test/boot slot test/checks $(CHECK)/slot.log $(CHECK_QEMU) \
		-kernel $(OUT)/slot/vmlinuz -initrd $(OUT)/slot/stage0-bitten.zst \
		-append "$(CHECK_CMDLINE) init=/init werewolf.slot=a werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.grubenv=$(VICTIM_UUID):/boot/grub/grubenv" \
		-drive file=$(CHECK)/victim.img,format=raw,if=virtio
	@grep -a -o 'saved_entry=werewolf-[ab]' $(CHECK)/victim.img | sort -u | grep -qx saved_entry=werewolf-a || \
		{ echo "FAIL   slot               GRUB's default is not werewolf-a after commit"; exit 1; }
	@echo "pass   slot               GRUB's default is werewolf-a"

# PostgreSQL's data must outlive a reboot, and a power cut: the demo as it
# ships, a werewolf disk (make disk: GPT, systemd-boot, werewolf's ext4
# with its slots and data/), booted three times under UEFI from the same
# image. The first makes the cluster and stores its posture, and powers off
# (test/checks-persist); the second keeps both, finds the first's, and then
# loses its power (test/checks-persist-again); the third, after the cut,
# must keep all of it (test/checks-persist-cut). Without EL2: edk2, started
# there under HVF, never reaches the boot manager, and the direct boots
# already prove the guest's hypervisor stays off. Its network
# reaches nothing beyond QEMU (restrict=on), so the updater, finding no
# newer packages, builds no slot b mid-test, and the scan fetches no
# database. After the demo's own check, which builds the same form in the
# same place.
UEFI_FIRMWARE = $(firstword $(wildcard $(if $(filter aarch64,$(ARCH)), \
	/opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/local/share/qemu/edk2-aarch64-code.fd \
	/usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd, \
	/opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/local/share/qemu/edk2-x86_64-code.fd \
	/usr/share/qemu/edk2-x86_64-code.fd /usr/share/ovmf/OVMF.fd)))
# aarch64's edk2 loads with -bios; x86_64's OVMF is a pair of pflash
# images, read-only code and writable variables. The variables are a
# per-run copy a recipe makes at UEFI_VARS_COPY, so a boot that writes
# NVRAM (or a power cut mid-write) cannot corrupt the shared template.
# x86_64 shares the i386 variables template, as QEMU's own firmware
# descriptor does.
UEFI_VARS = $(firstword $(wildcard \
	/opt/homebrew/share/qemu/edk2-i386-vars.fd /usr/local/share/qemu/edk2-i386-vars.fd \
	/usr/share/qemu/edk2-i386-vars.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd))
UEFI_VARS_COPY = $(CHECK)/ovmf-vars.fd
# No wait at the firmware's boot menu: arm64's edk2, with no variables to
# say otherwise, counts one down for 5 s before every boot (QEMU start to
# ssh, 5.9 s against 0.7 s without), and takes its length from QEMU's
# -boot; x86_64's OVMF waits for none either way.
UEFI_FLAGS = -boot menu=on,splash-time=0 $(if $(filter aarch64,$(ARCH)),-bios $(UEFI_FIRMWARE),\
	-drive if=pflash,format=raw,unit=0,readonly=on,file=$(UEFI_FIRMWARE) \
	-drive if=pflash,format=raw,unit=1,file=$(UEFI_VARS_COPY))
# make the writable variables copy (x86_64), or nothing (aarch64).
uefi-vars = $(if $(filter aarch64,$(ARCH)),:,cp $(UEFI_VARS) $(UEFI_VARS_COPY))
PERSIST_QEMU = qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic \
	-smp 2 -m 2048 -no-reboot -device virtio-rng-pci $(UEFI_FLAGS) \
	-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile= \
	-drive file=$(CHECK)/persist.img,format=raw,if=virtio
.PHONY: check-persist _check-persist-boot _check-form-again
# persist boots through UEFI firmware (edk2/OVMF), the suite's only firmware
# path. Emulated aarch64 has no EL2, so edk2 + the 2 GB demo run under pure
# TCG and cannot reach runit in the boot budget; x86_64 (fast enough under
# TCG), Apple Silicon (HVF) and any KVM host all cover it, and its subject,
# PostgreSQL surviving a power cut, is architecture-independent. check-slot
# keeps the bite path on arm by booting a slot direct-kernel, not through
# firmware. So skip it, loudly, only where it can only ever time out.
# check-demo first, so a broken demo is named as such, not as persist;
# CI, whose forms jobs check demo on their own, passes PERSIST_AFTER= and
# saves that build and its boots.
PERSIST_AFTER ?= check-demo
check-persist: | $(CHECK_SHARED) $(PERSIST_AFTER)
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   persist            emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@mkdir -p $(CHECK)
	@[ -n "$(UEFI_FIRMWARE)" ] || { echo "FAIL   persist            no UEFI firmware for $(ARCH) (edk2 or OVMF)"; exit 1; }
	@[ "$(ARCH)" = aarch64 ] || [ -n "$(UEFI_VARS)" ] || { echo "FAIL   persist            no UEFI variables template for $(ARCH) (edk2-i386-vars.fd or OVMF_VARS.fd)"; exit 1; }
	@rm -f $(CHECK)/persist.img
	@$(CHECK_MAKE) FORM=demo disk DISK=$(CHECK)/persist.img DISK_MIB=2048 \
		DISK_ARGS="console=$(CONSOLE) werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) $(SEAL_ARGS)" >$(CHECK)/persist-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/persist-build.log; echo "FAIL   persist build: see $(CHECK)/persist-build.log"; exit 1; }
	@$(CHECK_MAKE) FORM=demo _check-persist-boot
endif

_check-persist-boot:
	@$(uefi-vars)
	@test/boot persist test/checks-persist $(CHECK)/persist.log $(PERSIST_QEMU)
	@POWER_CUT=1 test/boot persist-again test/checks-persist-again $(CHECK)/persist-again.log $(PERSIST_QEMU)
	@test/boot persist-cut test/checks-persist-cut $(CHECK)/persist-cut.log $(PERSIST_QEMU)
	@echo "pass   persist            $$(grep -a -c 'pg-init: removed the lock the last boot left' $(CHECK)/persist-cut.log) stale lock(s) removed after the cut"

# A whole update, over the network, so not part of `check`, which needs
# none: a form as it ships, on slot a of a disk, its build record claiming
# the kernel release before its own, updates itself to slot b, which must
# then boot and commit. The claim is one more file laid over the slot's
# root, as a later tar entry replaces an earlier one; the build itself is
# untouched. check-updater: prod built with DEV=1, which follows no
# releases, so builds its slot from Wolfi and Alpine. check-updater-release: prod-ssh, a form CI publishes, which
# installs CI's latest signed release; the claim also makes its root unlike
# any release's. See test/update.
CHECK_UPDATE = $(CHECK)/update-$(FORM)
check-updater: | $(CHECK_SHARED)
	@$(MAKE) --no-print-directory FORM=prod DEV=1 _check-updater

# The same update, with the machine's power cut once the update is staged
# and before it is due: whatever ends a boot, a staged slot is armed, and
# the next boot is the update's (test/update, STAGED).
check-updater-staged: | $(CHECK_SHARED)
	@$(MAKE) --no-print-directory FORM=prod DEV=1 STAGED=1 _check-updater

check-updater-release: | $(CHECK_SHARED)
	@$(MAKE) --no-print-directory FORM=prod-ssh _check-updater

_check-updater:
	@mkdir -p $(CHECK_UPDATE)
	@$(MAKE) --no-print-directory slot >$(CHECK_UPDATE)/build.log 2>&1 || \
		{ tail -n 20 $(CHECK_UPDATE)/build.log; echo "FAIL   update build: see $(CHECK_UPDATE)/build.log"; exit 1; }
	@$(MAKE) --no-print-directory _check-updater-boot

_check-updater-boot:
	@rm -rf $(CHECK_UPDATE)/claim $(CHECK_UPDATE)/victim $(CHECK_UPDATE)/victim.img
	@mkdir -p $(CHECK_UPDATE)/claim/usr/share/werewolf $(CHECK_UPDATE)/victim/var/lib/werewolf/a $(CHECK_UPDATE)/victim/boot/grub
	@# linux-virt-6.18.55-r0 claims linux-virt-6.18.54-r0.
	@awk -F. '{ split($$3, z, "-"); if (z[1] < 1) exit 1; printf "%s.%s.%d-%s\n", $$1, $$2, z[1] - 1, z[2] }' \
		$(OUT)/meta/usr/share/werewolf/kernel >$(CHECK_UPDATE)/claim/usr/share/werewolf/kernel
	@printf '#mtree\n./ type=dir uid=0 gid=0 uname=root gname=root mode=0755 time=0.0\n' >$(CHECK_UPDATE)/root.mtree
	@$(TAR) -C $(CHECK_UPDATE)/claim -cf $(CHECK_UPDATE)/claim.tar --uid 0 --gid 0 --numeric-owner usr/share/werewolf/kernel
	@$(TAR) -cf $(CHECK_UPDATE)/root.tar --uid 0 --gid 0 --numeric-owner $(foreach p,$(PRUNE),--exclude $(p)) \
		@$(CHECK_UPDATE)/root.mtree @$(OUT)/rootfs.tar @$(OUT)/overlay.tar @$(CHECK_UPDATE)/claim.tar
	@mkfs.erofs $(EROFS_OPTS) -T0 -U 00000000-0000-0000-0000-000000000000 --tar=f \
		$(CHECK_UPDATE)/victim/var/lib/werewolf/a/root.erofs $(CHECK_UPDATE)/root.tar >/dev/null
	@rm -rf $(CHECK_UPDATE)/root.tar $(CHECK_UPDATE)/verity && mkdir -p $(CHECK_UPDATE)/verity
	@$(VERITY_BIN) $(CHECK_UPDATE)/victim/var/lib/werewolf/a/root.erofs $(CHECK_UPDATE)/verity/verity
	@env=$(CHECK_UPDATE)/victim/boot/grub/grubenv; \
		printf '# GRUB Environment Block\nsaved_entry=werewolf-b\nnext_entry=werewolf-a\n' >$$env; \
		head -c $$((1024 - $$(wc -c <$$env))) /dev/zero | tr '\0' '#' >>$$env
	@mke2fs -q -F -t ext4 -U $(VICTIM_UUID) -d $(CHECK_UPDATE)/victim $(CHECK_UPDATE)/victim.img 3G
	@# The build's stage0, then this root's /verity in a cpio of its own,
	@# which the kernel unpacks over the build's.
	@cp $(OUT)/slot/vmlinuz $(CHECK_UPDATE)/
	@(cd $(CHECK_UPDATE)/verity && $(TAR) -cf - --format newc --uid 0 --gid 0 --numeric-owner verity) | \
		zstd -q -c | cat $(OUT)/slot/stage0.zst - >$(CHECK_UPDATE)/stage0.zst
	@STAGED='$(STAGED)' test/update $(CHECK_UPDATE) \
		"console=$(CONSOLE) panic=1 $$(cat $(OUT)/slot/cmdline) $(SEAL_ARGS) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 init=/init werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.grubenv=$(VICTIM_UUID):/boot/grub/grubenv" \
		$(QEMU) -smp 2 -m 2048 -no-reboot -device virtio-rng-pci -netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile=

# The CI job, here: in an Ubuntu VM like GitHub's runners, with nested
# virtualization for KVM. See test/lima-ci.
ci:
	test/lima-ci

# --- Lima ---------------------------------------------------------------------
# Lima needs a disk image to call the instance's. This one is 64 MiB of
# zeros, which Lima grows to 100 GiB and keeps until `limactl delete`; the
# lima form formats it as /data on first boot. The root is the initramfs
# either way.
$(BUILD)/disk.img:
	mkdir -p $(BUILD)
	dd if=/dev/zero of=$@ bs=1048576 count=64 2>/dev/null

$(OUT)/lima.yaml: boot/lima.yaml.in Makefile $(FORM_FILES)
	mkdir -p $(OUT)
	sed -e 's|@BUILD@|$(CURDIR)/$(BUILD)|g' -e 's|@OUT@|$(CURDIR)/$(OUT)|g' -e 's|@VMTYPE@|$(VMTYPE)|g' \
		-e 's|@LIMA_ARCH@|$(ARCH)|g' -e 's|@CONSOLE@|$(LIMA_CONSOLE)|g' -e 's|@KERNEL_ARGS@|$(KERNEL_ARGS)|g' $< > $@

lima: image $(BUILD)/disk.img $(OUT)/lima.yaml
	limactl start --name werewolf --tty=false $(OUT)/lima.yaml

lima-delete:
	limactl stop -f werewolf
	limactl delete werewolf

# The demo form in Lima, made with howl create: its own boot disk,
# booted by its own systemd-boot and reached over vzNAT, since Lima cannot
# forward a port to a guest without ssh. Its URL is printed at the end.
# See forms/demo/README.md.
demo: $(HOWL)
	test/lima-demo

# webshell-demo: boot the webshell-example form (docs/forms.md) under QEMU,
# as it ships -- no shell -- with its port on this host's 127.0.0.1:8080,
# to attack from the outside with curl or a browser. Ctrl-a x quits.
webshell-demo:
	@$(MAKE) --no-print-directory FORM=webshell-example DEV= _webshell-demo

_webshell-demo: image $(BUILD)/data.img $(if $(wildcard config),config-tar)
	@echo "webshell-example is up: attack it at http://127.0.0.1:8080  (Ctrl-a x quits)"
	$(QEMU) -smp 2 -m 1024 \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst \
		-append "console=$(CONSOLE) $(KERNEL_ARGS) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 werewolf.data=vda" \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:8080-:8080 -device virtio-net-pci,netdev=n0 \
		-device virtio-rng-pci -drive file=$(BUILD)/data.img,format=raw,if=virtio $(QEMU_CONFIG)

demo-delete: $(HOWL)
	test/lima-demo delete

# The demo on Google Compute Engine (test/gcp): its disk as a release
# makes one, imported as an image and booted on a VM that stays, reached
# over HTTP. Needs gcloud, logged in, with a project; the VM costs what an
# e2-medium or t2a-standard-1 costs until demo-gcp-delete.
demo-gcp: $(HOWL)
	test/gcp demo demo $(ARCH)

demo-gcp-delete: $(HOWL)
	test/gcp demo-delete

# The webshell-example form on Google Compute Engine (test/gcp), the same
# way: a vulnerable web app on a real VM on the Internet, reached at
# http://ADDR:8080, to attack from anywhere and watch it hold. The VM costs
# what an e2-small or t2a-standard-1 costs until webshell-gcp-delete.
webshell-gcp: $(HOWL)
	test/gcp webshell webshell-example $(ARCH)

webshell-gcp-delete: $(HOWL)
	test/gcp webshell-delete

# The locks stay: they are what makes the next build the same as the last.
# `make relock` resolves them again; `rm -rf build` removes them too.
clean:
	rm -rf $(filter-out $(LOCK),$(wildcard build/*))

# The comment that opens this file, to its first empty line.
help:
	@sed -n '2,/^$$/s/^# \{0,1\}//p' Makefile

# BEGIN: lint-install .
# http://github.com/codeGROOVE-dev/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_OS := $(shell uname)
LINT_OS_LOWER := $(shell echo $(LINT_OS) | tr '[:upper:]' '[:lower:]')
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# shellcheck and hadolint lack arm64 native binaries: rely on x86-64 emulation
ifeq ($(LINT_OS),Darwin)
	ifeq ($(LINT_ARCH),arm64)
		LINT_ARCH=x86_64
	endif
endif

LINTERS :=
FIXERS :=

YAMLLINT_VERSION ?= 1.37.1
YAMLLINT_ROOT := $(LINT_ROOT)/out/linters/yamllint-$(YAMLLINT_VERSION)
YAMLLINT_BIN := $(YAMLLINT_ROOT)/dist/bin/yamllint
$(YAMLLINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yamllint-*
	curl -sSfL https://github.com/adrienverge/yamllint/archive/refs/tags/v$(YAMLLINT_VERSION).tar.gz | tar -C $(LINT_ROOT)/out/linters -zxf -
	cd $(YAMLLINT_ROOT) && pip3 install --target dist . || pip install --target dist .

LINTERS += yamllint-lint
yamllint-lint: $(YAMLLINT_BIN)
	PYTHONPATH=$(YAMLLINT_ROOT)/dist $(YAMLLINT_ROOT)/dist/bin/yamllint .

.PHONY: _lint $(LINTERS)
_lint:
	@exit_code=0; \
	for target in $(LINTERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

.PHONY: fix $(FIXERS)
fix:
	@exit_code=0; \
	for target in $(FIXERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

# END: lint-install .

# --- zig lint and fix -----------------------------------------------------------
# Kept out of lint-install's block above, which it rewrites. `make lint`
# checks werewolf's Zig three ways: zig ast-check, Zig's own check of every
# function, called or not; tools/zigfix --check, zig fmt's layout with lines
# held to the Style Guide's 100 and nothing the standard library deprecates;
# and ziglint, with the Style Guide's naming rules (.ziglint.zon says which
# and why). `make fix` runs tools/zigfix, which makes most of that so.
ZIG_SOURCES = $(shell find . -name '*.zig' -not -path './build/*' -not -path './out/*' -not -path './.zig-cache/*')

ZIGFIX := $(LINT_ROOT)/out/tools/zigfix
$(ZIGFIX): tools/zigfix.zig
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -femit-bin=$@ tools/zigfix.zig

# ziglint's release for this machine, checked against the sha256 each
# release's checksums.txt gave when it was pinned.
ZIGLINT_VERSION ?= 0.5.3
ZIGLINT_PLATFORM := $(subst arm64,aarch64,$(shell uname -m))-$(if $(filter Darwin,$(LINT_OS)),macos,linux)
ZIGLINT_SHA256_aarch64-macos := 5fae98d6052b42ac07a8cb211036a633ebcd90db0ad40ebbadfbec96195bff13
ZIGLINT_SHA256_aarch64-linux := 110203d2e2332bfd5e2972f00cf731a215cf953e3eb4e14a17d8f7f80eeab26d
ZIGLINT_SHA256_x86_64-linux := 7560bf5ad36170ae1560505a5e273c83376534feccad23a9f7be716f94853539
ZIGLINT_ROOT := $(LINT_ROOT)/out/linters/ziglint-$(ZIGLINT_VERSION)
ZIGLINT_BIN := $(ZIGLINT_ROOT)/ziglint
$(ZIGLINT_BIN):
	@[ -n "$(ZIGLINT_SHA256_$(ZIGLINT_PLATFORM))" ] || { echo "no ziglint $(ZIGLINT_VERSION) for $(ZIGLINT_PLATFORM)" >&2; exit 1; }
	mkdir -p $(ZIGLINT_ROOT)
	curl -sSfL -o $(ZIGLINT_ROOT)/ziglint.tar.gz https://github.com/rockorager/ziglint/releases/download/v$(ZIGLINT_VERSION)/ziglint-$(ZIGLINT_PLATFORM).tar.gz
	echo "$(ZIGLINT_SHA256_$(ZIGLINT_PLATFORM))  $(ZIGLINT_ROOT)/ziglint.tar.gz" | shasum -a 256 -c -
	tar -C $(ZIGLINT_ROOT) -xzf $(ZIGLINT_ROOT)/ziglint.tar.gz ziglint
	rm $(ZIGLINT_ROOT)/ziglint.tar.gz

.PHONY: zig-lint zig-fix
LINTERS += zig-lint
zig-lint: $(ZIGFIX) $(ZIGLINT_BIN)
	@status=0; for f in $(ZIG_SOURCES); do zig ast-check $$f >/dev/null || status=1; done; exit $$status
	$(ZIGFIX) --check $(ZIG_SOURCES)
	$(ZIGLINT_BIN) $(ZIG_SOURCES)

FIXERS += zig-fix
zig-fix: $(ZIGFIX)
	$(ZIGFIX) $(ZIG_SOURCES)
