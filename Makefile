# werewolf: a Wolfi userland on an Alpine kernel, booted from RAM.
#
#   make            build/<arch>/vmlinuz + build/<arch>/<form>/initramfs.zst
#   make slot       build/<arch>/<form>/slot/: vmlinuz, stage0, root.erofs (for bite)
#   make disk       build/<arch>/<form>/disk.img: a boot disk of the slot, systemd-boot
#   make run        boot it under QEMU, root shell on the console, ssh on :2222
#   make lima       boot the lima form under Lima (vz on Apple silicon)
#   make demo       the demo form's boot disk in a Lima VM; prints its URL
#   make config     pack config/ into the raw config tar `run` attaches
#   make forms      list the forms and what each includes
#   make test       the Zig programs' unit tests
#   make posture    build posture and run it here, as root: any Linux's protections
#   make check      boot every form, and a slot, and check its protections
#   make lima-ci    the CI job, in an Ubuntu VM under Lima
#   make lock       resolve the form's packages and kernel afresh
#   make dist       the published forms' files and unsigned manifests, in dist/
#
# FORM picks the form (default sshd; `make lima` implies FORM=lima). ARCH
# defaults to the host. ARCH=x86_64 on an arm64 host builds fine and boots
# under TCG, slowly; it is for checking, not for working in.

ARCH ?= $(shell uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
HOST_ARCH := $(shell uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
HOST_OS := $(shell uname -s)

# --- forms --------------------------------------------------------------------
# A form is forms/<name>.yaml, an apko config, plus an optional forms/<name>/
# of files laid over the rootfs. A form builds on another with apko's own
# `include:`, and its files follow its packages: the image gets the folders
# of every form in the include chain, base first. CHAIN is that chain, read
# from the yaml so it is never written twice.
FORM ?= $(if $(filter lima,$(MAKECMDGOALS)),lima,sshd)
ifeq ($(wildcard forms/$(FORM).yaml),)
$(error no form forms/$(FORM).yaml; try `make forms`)
endif
CHAIN := $(shell f=$(FORM); c=; while [ -n "$$f" ]; do c="$$f $$c"; \
	f=$$(sed -n 's/^include: *\(.*\)\.yaml$$/\1/p' forms/$$f.yaml); done; echo $$c)
CHAIN_DIRS := $(wildcard $(addprefix forms/,$(CHAIN)))

# --- allowances ---------------------------------------------------------------
# What a form may take back of werewolf's defaults, and only when it is
# built: an empty file etc/werewolf/allow/NAME in its folder, inherited along
# the chain like its other files, so no form drops what one it includes was
# given. Nothing on the machine reads an allowance from its command line,
# config or metadata, which root can rewrite: the build turns them into the
# image's kernel arguments and module parameters, below, and the image is
# what decides (design/lockdown.md, Allowances). A name not here fails the
# build.
#
#   kvm         run virtual machines: KVM starts, built in (aarch64) or from
#               the form's modules (x86_64), with nested virtualization off
#   nested-kvm  and let their guests run virtual machines too; needs kvm
ALLOWANCES = kvm nested-kvm
ALLOW_FILES := $(wildcard $(addsuffix /etc/werewolf/allow/*,$(CHAIN_DIRS)))
ALLOW := $(sort $(notdir $(ALLOW_FILES)))
ifneq ($(filter-out $(ALLOWANCES),$(ALLOW)),)
$(error form $(FORM) allows $(filter-out $(ALLOWANCES),$(ALLOW)); werewolf knows only $(ALLOWANCES))
endif
ifneq ($(filter nested-kvm,$(ALLOW)),)
ifeq ($(filter kvm,$(ALLOW)),)
$(error form $(FORM) allows nested-kvm without kvm)
endif
endif

# The kernel's hardening that has no runtime switch, on the command line of
# every way the image boots: bite's and disk/build's entries, which read it
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
# (docs/security.md).
KERNEL_ARGS = debugfs=off proc_mem.force_override=never slab_nomerge page_alloc.shuffle=1
ifeq ($(ARCH),aarch64)
KERNEL_ARGS += $(if $(filter nested-kvm,$(ALLOW)),kvm-arm.mode=nested,$(if $(filter kvm,$(ALLOW)),,kvm-arm.mode=none))
else
KERNEL_ARGS += ia32_emulation=0
endif
# Parameters the image loads modules with, MODULE:KEY=VALUE, one a word: on
# x86_64, KVM's nested virtualization, which Linux turns on by default.
# A parameter for a module the form does not carry fails the build.
MODULE_PARAMS = $(if $(and $(filter x86_64,$(ARCH)),$(filter kvm,$(ALLOW))),$(foreach m,kvm-intel kvm-amd,$(m):nested=$(if $(filter nested-kvm,$(ALLOW)),1,0)))

# werewolf's nine programs are built, not checked in, and laid in like
# form folders: the module loader, modules/modules.zig, the network setup,
# net/net.zig, the network policy, fence/fence.zig, the one-way mount,
# mount/mount.zig, and the security
# posture check, posture/posture.zig, in every form (the loader in stage0
# too); the DHCP
# client, dhcp/dhcp.zig, in any form whose chain includes dhcp; the
# metadata fetcher, cloud/cloud.zig, in any whose chain includes cloud; the
# updater, updater/update.zig, in any whose chain includes autoupdate; and the demo's page,
# status/status.zig, in any whose chain includes demo. Zig is
# pre-1.0 and changes between releases, so the build insists on the version
# the code is written for.
ZIG_VERSION = 0.17.0
# Each is built into its own folder under PROGRAMS, apart from the forms',
# so a form may share a program's name.
PROGRAMS = build/$(ARCH)/programs
DHCP := $(PROGRAMS)/dhcp/usr/lib/werewolf/dhcp
DHCP_BIN := $(if $(filter dhcp,$(CHAIN)),$(DHCP))
CLOUD := $(PROGRAMS)/cloud/usr/lib/werewolf/cloud
CLOUD_BIN := $(if $(filter cloud,$(CHAIN)),$(CLOUD))
BITE_CLEANUP := $(PROGRAMS)/bite-cleanup/usr/bin/bite-cleanup
BITE_CLEANUP_BIN := $(if $(filter bitten,$(CHAIN)),$(BITE_CLEANUP))
MOUNT_BIN := $(PROGRAMS)/mount/usr/lib/werewolf/mount
LOADER_BIN := $(PROGRAMS)/modules/usr/lib/werewolf/modules
# stage0's own /init (stage0/stage0.zig): the kernel's first process on every
# machine. In stage0's initramfs, not the root's.
STAGE0_BIN := $(PROGRAMS)/stage0/init
# The root's /init (init/init.zig), which stage0 hands over to: PID 1 until
# runit, in every form.
INIT_BIN := $(PROGRAMS)/init/init
NET_BIN := $(PROGRAMS)/net/usr/lib/werewolf/net
FENCE_BIN := $(PROGRAMS)/fence/usr/lib/werewolf/fence
POSTURE_BIN := $(PROGRAMS)/posture/usr/lib/werewolf/posture
# What a shell script used to do, one small program each (design/shell-free.md):
# runit's stages, reboot and poweroff, GRUB's environment block, and the
# commit, power-button, console and sshd services. The forms link to them.
SHELLFREE := stage reboot grubenv commit powerbtn console sshd-start
SHELLFREE_BINS := $(foreach p,$(SHELLFREE),$(PROGRAMS)/$(p)/usr/lib/werewolf/$(p))
UPDATER_BIN := $(if $(filter autoupdate,$(CHAIN)),$(PROGRAMS)/updater/usr/lib/werewolf/update)
STATUS_BIN := $(if $(filter demo,$(CHAIN)),$(PROGRAMS)/status/usr/lib/werewolf/status)
OVERLAY_DIRS := $(CHAIN_DIRS) build/$(ARCH)/$(FORM)$(if $(DEV),-dev)/ro $(PROGRAMS)/init $(PROGRAMS)/modules $(PROGRAMS)/net $(PROGRAMS)/fence $(PROGRAMS)/mount $(PROGRAMS)/posture $(addprefix $(PROGRAMS)/,$(SHELLFREE)) $(if $(DHCP_BIN),$(PROGRAMS)/dhcp) $(if $(CLOUD_BIN),$(PROGRAMS)/cloud) $(if $(BITE_CLEANUP_BIN),$(PROGRAMS)/bite-cleanup) $(if $(UPDATER_BIN),$(PROGRAMS)/updater) \
	$(if $(STATUS_BIN),$(PROGRAMS)/status)

# A form that includes bitten boots from a slot, which bite installs; the
# others boot directly, from the initramfs.
SLOT := $(filter bitten,$(CHAIN))

# --- locks --------------------------------------------------------------------
# Every package in an image is pinned by a lock, apko's own, covering both
# architectures: one for the form, one for stage0, and one for the kernel,
# Alpine's linux-virt from the branch kernel/kernel.yaml names. A build
# installs exactly what its locks name, and everything after apko depends
# only on its input, so the same locks and the same tree give the same
# bytes. A lock is resolved from the repositories as they are when it is
# missing or older than its config; `make lock` resolves the form's again.
# CI does that every 15 minutes, and releases when the result changes.
LOCK = build/lock
LOCKS = $(FORM_LOCK) $(LOCK)/stage0.lock.json $(LOCK)/kernel.lock.json

# DEV=1 builds a form with a shell, for debugging and for test/checks, which
# run as root on the console: busybox-full on top of the form's packages,
# locked apart, and built apart, in build/<arch>/<form>-dev. No form needs
# it to work; the forms that log people in carry busybox-full themselves.
DEV ?=
FORM_LOCK = $(LOCK)/$(FORM)$(if $(DEV),-dev).lock.json

# apko lock CONFIG, from CONFIG's directory, where apko resolves include:,
# and then from forms/, for DEV's config.
apko_lock = mkdir -p $(LOCK) && cd $(dir $(1)) && \
	apko lock --arch aarch64,x86_64 --include-paths $(CURDIR)/forms --output $(CURDIR)/$@ $(notdir $(1))

# apko build-minirootfs CONFIG into $@, pinned to every package LOCK names
# for ARCH. apko writes the pins into /etc/apk/world; meta puts the plain
# world back, so the machine's own apk is not held to them.
define apko_build
pins=$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(.*\)-\([^-]*-r[0-9]*\)\.apk".*|-p \1=\2|p' $(2)) && \
	[ -n "$$pins" ] || { echo "$(2) names no packages for $(ARCH); make lock" >&2; exit 1; }; \
	mkdir -p $(dir $@) && cd $(dir $(1)) && \
	apko build-minirootfs --build-arch $(ARCH) $$pins $(notdir $(1)) $(CURDIR)/$@
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

# Leaf modules a form carries, from forms/<name>.modules along its include
# chain, as its folders are. A line may start with an arch and a colon to
# apply to that arch alone. modules.dep lists each leaf's transitive
# dependencies; read back to front that is a load order, which is what
# werewolf.modules holds and init insmods. No kmod index files travel, so
# there is nothing describing the 880 modules that stay behind. init closes
# the loader once these are in.
MODULES := $(shell for f in $(CHAIN); do [ -f forms/$$f.modules ] && cat forms/$$f.modules; done | \
	awk -v a=$(ARCH) '{ c = index($$0, sprintf("%c", 35)); if (c) $$0 = substr($$0, 1, c - 1) } \
		$$1 ~ /:$$/ { if ($$1 != a ":") next; $$1 = "" } { print }')
MODULE_LISTS := $(wildcard $(addprefix forms/,$(addsuffix .modules,$(CHAIN))))

# The network policy, from forms/<name>.net along the chain: `listen tcp/PORT`
# for what a form serves, `connect USER|all tcp/PORT udp/PORT icmp` for what
# its programs may send, by the user they run as, and `metadata USER` for
# who may reach the cloud's metadata server. Nothing undeclared is sent or
# received. meta compiles it to numbers, users to uids from the
# image's own /etc/passwd, in /usr/share/werewolf/net, which fence enforces
# (design/fence.md). A line it cannot compile fails the build.
NET_LISTS := $(wildcard $(addprefix forms/,$(addsuffix .net,$(CHAIN))))

BUILD = build/$(ARCH)
OUT = $(BUILD)/$(FORM)$(if $(DEV),-dev)
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
# A Linux host without /dev/kvm (some CI runners) emulates, slowly.
ifeq ($(ARCH),$(HOST_ARCH))
ACCEL = $(if $(filter Darwin,$(HOST_OS)),hvf,$(if $(wildcard /dev/kvm),kvm,tcg))
CPU = $(if $(filter tcg,$(ACCEL)),max,host)
VMTYPE = $(if $(filter Darwin,$(HOST_OS)),vz,qemu)
else
ACCEL = tcg
CPU = max
VMTYPE = qemu
endif
LIMA_CONSOLE = $(if $(filter vz,$(VMTYPE)),hvc0,$(CONSOLE))

.PHONY: all image slot disk run lima lima-stop demo demo-stop ssh config forms test check check-form check-slot check-slot-boot check-nodata check-nodata-boot check-lease check-lease-boot check-unsigned check-unsigned-boot check-unsigned-slot check-metadata check-metadata-boots lima-ci lock inputs dist dist-form posture clean help

all: image

image: $(BUILD)/vmlinuz $(OUT)/initramfs.zst

$(FORM_LOCK): $(addprefix forms/,$(addsuffix .yaml,$(CHAIN))) $(if $(DEV),$(BUILD)/dev/$(FORM)-dev.yaml)
	$(call apko_lock,$(if $(DEV),$(BUILD)/dev/$(FORM)-dev.yaml,forms/$(FORM).yaml))

# DEV's config: the form, and a shell. It has a name of its own, since one
# that included its own name would find itself.
$(BUILD)/dev/%-dev.yaml:
	mkdir -p $(dir $@) && printf 'include: %s.yaml\ncontents:\n  packages:\n    - busybox-full\n' $* >$@

$(LOCK)/stage0.lock.json: stage0/stage0.yaml
	$(call apko_lock,$<)

$(LOCK)/kernel.lock.json: kernel/kernel.yaml
	$(call apko_lock,$<)

lock:
	rm -f $(LOCKS)
	$(MAKE) --no-print-directory FORM=$(FORM) $(LOCKS)

# --- kernel -------------------------------------------------------------------
# Alpine's linux-virt, installed by apko with the rest of what it depends on,
# checked against the Alpine keys in forms/autoupdate. Only the kernel and
# its modules are kept.
$(BUILD)/kernel/rootfs.tar: $(LOCK)/kernel.lock.json
	$(call apko_build,kernel/kernel.yaml,$<)

$(BUILD)/vmlinuz: $(BUILD)/kernel/rootfs.tar
	rm -rf $(BUILD)/kernel/x
	mkdir -p $(BUILD)/kernel/x
	$(TAR) -xf $< -C $(BUILD)/kernel/x boot/vmlinuz-virt lib/modules
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

# Decompressed here: Alpine's kernel cannot (MODULE_DECOMPRESS is off), and
# the loader hands it each file as it is. The initramfs is compressed whole.
$(OUT)/modules.tar: $(BUILD)/vmlinuz $(MODULE_LISTS) $(ALLOW_FILES) Makefile
	rm -rf $(OUT)/modules
	kver=$$(ls $(BUILD)/kernel/x/lib/modules); \
	src=$(BUILD)/kernel/x/lib/modules/$$kver; \
	dst=$(OUT)/modules/usr/lib/modules/$$kver; \
	mkdir -p $$dst && : > $$dst/all && \
	for m in $(MODULES); do \
		paths=$$(awk -v m="$$m" '$$1 ~ ("/" m "\\.ko\\.gz:$$") { sub(":", "", $$1); for (i = NF; i >= 1; i--) print $$i }' $$src/modules.dep); \
		[ -n "$$paths" ] || { echo "module $$m not in $$src/modules.dep" >&2; exit 1; }; \
		echo "$$paths" >> $$dst/all; \
	done && \
	awk '!seen[$$0]++' $$dst/all > $$dst/all.gz && rm $$dst/all && \
	sed 's/\.gz$$//' $$dst/all.gz | awk -v params='$(MODULE_PARAMS)' ' \
		BEGIN { n = split(params, p, " "); for (i = 1; i <= n; i++) { c = index(p[i], ":"); \
			m = substr(p[i], 1, c - 1); want[m] = want[m] " " substr(p[i], c + 1) } } \
		{ m = $$0; sub(".*/", "", m); sub("\\.ko$$", "", m); if (m in want) { $$0 = $$0 want[m]; delete want[m] } print } \
		END { for (m in want) { printf "module parameters for %s, which the form does not carry\n", m > "/dev/stderr"; exit 1 } }' \
		> $$dst/werewolf.modules && \
	for p in $$(cat $$dst/all.gz); do mkdir -p $$dst/$$(dirname $$p) && gunzip -c $$src/$$p > $$dst/$${p%.gz}; done && \
	rm $$dst/all.gz
	$(call layer,$(OUT)/modules)

# apko resolves `include:` against its working directory, and
# build-minirootfs has no flag to change that, so it runs inside forms/.
# Under DEV the form's own config serves: the lock's pins, passed as extra
# packages, bring the shell.
$(OUT)/rootfs.tar: $(FORM_LOCK)
	$(call apko_build,forms/$(FORM).yaml,$<)

# werewolf's own files: each form's folder along the chain, then meta.
$(OUT)/overlay.tar: $(OUT)/meta.stamp $(OUT)/ro.stamp $(shell find $(CHAIN_DIRS) -type f) $(DHCP_BIN) $(CLOUD_BIN) $(BITE_CLEANUP_BIN) $(LOADER_BIN) $(NET_BIN) $(FENCE_BIN) $(MOUNT_BIN) $(POSTURE_BIN) $(INIT_BIN) $(SHELLFREE_BINS) $(UPDATER_BIN) $(STATUS_BIN)
	$(call layer,$(OVERLAY_DIRS) $(OUT)/meta)

# Booted directly, the machine boots as a slot does, through stage0, onto
# the same root.erofs, read-only: the slot's stage0, then a second cpio
# holding root.erofs, which the kernel unpacks after it and stage0 mounts.
$(OUT)/initramfs.zst: $(OUT)/slot/initramfs.zst $(OUT)/slot/root.erofs
	@[ "$(firstword $(CHAIN))" = minimal ] || \
		{ echo "form $(FORM) does not include minimal, which carries /init" >&2; exit 1; }
	rm -rf $(OUT)/direct && mkdir -p $(OUT)/direct && cp $(OUT)/slot/root.erofs $(OUT)/direct/ && \
		TZ=UTC touch -t 197001010000 $(OUT)/direct/root.erofs && \
		(cd $(OUT)/direct && $(TAR) -cf - --format newc --uid 0 --gid 0 --numeric-owner root.erofs) | \
		zstd -1 -q -c > $(OUT)/direct.cpio.zst && \
		cat $(OUT)/slot/initramfs.zst $(OUT)/direct.cpio.zst > $@
	rm -rf $(OUT)/direct $(OUT)/direct.cpio.zst
	@echo "form $(FORM): $(CHAIN)"
	@ls -la $(BUILD)/vmlinuz $@

# What a read-only root needs that a form cannot spell out by hand: each
# service's supervise directory, along the chain, as a link into
# /run/runit, and apko's accounts, from which init seeds /run/werewolf
# (the image's /etc/passwd, group and shadow link there). A layer of the
# overlay, so the updater carries it forward too.
$(OUT)/ro.stamp: $(OUT)/rootfs.tar $(shell find $(CHAIN_DIRS) -type d -path '*/etc/sv/*') Makefile
	rm -rf $(OUT)/ro && mkdir -p $(OUT)/ro/usr/share/werewolf/etc && \
	for f in passwd group shadow; do \
		$(TAR) -xOf $(OUT)/rootfs.tar etc/$$f > $(OUT)/ro/usr/share/werewolf/etc/$$f || exit 1; \
	done && \
	for s in $$(for c in $(CHAIN_DIRS); do [ -d $$c/etc/sv ] && ls $$c/etc/sv; done | LC_ALL=C sort -u); do \
		mkdir -p $(OUT)/ro/etc/sv/$$s && ln -s /run/runit/supervise.$$s $(OUT)/ro/etc/sv/$$s/supervise || exit 1; \
	done
	touch $@

# --- zig ----------------------------------------------------------------------
define zig_build
@[ "$$(zig version)" = "$(ZIG_VERSION)" ] || \
	{ echo "$< is written for zig $(ZIG_VERSION), not $$(zig version)" >&2; exit 1; }
mkdir -p $(dir $@)
zig build-exe -O ReleaseSafe -fstrip -target $(ARCH)-linux-musl -femit-bin=$@ $<
endef

$(DHCP): dhcp/dhcp.zig
	$(zig_build)

$(BITE_CLEANUP): bite-cleanup/bite-cleanup.zig
	$(zig_build)

$(CLOUD): cloud/cloud.zig
	$(zig_build)

$(MOUNT_BIN): mount/mount.zig
	$(zig_build)

$(LOADER_BIN): modules/modules.zig
	$(zig_build)

$(FENCE_BIN): fence/fence.zig
	$(zig_build)

$(NET_BIN): net/net.zig
	$(zig_build)

$(PROGRAMS)/updater/usr/lib/werewolf/update: updater/update.zig updater/sandbox.zig updater/cve.zig
	$(zig_build)

$(PROGRAMS)/status/usr/lib/werewolf/status: status/status.zig
	$(zig_build)

$(POSTURE_BIN): posture/posture.zig
	$(zig_build)

$(INIT_BIN): init/init.zig
	$(zig_build)

define shellfree_rule
$(PROGRAMS)/$(1)/usr/lib/werewolf/$(1): $(1)/$(1).zig
	$$(zig_build)
endef
$(foreach p,$(SHELLFREE),$(eval $(call shellfree_rule,$(p))))

test:
	zig fmt --check dhcp cloud bite-cleanup modules net fence mount posture updater status disk stage0 init $(SHELLFREE)
	zig test dhcp/dhcp.zig
	zig test cloud/cloud.zig
	zig test mount/mount.zig
	zig test modules/modules.zig
	zig test net/net.zig
	zig test fence/fence.zig
	zig test updater/update.zig
	zig test status/status.zig
	zig test posture/posture.zig
	zig test disk/gpt.zig
	zig test stage0/stage0.zig
	zig test init/init.zig
	zig test bite-cleanup/bite-cleanup.zig
	for p in $(SHELLFREE); do zig test $$p/$$p.zig || exit 1; done

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
# update in forms/autoupdate rebuilds a slot as `make slot` does, from these.
# In every image, in /usr/share/werewolf. Nothing here says when or where it
# was built, so a rebuild matches.
$(OUT)/meta.stamp: $(OUT)/ro.stamp $(OUT)/rootfs.tar $(BUILD)/stage0/rootfs.tar $(BUILD)/kernel/rootfs.tar $(STAGE0_BIN) $(MODULE_LISTS) $(NET_LISTS) $(shell find $(CHAIN_DIRS) -type f) $(DHCP_BIN) $(CLOUD_BIN) $(BITE_CLEANUP_BIN) $(LOADER_BIN) $(NET_BIN) $(FENCE_BIN) $(MOUNT_BIN) $(POSTURE_BIN) $(INIT_BIN) $(SHELLFREE_BINS) $(UPDATER_BIN) $(STATUS_BIN) Makefile
	rm -rf $(OUT)/meta
	d=$(OUT)/meta/usr/share/werewolf && mkdir -p $$d $(OUT)/meta/etc/apk && \
	kernel=$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(linux-virt-[^/]*\)\.apk".*|\1|p' $(LOCK)/kernel.lock.json) && \
	echo $(FORM) > $$d/form && \
	echo $(MODULES) | tr ' ' '\n' > $$d/modules && \
	for p in $(MODULE_PARAMS); do echo "$${p%%:*} $${p#*:}"; done > $$d/module-params && \
	echo $(KERNEL_ARGS) > $$d/cmdline && \
	echo $$kernel > $$d/kernel && \
	$(TAR) -xOf $(BUILD)/kernel/rootfs.tar etc/apk/repositories > $$d/alpine && \
	for c in $(OVERLAY_DIRS); do (cd $$c && find . \( -type f -o -type l \) ! -name .DS_Store | sed 's|^\./||'); done | LC_ALL=C sort -u > $$d/overlay && \
	$(TAR) -xOf $(BUILD)/stage0/rootfs.tar etc/apk/world | grep -v = > $$d/stage0.world && \
	$(TAR) -xOf $(OUT)/rootfs.tar etc/apk/world | grep -v = > $(OUT)/meta/etc/apk/world && \
	cp $(STAGE0_BIN) $$d/stage0.init && \
	echo "$(FORM) $$kernel built-by-make" > $$d/release && \
	$(TAR) -xOf $(OUT)/rootfs.tar etc/passwd > $(OUT)/passwd && \
	awk -v pw=$(OUT)/passwd ' \
		FILENAME == pw { split($$0, a, ":"); uid[a[1]] = a[3]; next } \
		{ c = index($$0, sprintf("%c", 35)); if (c) $$0 = substr($$0, 1, c - 1) } \
		NF == 0 { next } \
		$$1 == "listen" && NF > 1 { for (i = 2; i <= NF; i++) { \
			if ($$i !~ /^tcp\/[0-9]+$$/ || substr($$i, 5) + 0 < 1 || substr($$i, 5) + 0 > 65535) bad(); \
			print "listen tcp " substr($$i, 5) + 0 } next } \
		$$1 == "metadata" && NF > 1 { for (i = 2; i <= NF; i++) { if (!($$i in uid)) bad(); print "metadata " uid[$$i] } next } \
		$$1 == "connect" && NF > 2 { who = $$2 == "all" ? "all" : ($$2 in uid ? uid[$$2] : bad()); \
			for (i = 3; i <= NF; i++) { \
				if ($$i == "icmp") { print "connect " who " icmp"; continue } \
				if ($$i !~ /^(tcp|udp)\/[0-9]+$$/ || substr($$i, 5) + 0 < 1 || substr($$i, 5) + 0 > 65535) bad(); \
				print "connect " who " " substr($$i, 1, 3) " " substr($$i, 5) + 0 } next } \
		{ bad() } \
		function bad() { printf "%s:%d: cannot compile: %s\n", FILENAME, FNR, $$0 > "/dev/stderr"; exit 1 }' \
		$(OUT)/passwd $(NET_LISTS) > $(OUT)/net && \
	LC_ALL=C sort -u $(OUT)/net > $$d/net && rm $(OUT)/net $(OUT)/passwd
	touch $@

# --- disk ---------------------------------------------------------------------
# werewolf's own boot disk (design/native-boot.md): GPT, an EFI partition
# holding systemd-boot and slot a's kernel and stage0, and an ext4 partition
# holding slot a's root.erofs, laid out as bite leaves a distro's. UEFI
# firmware boots it anywhere, and it updates itself as a bitten machine does.
# Only forms that boot from a slot have one. systemd-boot comes from Wolfi,
# pinned by a lock like the kernel's; the partition table is written by
# disk/gpt.zig, built for this host. DISK_MIB is the disk's size;
# DISK_ARGS go on the kernel command line, and updates carry them over.
DISK ?= $(OUT)/disk.img
DISK_MIB ?= 8192
DISK_ARGS ?=
GPT_BIN = build/host/gpt

$(LOCK)/boot.lock.json: disk/boot.yaml
	$(call apko_lock,$<)

$(BUILD)/boot/rootfs.tar: $(LOCK)/boot.lock.json
	$(call apko_build,disk/boot.yaml,$<)

$(GPT_BIN): disk/gpt.zig
	@[ "$$(zig version)" = "$(ZIG_VERSION)" ] || \
		{ echo "$< is written for zig $(ZIG_VERSION), not $$(zig version)" >&2; exit 1; }
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -femit-bin=$@ $<

disk: $(DISK)

$(DISK): $(OUT)/slot/vmlinuz $(OUT)/slot/initramfs.zst $(OUT)/slot/root.erofs $(OUT)/slot/cmdline \
		$(BUILD)/boot/rootfs.tar $(GPT_BIN) disk/build
	@[ -n "$(SLOT)" ] || { echo "form $(FORM) does not boot from a slot; build on bitten" >&2; exit 1; }
	disk/build $(ARCH) $(BUILD)/boot/rootfs.tar $(GPT_BIN) $(OUT)/slot $@ $(DISK_MIB) $(DISK_ARGS)

# --- slot ---------------------------------------------------------------------
# The same rootfs, booted from disk: a small stage0 initramfs that loads the
# modules and mounts root.erofs read-only at / (stage0/stage0.zig).
# This is what bite installs, and what autoupdate rebuilds on the machine.
# root.erofs is made straight from the tar, as the cpio is; the modules stay
# in stage0, since they are loaded before the root exists.
slot: $(OUT)/slot/vmlinuz $(OUT)/slot/initramfs.zst $(OUT)/slot/root.erofs $(OUT)/slot/cmdline
	@ls -la $(OUT)/slot

# The kernel arguments the image asks for, beside it, for bite and
# disk/build to boot it with: the same as its /usr/share/werewolf/cmdline.
$(OUT)/slot/cmdline: $(OUT)/meta.stamp
	mkdir -p $(dir $@)
	cp $(OUT)/meta/usr/share/werewolf/cmdline $@

$(BUILD)/stage0/rootfs.tar: $(LOCK)/stage0.lock.json
	$(call apko_build,stage0/stage0.yaml,$<)

$(STAGE0_BIN): stage0/stage0.zig
	$(zig_build)

$(BUILD)/stage0/init.tar: $(STAGE0_BIN) $(LOADER_BIN)
	rm -rf $(BUILD)/stage0/files && mkdir -p $(BUILD)/stage0/files/usr/lib/werewolf && \
		cp $(STAGE0_BIN) $(BUILD)/stage0/files/init && cp $(LOADER_BIN) $(BUILD)/stage0/files/usr/lib/werewolf/
	$(call layer,$(BUILD)/stage0/files)

$(OUT)/slot/initramfs.zst: $(BUILD)/stage0/rootfs.tar $(BUILD)/stage0/init.tar $(OUT)/modules.tar
	mkdir -p $(dir $@)
	$(TAR) -cf $(OUT)/stage0.cpio --format newc --uid 0 --gid 0 --numeric-owner \
		@$(BUILD)/stage0/rootfs.tar @$(BUILD)/stage0/init.tar @$(OUT)/modules.tar
	zstd -19 -T0 -q -f -o $@ $(OUT)/stage0.cpio
	rm $(OUT)/stage0.cpio

# LZMA in 1 MiB clusters, with small files packed together and duplicates
# kept once: the densest erofs makes, as small as the root as a zstd -19
# tar, since direct boot holds it in RAM, and the one every common
# mkfs.erofs can write (Homebrew's, Ubuntu's). zstd would read about five
# times faster for about a fifth more size (prod: 8.2 MB, 0.08 s to read
# every file cold, against LZMA's 6.8 MB and 0.42 s), but Homebrew's
# erofs-utils is built without it; lz4hc was both larger and slower (13.0
# MB, 1.0 s). werewolf reads its root mostly at startup, and then from the
# page cache. A slot the updater builds on the machine is zstd: Wolfi's
# mkfs.erofs has no LZMA. -b 4096 because mkfs.erofs
# otherwise takes the builder's page size, 16 KiB on Apple silicon, which a
# 4 KiB-page kernel will not mount. -T0 dates every file and the image
# 1970, and the UUID is fixed (stage0 finds the image by path), so a rebuild
# matches. erofs-utils before 1.9 (Ubuntu 24.04 has 1.7.1) take
# -Eall-fragments from a tar and write every file empty, without an error,
# so older ones are refused, as are ones built without LZMA.
EROFS_OPTS = -b 4096 -zlzma,level=109 -C1048576 -Eall-fragments,dedupe
$(OUT)/slot/root.erofs: $(OUT)/rootfs.tar $(OUT)/overlay.tar
	mkdir -p $(dir $@)
	@# The root directory itself, first: without an entry for it, mkfs.erofs
	@# gives / the builder's uid and mode 0777, which sshd's StrictModes
	@# rightly refuses keys under.
	printf '#mtree\n./ type=dir uid=0 gid=0 uname=root gname=root mode=0755 time=0.0\n' >$(OUT)/root.mtree
	$(TAR) -cf $(OUT)/root.tar --uid 0 --gid 0 --numeric-owner @$(OUT)/root.mtree @$(OUT)/rootfs.tar @$(OUT)/overlay.tar
	rm -f $@
	@v=$$(mkfs.erofs --version 2>/dev/null | sed -n 's/.*erofs-utils) *//p'); case $$v in '' | 1.[0-8] | 1.[0-8].*) \
		echo "mkfs.erofs $${v:-before 1.9}: 1.9 or later is needed; older ones write an image of empty files" >&2; exit 1 ;; esac
	@{ mkfs.erofs --version; mkfs.erofs --help; } 2>&1 | grep -q 'available compressors:.*lzma' || \
		{ echo "mkfs.erofs has no LZMA: an erofs-utils built with liblzma is needed" >&2; exit 1; }
	mkfs.erofs $(EROFS_OPTS) -T0 -U 00000000-0000-0000-0000-000000000000 --tar=f $@ $(OUT)/root.tar >/dev/null
	rm $(OUT)/root.tar $(OUT)/root.mtree

$(OUT)/slot/vmlinuz: $(BUILD)/vmlinuz
	mkdir -p $(dir $@)
	cp $< $@

# --- release ------------------------------------------------------------------
# CI publishes these forms for both architectures (docs/releases.md). `make
# inputs` resolves their locks afresh and writes what the release would be
# built from: a digest of the files that build it, and every package's URL.
# CI builds only when that changes. `make dist` puts each form's files in
# dist/ as a release names them, with its manifest, unsigned.
RELEASE_FORMS = minimal prod prod-ssh
DIST = dist

inputs:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FORM=$$f lock || exit 1; done
	{ echo "tree $$(src='Makefile forms kernel stage0 dhcp cloud modules net fence mount posture updater'; \
		{ find $$src -type f ! -name .DS_Store | LC_ALL=C sort | xargs $(SHA256); \
		  find $$src -type f -perm -100 | LC_ALL=C sort; } | $(SHA256) | cut -c1-64)"; \
	  sed -n 's|.*"url": "\([^"]*\.apk\)".*|\1|p' \
		$(addprefix $(LOCK)/,$(addsuffix .lock.json,$(RELEASE_FORMS) stage0 kernel)) | LC_ALL=C sort -u; \
	} > $(LOCK)/inputs
	@echo "inputs: $$($(SHA256) < $(LOCK)/inputs | cut -c1-16), $$(grep -c '^https' $(LOCK)/inputs) packages"

dist:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FORM=$$f dist-form || exit 1; done

dist-form: $(if $(SLOT),slot,image) $(OUT)/meta.stamp $(OUT)/slot/cmdline
	release/manifest $(FORM) $(ARCH) $(OUT)/rootfs.tar $(OUT)/meta/usr/share/werewolf/kernel $(DIST) \
		$(if $(SLOT),vmlinuz=$(OUT)/slot/vmlinuz stage0.zst=$(OUT)/slot/initramfs.zst root.erofs=$(OUT)/slot/root.erofs,vmlinuz=$(BUILD)/vmlinuz initramfs.zst=$(OUT)/initramfs.zst) \
		cmdline=$(OUT)/slot/cmdline

forms:
	@for y in forms/*.yaml; do \
		f=$${y#forms/}; f=$${f%.yaml}; c=$$f; i=$$f; \
		while i=$$(sed -n 's/^include: *\(.*\)\.yaml$$/\1/p' forms/$$i.yaml); [ -n "$$i" ]; do c="$$i > $$c"; done; \
		printf '%-18s %s\n' "$$f" "$$c"; \
	done

# --- config -------------------------------------------------------------------
# config/ is a directory you keep (gitignored); `make config` packs it into a
# tar that is attached to the VM as a raw disk. init finds it by the ustar
# magic, so it can sit on any block device on any provider. See README for
# the files init honours.
config: $(BUILD)/config.tar

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

$(BUILD)/data.img:
	mkdir -p $(BUILD)
	dd if=/dev/zero of=$@ bs=1048576 count=0 seek=8192 status=none

QEMU = qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic

run: image $(BUILD)/data.img $(if $(wildcard config),config)
	$(QEMU) -smp 4 -m 2048 \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst \
		-append "console=$(CONSOLE) $(KERNEL_ARGS) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 werewolf.data=vda werewolf.debug=1" \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8080-:80 -device virtio-net-pci,netdev=n0 \
		-device virtio-rng-pci -drive file=$(BUILD)/data.img,format=raw,if=virtio $(QEMU_CONFIG)

ssh:
	ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1

# --- checks -------------------------------------------------------------------
# `make check` boots every form under QEMU, then a slot as bite leaves one,
# and runs test/checks on each as root on its console (test/boot). Each
# machine gets a blank disk and a config disk of its own, and nothing listens
# on the host, so `make -j check` runs them side by side. The config holds
# only data.key, a fixed test key, so crypt puts /data in LUKS2. Builds and
# consoles are logged in build/<arch>/check/. See docs/testing.md.
FORMS := $(patsubst forms/%.yaml,%,$(wildcard forms/*.yaml))
CHECK = $(BUILD)/check
# Every form is checked as built with DEV=1, since test/checks needs a root
# shell on the console; the forms that ship without one are also booted as
# they ship (check-shellfree-%).
CHECK_MAKE = $(MAKE) --no-print-directory DEV=1
SHELLFREE_FORMS = minimal prod demo
SHELLFREE_CHECKS = $(addprefix check-shellfree-,$(SHELLFREE_FORMS))
# romfile= because direct boot needs no network boot ROM, and CI has none.
CHECK_QEMU = $(QEMU) -smp 2 -m 1024 -no-reboot -device virtio-rng-pci \
	-netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile=
# panic=1 with -no-reboot: a panic ends QEMU at once rather than hanging.
# werewolf.check=1 adds posture's attacks, which write to the kernel log.
CHECK_BOOT = console=$(CONSOLE) $(KERNEL_ARGS) panic=1 werewolf.debug=1 werewolf.check=1
# The posture checks known to fail on the form and architecture, for
# test/boot to expect.
export POSTURE_KNOWN = $(shell awk -v b=$(if $(DEV),dev,*) -v f=$(FORM) -v a=$(ARCH) '$$1 == b || $$1 == f || $$1 == a { $$1 = ""; k = k $$0 } END { print k }' test/posture-known)
CHECK_CMDLINE = $(CHECK_BOOT) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3
# What every form shares, built once before the forms build side by side.
CHECK_SHARED = $(BUILD)/vmlinuz $(BUILD)/stage0/rootfs.tar $(BUILD)/stage0/init.tar $(DHCP) $(CLOUD) $(BITE_CLEANUP) $(LOADER_BIN) $(NET_BIN) $(FENCE_BIN) $(MOUNT_BIN) $(POSTURE_BIN) $(INIT_BIN) $(SHELLFREE_BINS) $(PROGRAMS)/updater/usr/lib/werewolf/update
# bitten has no updater, which would fetch from the network once committed.
CHECK_SLOT_FORM = bitten
VICTIM_UUID = 0e7e1f00-c4ec-4b00-8000-00000000c4ec

check: $(addprefix check-,$(FORMS)) $(SHELLFREE_CHECKS) check-slot check-nodata check-lease check-unsigned check-metadata
	@echo "check: every form, and a slot, passed"

check-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(CHECK_MAKE) FORM=$* image >$(CHECK)/$*-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/$*-build.log; echo "FAIL   $* build: see $(CHECK)/$*-build.log"; exit 1; }
	@$(CHECK_MAKE) FORM=$* check-form

check-form:
	@rm -f $(CHECK)/$(FORM).img && dd if=/dev/zero of=$(CHECK)/$(FORM).img bs=1048576 count=0 seek=1024 status=none
	@rm -rf $(CHECK)/$(FORM)-config && mkdir -p $(CHECK)/$(FORM)-config && \
		head -c 64 /dev/zero | tr '\0' k >$(CHECK)/$(FORM)-config/data.key && \
		$(if $(CHECK_SSH),rm -f $(CHECK)/$(FORM)-key $(CHECK)/$(FORM)-key.pub && \
			ssh-keygen -q -t ed25519 -N '' -C werewolf-check -f $(CHECK)/$(FORM)-key && \
			cp $(CHECK)/$(FORM)-key.pub $(CHECK)/$(FORM)-config/authorized_keys &&) \
		COPYFILE_DISABLE=1 $(TAR) --uid 0 --gid 0 --numeric-owner -cf $(CHECK)/$(FORM)-config.tar -C $(CHECK)/$(FORM)-config .
	@SSH_PORT=$(CHECK_SSH) SSH_KEY=$(CHECK)/$(FORM)-key test/boot $(FORM) test/checks $(CHECK)/$(FORM).log $(CHECK_FORM_QEMU)
	@SSH_PORT=$(CHECK_SSH) SSH_KEY=$(CHECK)/$(FORM)-key test/boot $(FORM)-again test/checks-again $(CHECK)/$(FORM)-again.log $(CHECK_FORM_QEMU)
	@! grep -a -E 'werewolf: (formatting|making LUKS2) ' $(CHECK)/$(FORM)-again.log || \
		{ echo "FAIL   $(FORM)-again        formatted the disk its first boot left"; exit 1; }

# The forms released without a shell, booted as they ship, without DEV:
# test/boot runs no checks there (CHECKS -) and judges the machine by its
# posture line alone, which must find no shell. A static pattern, so that
# it, not check-%, makes these.
$(SHELLFREE_CHECKS): check-shellfree-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(MAKE) --no-print-directory FORM=$* DEV= image >$(CHECK)/$*-shellfree-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/$*-shellfree-build.log; echo "FAIL   $*-shellfree build: see $(CHECK)/$*-shellfree-build.log"; exit 1; }
	@$(MAKE) --no-print-directory FORM=$* DEV= check-shellfree-boot

check-shellfree-boot:
	@rm -f $(CHECK)/$(FORM)-shellfree.img && dd if=/dev/zero of=$(CHECK)/$(FORM)-shellfree.img bs=1048576 count=0 seek=1024 status=none
	@test/boot $(FORM)-shellfree - $(CHECK)/$(FORM)-shellfree.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
		-drive file=$(CHECK)/$(FORM)-shellfree.img,format=raw,if=virtio

# The same disks both times: the second boot must find what the first left.
# A form that serves ssh, as its policy declares, is logged into from here
# on both its boots (test/boot): with a key made for the run, in its config,
# through port 22 forwarded from a port of its own, so forms boot side by
# side.
comma := ,
CHECK_SSH = $(if $(shell cat $(wildcard $(addprefix forms/,$(addsuffix .net,$(CHAIN)))) /dev/null | grep -x 'listen tcp/22'),$(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x '$(FORM)' | cut -d: -f1 | awk '{ print 22200 + $$1 }'))
CHECK_FORM_QEMU = $(if $(CHECK_SSH),$(subst user$(comma)id=n0,user$(comma)id=n0$(comma)hostfwd=tcp:127.0.0.1:$(CHECK_SSH)-:22,$(CHECK_QEMU)),$(CHECK_QEMU)) \
	-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
	-drive file=$(CHECK)/$(FORM).img,format=raw,if=virtio \
	-drive file=$(CHECK)/$(FORM)-config.tar,format=raw,if=virtio,readonly=on

# The dhcp form with no werewolf.ip: an address from QEMU's DHCP server, and
# the client split as it says it is. After dhcp's own check, which builds
# the same form in the same place.
check-lease: | $(CHECK_SHARED) check-dhcp
	@$(CHECK_MAKE) FORM=dhcp check-lease-boot

check-lease-boot:
	@test/boot lease test/checks-lease $(CHECK)/lease.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_BOOT)"
	@grep -a -q 'dhcp: {.*"event":"bound"' $(CHECK)/lease.log || \
		{ echo "FAIL   lease              no \"bound\" event on the console"; exit 1; }

# An unsigned module offered at boot must be refused: by init on a RAM root,
# and by stage0 on a slot. test/unsign cuts the signature off evdev, in a
# cpio appended to the initramfs, which the kernel unpacks last. After the
# checks that build the same forms in the same places.
check-unsigned: | $(CHECK_SHARED) check-minimal check-slot
	@$(CHECK_MAKE) FORM=minimal check-unsigned-boot
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) check-unsigned-slot

check-unsigned-boot:
	@test/unsign $(OUT)/modules.tar evdev $(CHECK)/unsigned-$(FORM).cpio.zst
	@cat $(OUT)/initramfs.zst $(CHECK)/unsigned-$(FORM).cpio.zst >$(CHECK)/unsigned-$(FORM).zst
	@test/boot unsigned test/checks-unsigned $(CHECK)/unsigned.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(CHECK)/unsigned-$(FORM).zst -append "$(CHECK_CMDLINE)"

check-unsigned-slot:
	@test/unsign $(OUT)/modules.tar evdev $(CHECK)/unsigned-$(FORM).cpio.zst
	@cat $(OUT)/slot/initramfs.zst $(CHECK)/unsigned-$(FORM).cpio.zst >$(CHECK)/unsigned-$(FORM).zst
	@cp $(CHECK)/victim.img $(CHECK)/unsigned-victim.img
	@test/boot unsigned-slot test/checks-unsigned $(CHECK)/unsigned-slot.log $(CHECK_QEMU) \
		-kernel $(OUT)/slot/vmlinuz -initrd $(CHECK)/unsigned-$(FORM).zst \
		-append "$(CHECK_CMDLINE) init=/init werewolf.slot=a werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.grubenv=$(VICTIM_UUID):/boot/grub/grubenv" \
		-drive file=$(CHECK)/unsigned-victim.img,format=raw,if=virtio

# The cloud form against a stand-in metadata server (test/metadata), five
# ways: a good config on GCP, AWS and Hetzner must be taken; a hostile one
# refused whole; and a machine on no cloud must not ask at all
# (test/cloud-boot). arm64 guests have SMBIOS only under UEFI firmware.
CLOUD_FIRMWARE = $(if $(filter aarch64,$(ARCH)),$(firstword $(wildcard \
	/opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/local/share/qemu/edk2-aarch64-code.fd \
	/usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd)))
METADATA_QEMU = $(QEMU) -smp 2 -m 1024 -no-reboot -device virtio-rng-pci \
	-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_BOOT)"
METADATA_BOOTS = "gcp good metadata" "aws good metadata" "hetzner good metadata" \
	"gcp hostile metadata-refused" "none good metadata-refused"

check-metadata: | $(CHECK_SHARED) check-cloud
	@$(CHECK_MAKE) FORM=cloud check-metadata-boots

check-metadata-boots:
	@[ "$(ARCH)" != aarch64 ] || [ -n "$(CLOUD_FIRMWARE)" ] || \
		{ echo "FAIL   metadata           no UEFI firmware for arm64 (edk2-aarch64-code.fd)"; exit 1; }
	@failed=0; for b in $(METADATA_BOOTS); do set -- $$b; \
		test/cloud-boot meta-$$1-$$2 $$1 $$2 test/checks-$$3 $(CHECK)/meta-$$1-$$2.log "$(CLOUD_FIRMWARE)" $(METADATA_QEMU) || failed=1; \
	done; exit $$failed

# crypt with a blank disk and no data.key must refuse, not make a key up.
# After crypt's own check, which builds the same form in the same place.
check-nodata: | $(CHECK_SHARED) check-crypt
	@$(CHECK_MAKE) FORM=crypt check-nodata-boot

check-nodata-boot:
	@rm -f $(CHECK)/nodata.img && dd if=/dev/zero of=$(CHECK)/nodata.img bs=1048576 count=0 seek=1024 status=none
	@test/boot nodata test/checks-nodata $(CHECK)/nodata.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
		-drive file=$(CHECK)/nodata.img,format=raw,if=virtio

# The slot path: stage0 finding root.erofs by filesystem UUID, the overlay,
# /victim read-only, and commit making the slot GRUB's default, which takes
# the minute commit waits. The victim is a small ext4 holding what bite
# leaves: the root image in slot a, and GRUB's environment block.
# After bitten's own check, which builds the same form in the same place.
check-slot: | $(CHECK_SHARED) check-$(CHECK_SLOT_FORM)
	@mkdir -p $(CHECK)
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) slot >$(CHECK)/slot-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/slot-build.log; echo "FAIL   slot build: see $(CHECK)/slot-build.log"; exit 1; }
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) check-slot-boot

check-slot-boot:
	@rm -rf $(CHECK)/victim $(CHECK)/victim.img
	@mkdir -p $(CHECK)/victim/var/lib/werewolf/a $(CHECK)/victim/boot/grub
	@cp $(OUT)/slot/root.erofs $(CHECK)/victim/var/lib/werewolf/a/
	@# A distro beside werewolf, for bite-cleanup: what it must delete, a
	@# name that only begins like one it keeps, and links that lead out.
	@v=$(CHECK)/victim; mkdir -p $$v/etc $$v/home/user/.ssh $$v/var/log $$v/var/lib/werewolf2 && \
		echo ID=debian >$$v/etc/os-release && echo secret >$$v/home/user/.ssh/id && echo log >$$v/var/log/syslog && \
		touch $$v/bootx && ln -s /run/werewolf $$v/etc/escape && ln -s ../../.. $$v/var/lib/up
	@env=$(CHECK)/victim/boot/grub/grubenv; \
		printf '# GRUB Environment Block\nsaved_entry=werewolf-b\nnext_entry=werewolf-a\n' >$$env; \
		head -c $$((1024 - $$(wc -c <$$env))) /dev/zero | tr '\0' '#' >>$$env
	@mke2fs -q -F -t ext4 -U $(VICTIM_UUID) -d $(CHECK)/victim $(CHECK)/victim.img 128M
	@test/boot slot test/checks $(CHECK)/slot.log $(CHECK_QEMU) \
		-kernel $(OUT)/slot/vmlinuz -initrd $(OUT)/slot/initramfs.zst \
		-append "$(CHECK_CMDLINE) init=/init werewolf.slot=a werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.grubenv=$(VICTIM_UUID):/boot/grub/grubenv" \
		-drive file=$(CHECK)/victim.img,format=raw,if=virtio
	@grep -a -o 'saved_entry=werewolf-[ab]' $(CHECK)/victim.img | sort -u | grep -qx saved_entry=werewolf-a || \
		{ echo "FAIL   slot               GRUB's default is not werewolf-a after commit"; exit 1; }
	@echo "pass   slot               GRUB's default is werewolf-a"

# The CI job, here: in an Ubuntu VM like GitHub's runners, with nested
# virtualization for KVM. See test/lima-ci.
lima-ci:
	test/lima-ci

# --- Lima ---------------------------------------------------------------------
# Lima needs a disk image to call the instance's. This one is 64 MiB of
# zeros, which Lima grows to 100 GiB and keeps until `limactl delete`; the
# lima form formats it as /data on first boot. The root is the initramfs
# either way.
$(BUILD)/disk.img:
	mkdir -p $(BUILD)
	dd if=/dev/zero of=$@ bs=1048576 count=64 status=none

$(OUT)/lima.yaml: lima.yaml.in Makefile $(ALLOW_FILES)
	mkdir -p $(OUT)
	sed -e 's|@BUILD@|$(CURDIR)/$(BUILD)|g' -e 's|@OUT@|$(CURDIR)/$(OUT)|g' -e 's|@VMTYPE@|$(VMTYPE)|g' \
		-e 's|@LIMA_ARCH@|$(ARCH)|g' -e 's|@CONSOLE@|$(LIMA_CONSOLE)|g' -e 's|@KERNEL_ARGS@|$(KERNEL_ARGS)|g' $< > $@

lima: image $(BUILD)/disk.img $(OUT)/lima.yaml
	limactl start --name werewolf --tty=false $(OUT)/lima.yaml

lima-stop:
	limactl stop -f werewolf
	limactl delete werewolf

# The demo form's boot disk in Lima, booted by its own systemd-boot and
# reached over vzNAT, since Lima cannot forward a port to a guest without
# ssh. The disk names vzNAT's MAC, fixed in test/lima-demo, so DHCP runs
# there. Its URL is printed at the end. See docs/demo.md.
DEMO_MAC = 52:55:55:57:e1:f0
demo:
	@$(MAKE) --no-print-directory FORM=demo disk DISK=build/$(ARCH)/demo/lima.img DISK_ARGS=werewolf.mac=$(DEMO_MAC)
	test/lima-demo build/$(ARCH)/demo/lima.img

demo-stop:
	test/lima-demo stop

clean:
	rm -rf build

help:
	@sed -n '2,20p' Makefile | cut -c3-

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
