# werewolf: a Wolfi userland on an Alpine kernel, booted from RAM.
#
#   make            build/<arch>/vmlinuz + build/<arch>/<form>/initramfs.zst
#   make run        boot it under QEMU, root shell on the console, ssh on :2222
#   make lima       boot the lima form under Lima (vz on Apple silicon)
#   make config     pack config/ into the raw config tar `run` attaches
#   make forms      list the forms and what each includes
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

# --- kernel -------------------------------------------------------------------
# Alpine's linux-virt: the KVM guest kernel, pinned by package and digest. The
# versioned branch is used rather than latest-stable so a bump here is the
# only way this changes.
ALPINE_BRANCH = v3.24
KERNEL_PKG = linux-virt-6.18.55-r0.apk
KERNEL_SHA256_aarch64 = c7fb892408d7fe163a18671e5c7816752976d1c67fd17794dfba794aa0d6c1ac
KERNEL_SHA256_x86_64 = a941c15fc5db26b6692fd0140fa0970da76cb12aadf3dc8306c419f21bd39c93
KERNEL_URL = https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_BRANCH)/main/$(ARCH)/$(KERNEL_PKG)
KERNEL_SHA256 = $(KERNEL_SHA256_$(ARCH))

# Leaf modules the initramfs carries. modules.dep lists each one's
# transitive dependencies; read back to front that is a load order, which
# is what werewolf.modules holds and init insmods. No kmod index files
# travel, so there is nothing describing the 880 modules that stay behind.
# virtio-pci and virtio-console are built in. init closes the loader once
# these are in.
#
# ext4 and dm-crypt are for /data. XTS and generic AES are built in, but the
# hardware AES drivers are modules, and with the loader closed nothing pulls
# them in on demand: without them dm-crypt still works, much slower, and
# says nothing. evdev and button carry the ACPI power button to the powerbtn
# service. Every form carries the same list.
MODULES = virtio_net virtio_blk virtio_scsi sr_mod isofs ext4 dm-crypt evdev button $(MODULES_$(ARCH))
MODULES_aarch64 = aes-ce-blk
MODULES_x86_64 = aesni-intel

BUILD = build/$(ARCH)
OUT = $(BUILD)/$(FORM)
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
ifeq ($(ARCH),$(HOST_ARCH))
ACCEL = $(if $(filter Darwin,$(HOST_OS)),hvf,kvm)
CPU = host
VMTYPE = $(if $(filter Darwin,$(HOST_OS)),vz,qemu)
else
ACCEL = tcg
CPU = max
VMTYPE = qemu
endif
LIMA_CONSOLE = $(if $(filter vz,$(VMTYPE)),hvc0,$(CONSOLE))

.PHONY: all image run lima lima-stop ssh config forms clean help

all: image

image: $(BUILD)/vmlinuz $(OUT)/initramfs.zst

$(BUILD)/kernel/$(KERNEL_PKG):
	mkdir -p $(dir $@)
	curl -fsSL -o $@.tmp $(KERNEL_URL)
	echo "$(KERNEL_SHA256)  $@.tmp" | $(SHA256) -c -
	mv $@.tmp $@

# The apk is three concatenated gzip streams (signature, control, data);
# bsdtar reads straight through them.
$(BUILD)/vmlinuz $(BUILD)/modules/.stamp: $(BUILD)/kernel/$(KERNEL_PKG) Makefile
	rm -rf $(BUILD)/kernel/x $(BUILD)/modules
	mkdir -p $(BUILD)/kernel/x
	$(TAR) -xzf $< -C $(BUILD)/kernel/x
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
	kver=$$(ls $(BUILD)/kernel/x/lib/modules); \
	src=$(BUILD)/kernel/x/lib/modules/$$kver; \
	dst=$(BUILD)/modules/usr/lib/modules/$$kver; \
	mkdir -p $$dst && : > $$dst/all && \
	for m in $(MODULES); do \
		paths=$$(awk -v m="$$m" '$$1 ~ ("/" m "\\.ko\\.gz:$$") { sub(":", "", $$1); for (i = NF; i >= 1; i--) print $$i }' $$src/modules.dep); \
		[ -n "$$paths" ] || { echo "module $$m not in $$src/modules.dep" >&2; exit 1; }; \
		echo "$$paths" >> $$dst/all; \
	done && \
	awk '!seen[$$0]++' $$dst/all > $$dst/werewolf.modules && rm $$dst/all && \
	for p in $$(cat $$dst/werewolf.modules); do mkdir -p $$dst/$$(dirname $$p) && cp $$src/$$p $$dst/$$p; done
	touch $(BUILD)/modules/.stamp

# apko resolves `include:` against its working directory, and
# build-minirootfs has no flag to change that, so it runs inside forms/.
$(OUT)/rootfs.tar: $(addprefix forms/,$(addsuffix .yaml,$(CHAIN)))
	mkdir -p $(OUT)
	cd forms && apko build-minirootfs --build-arch $(ARCH) $(FORM).yaml $(CURDIR)/$@

# One cpio: the apko rootfs as apko wrote it (ownership intact, never
# extracted on the host), then each form's folder along the chain, then the
# modules. Later entries win.
$(OUT)/initramfs.zst: $(OUT)/rootfs.tar $(BUILD)/modules/.stamp $(shell find $(CHAIN_DIRS) -type f)
	@[ "$(firstword $(CHAIN))" = minimal ] || \
		{ echo "form $(FORM) does not include minimal, which carries /init" >&2; exit 1; }
	COPYFILE_DISABLE=1 $(TAR) --format newc --uid 0 --gid 0 --numeric-owner --exclude .DS_Store \
		-cf $(OUT)/initramfs.cpio @$(OUT)/rootfs.tar \
		$(foreach d,$(CHAIN_DIRS),-C $(CURDIR)/$(d) .) -C $(CURDIR)/$(BUILD)/modules .
	zstd -19 -T0 -q -f -o $@ $(OUT)/initramfs.cpio
	rm $(OUT)/initramfs.cpio
	@echo "form $(FORM): $(CHAIN)"
	@ls -la $(BUILD)/vmlinuz $@

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

run: image $(BUILD)/data.img $(if $(wildcard config),config)
	qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -smp 4 -m 2048 -nographic \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst \
		-append "console=$(CONSOLE) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 werewolf.data=vda werewolf.debug=1" \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
		-device virtio-rng-pci -drive file=$(BUILD)/data.img,format=raw,if=virtio $(QEMU_CONFIG)

ssh:
	ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1

# --- Lima ---------------------------------------------------------------------
# Lima needs a disk image to call the instance's. This one is 64 MiB of
# zeros, which Lima grows to 100 GiB and keeps until `limactl delete`; the
# lima form formats it as /data on first boot. The root is the initramfs
# either way.
$(BUILD)/disk.img:
	mkdir -p $(BUILD)
	dd if=/dev/zero of=$@ bs=1048576 count=64 status=none

$(OUT)/lima.yaml: lima.yaml.in Makefile
	mkdir -p $(OUT)
	sed -e 's|@BUILD@|$(CURDIR)/$(BUILD)|g' -e 's|@OUT@|$(CURDIR)/$(OUT)|g' -e 's|@VMTYPE@|$(VMTYPE)|g' \
		-e 's|@LIMA_ARCH@|$(ARCH)|g' -e 's|@CONSOLE@|$(LIMA_CONSOLE)|g' $< > $@

lima: image $(BUILD)/disk.img $(OUT)/lima.yaml
	limactl start --name werewolf --tty=false $(OUT)/lima.yaml

lima-stop:
	limactl stop -f werewolf
	limactl delete werewolf

clean:
	rm -rf build

help:
	@sed -n '2,12p' Makefile | cut -c3-
