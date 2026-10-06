# werewolf: a Wolfi userland on an Alpine kernel, booted from RAM.
#
#   make            build/<arch>/vmlinuz + build/<arch>/<form>/initramfs.zst
#   make slot       build/<arch>/<form>/slot/: vmlinuz, stage0, root.erofs (for bite)
#   make run        boot it under QEMU, root shell on the console, ssh on :2222
#   make lima       boot the lima form under Lima (vz on Apple silicon)
#   make config     pack config/ into the raw config tar `run` attaches
#   make forms      list the forms and what each includes
#   make test       the updater's unit tests (zig)
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

# The autoupdate form's updater is built, not checked in: updater/update.zig,
# laid in like a form folder for any form whose chain includes autoupdate.
# Zig is pre-1.0 and changes between releases, so the build insists on the
# version the code is written for.
ZIG_VERSION = 0.16.0
UPDATER_BIN := $(if $(filter autoupdate,$(CHAIN)),build/$(ARCH)/updater/usr/lib/werewolf/update)
OVERLAY_DIRS := $(CHAIN_DIRS) $(if $(UPDATER_BIN),build/$(ARCH)/updater)

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
LOCKS = $(LOCK)/$(FORM).lock.json $(LOCK)/stage0.lock.json $(LOCK)/kernel.lock.json

# apko lock CONFIG, from CONFIG's directory, where apko resolves include:.
apko_lock = mkdir -p $(LOCK) && cd $(dir $(1)) && \
	apko lock --arch aarch64,x86_64 --output $(CURDIR)/$@ $(notdir $(1))

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

.PHONY: all image slot run lima lima-stop ssh config forms test check check-form check-slot check-slot-boot lima-ci lock inputs dist dist-form clean help

all: image

image: $(BUILD)/vmlinuz $(OUT)/initramfs.zst

$(LOCK)/$(FORM).lock.json: $(addprefix forms/,$(addsuffix .yaml,$(CHAIN)))
	$(call apko_lock,forms/$(FORM).yaml)

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

$(OUT)/modules.tar: $(BUILD)/vmlinuz $(MODULE_LISTS) Makefile
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
	awk '!seen[$$0]++' $$dst/all > $$dst/werewolf.modules && rm $$dst/all && \
	for p in $$(cat $$dst/werewolf.modules); do mkdir -p $$dst/$$(dirname $$p) && cp $$src/$$p $$dst/$$p; done
	$(call layer,$(OUT)/modules)

# apko resolves `include:` against its working directory, and
# build-minirootfs has no flag to change that, so it runs inside forms/.
$(OUT)/rootfs.tar: $(LOCK)/$(FORM).lock.json
	$(call apko_build,forms/$(FORM).yaml,$<)

# werewolf's own files: each form's folder along the chain, then meta.
$(OUT)/overlay.tar: $(OUT)/meta.stamp $(shell find $(CHAIN_DIRS) -type f) $(UPDATER_BIN)
	$(call layer,$(OVERLAY_DIRS) $(OUT)/meta)

# One cpio: the apko rootfs as apko wrote it (ownership intact, never
# extracted on the host), then werewolf's files, then the modules. Later
# entries win. Made from tars alone, its inode numbers are all zero.
$(OUT)/initramfs.zst: $(OUT)/rootfs.tar $(OUT)/overlay.tar $(OUT)/modules.tar
	@[ "$(firstword $(CHAIN))" = minimal ] || \
		{ echo "form $(FORM) does not include minimal, which carries /init" >&2; exit 1; }
	$(TAR) -cf $(OUT)/initramfs.cpio --format newc --uid 0 --gid 0 --numeric-owner \
		@$(OUT)/rootfs.tar @$(OUT)/overlay.tar @$(OUT)/modules.tar
	zstd -19 -T0 -q -f -o $@ $(OUT)/initramfs.cpio
	rm $(OUT)/initramfs.cpio
	@echo "form $(FORM): $(CHAIN)"
	@ls -la $(BUILD)/vmlinuz $@

# --- updater ------------------------------------------------------------------
build/$(ARCH)/updater/usr/lib/werewolf/update: updater/update.zig
	@[ "$$(zig version)" = "$(ZIG_VERSION)" ] || \
		{ echo "updater/update.zig is written for zig $(ZIG_VERSION), not $$(zig version)" >&2; exit 1; }
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -fstrip -target $(ARCH)-linux-musl -femit-bin=$@ updater/update.zig

test:
	zig fmt --check updater
	zig test updater/update.zig

# --- meta ---------------------------------------------------------------------
# What the build knows that the image will need to rebuild itself: the
# update in forms/autoupdate rebuilds a slot as `make slot` does, from these.
# In every image, in /usr/share/werewolf. Nothing here says when or where it
# was built, so a rebuild matches.
$(OUT)/meta.stamp: $(OUT)/rootfs.tar $(BUILD)/stage0/rootfs.tar $(BUILD)/kernel/rootfs.tar stage0/init $(MODULE_LISTS) $(shell find $(CHAIN_DIRS) -type f) $(UPDATER_BIN) Makefile
	rm -rf $(OUT)/meta
	d=$(OUT)/meta/usr/share/werewolf && mkdir -p $$d $(OUT)/meta/etc/apk && \
	kernel=$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(linux-virt-[^/]*\)\.apk".*|\1|p' $(LOCK)/kernel.lock.json) && \
	echo $(FORM) > $$d/form && \
	echo $(MODULES) | tr ' ' '\n' > $$d/modules && \
	echo $$kernel > $$d/kernel && \
	$(TAR) -xOf $(BUILD)/kernel/rootfs.tar etc/apk/repositories > $$d/alpine && \
	for c in $(OVERLAY_DIRS); do (cd $$c && find . -type f ! -name .DS_Store | sed 's|^\./||'); done | LC_ALL=C sort -u > $$d/overlay && \
	$(TAR) -xOf $(BUILD)/stage0/rootfs.tar etc/apk/world | grep -v = > $$d/stage0.world && \
	$(TAR) -xOf $(OUT)/rootfs.tar etc/apk/world | grep -v = > $(OUT)/meta/etc/apk/world && \
	cp stage0/init $$d/stage0.init && \
	echo "$(FORM) $$kernel built-by-make" > $$d/release
	touch $@

# --- slot ---------------------------------------------------------------------
# The same rootfs, booted from disk: a small stage0 initramfs that loads the
# modules and mounts root.erofs read-only under a RAM overlay (stage0/init).
# This is what bite installs, and what autoupdate rebuilds on the machine.
# root.erofs is made straight from the tar, as the cpio is; the modules stay
# in stage0, since they are loaded before the root exists.
slot: $(OUT)/slot/vmlinuz $(OUT)/slot/initramfs.zst $(OUT)/slot/root.erofs
	@ls -la $(OUT)/slot

$(BUILD)/stage0/rootfs.tar: $(LOCK)/stage0.lock.json
	$(call apko_build,stage0/stage0.yaml,$<)

$(BUILD)/stage0/init.tar: stage0/init
	rm -rf $(BUILD)/stage0/files && mkdir -p $(BUILD)/stage0/files && cp stage0/init $(BUILD)/stage0/files/
	$(call layer,$(BUILD)/stage0/files)

$(OUT)/slot/initramfs.zst: $(BUILD)/stage0/rootfs.tar $(BUILD)/stage0/init.tar $(OUT)/modules.tar
	mkdir -p $(dir $@)
	$(TAR) -cf $(OUT)/stage0.cpio --format newc --uid 0 --gid 0 --numeric-owner \
		@$(BUILD)/stage0/rootfs.tar @$(BUILD)/stage0/init.tar @$(OUT)/modules.tar
	zstd -19 -T0 -q -f -o $@ $(OUT)/stage0.cpio
	rm $(OUT)/stage0.cpio

# lz4hc: the root is read on demand, so decompression speed matters more
# than the last few percent of size. -b 4096 because mkfs.erofs otherwise
# takes the builder's page size, 16 KiB on Apple silicon, which a 4 KiB-page
# kernel will not mount. -T0 dates every file and the image 1970, and the
# UUID is fixed (stage0 finds the image by path), so a rebuild matches.
$(OUT)/slot/root.erofs: $(OUT)/rootfs.tar $(OUT)/overlay.tar
	mkdir -p $(dir $@)
	$(TAR) -cf $(OUT)/root.tar --uid 0 --gid 0 --numeric-owner @$(OUT)/rootfs.tar @$(OUT)/overlay.tar
	rm -f $@
	mkfs.erofs -b 4096 -zlz4hc -T0 -U 00000000-0000-0000-0000-000000000000 --tar=f $@ $(OUT)/root.tar >/dev/null
	rm $(OUT)/root.tar

$(OUT)/slot/vmlinuz: $(BUILD)/vmlinuz
	mkdir -p $(dir $@)
	cp $< $@

# --- release ------------------------------------------------------------------
# CI publishes these forms for both architectures (docs/releases.md). `make
# inputs` resolves their locks afresh and writes what the release would be
# built from: a digest of the files that build it, and every package's URL.
# CI builds only when that changes. `make dist` puts each form's files in
# dist/ as a release names them, with its manifest, unsigned.
RELEASE_FORMS = minimal prod-ssh
DIST = dist

inputs:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FORM=$$f lock || exit 1; done
	{ echo "tree $$(src='Makefile forms kernel stage0 updater'; \
		{ find $$src -type f ! -name .DS_Store | LC_ALL=C sort | xargs $(SHA256); \
		  find $$src -type f -perm -100 | LC_ALL=C sort; } | $(SHA256) | cut -c1-64)"; \
	  sed -n 's|.*"url": "\([^"]*\.apk\)".*|\1|p' \
		$(addprefix $(LOCK)/,$(addsuffix .lock.json,$(RELEASE_FORMS) stage0 kernel)) | LC_ALL=C sort -u; \
	} > $(LOCK)/inputs
	@echo "inputs: $$($(SHA256) < $(LOCK)/inputs | cut -c1-16), $$(grep -c '^https' $(LOCK)/inputs) packages"

dist:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FORM=$$f dist-form || exit 1; done

dist-form: $(if $(SLOT),slot,image) $(OUT)/meta.stamp
	release/manifest $(FORM) $(ARCH) $(OUT)/rootfs.tar $(OUT)/meta/usr/share/werewolf/kernel $(DIST) \
		$(if $(SLOT),vmlinuz=$(OUT)/slot/vmlinuz stage0.zst=$(OUT)/slot/initramfs.zst root.erofs=$(OUT)/slot/root.erofs,vmlinuz=$(BUILD)/vmlinuz initramfs.zst=$(OUT)/initramfs.zst)

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
		-append "console=$(CONSOLE) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 werewolf.data=vda werewolf.debug=1" \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
		-device virtio-rng-pci -drive file=$(BUILD)/data.img,format=raw,if=virtio $(QEMU_CONFIG)

ssh:
	ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1

# --- checks -------------------------------------------------------------------
# `make check` boots every form under QEMU, then a slot as bite leaves one,
# and runs test/checks on each as root on its console (test/boot). Each
# machine gets a blank disk and no config, and nothing listens on the host,
# so `make -j check` runs them side by side. Builds and consoles are logged
# in build/<arch>/check/. See docs/testing.md.
FORMS := $(patsubst forms/%.yaml,%,$(wildcard forms/*.yaml))
CHECK = $(BUILD)/check
# romfile= because direct boot needs no network boot ROM, and CI has none.
CHECK_QEMU = $(QEMU) -smp 2 -m 1024 -no-reboot -device virtio-rng-pci \
	-netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile=
# panic=1 with -no-reboot: a panic ends QEMU at once rather than hanging.
CHECK_CMDLINE = console=$(CONSOLE) panic=1 werewolf.debug=1 \
	werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3
# What every form shares, built once before the forms build side by side.
CHECK_SHARED = $(BUILD)/vmlinuz $(BUILD)/stage0/rootfs.tar build/$(ARCH)/updater/usr/lib/werewolf/update
# bitten has no updater, which would fetch from the network once committed.
CHECK_SLOT_FORM = bitten
VICTIM_UUID = 0e7e1f00-c4ec-4b00-8000-00000000c4ec

check: $(addprefix check-,$(FORMS)) check-slot
	@echo "check: every form, and a slot, passed"

check-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(MAKE) --no-print-directory FORM=$* image >$(CHECK)/$*-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/$*-build.log; echo "FAIL   $* build: see $(CHECK)/$*-build.log"; exit 1; }
	@$(MAKE) --no-print-directory FORM=$* check-form

check-form:
	@rm -f $(CHECK)/$(FORM).img && dd if=/dev/zero of=$(CHECK)/$(FORM).img bs=1048576 count=0 seek=1024 status=none
	@test/boot $(FORM) test/checks $(CHECK)/$(FORM).log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
		-drive file=$(CHECK)/$(FORM).img,format=raw,if=virtio

# The slot path: stage0 finding root.erofs by filesystem UUID, the overlay,
# /victim read-only, and commit making the slot GRUB's default, which takes
# the minute commit waits. The victim is a small ext4 holding what bite
# leaves: the root image in slot a, and GRUB's environment block.
# After bitten's own check, which builds the same form in the same place.
check-slot: | $(CHECK_SHARED) check-$(CHECK_SLOT_FORM)
	@mkdir -p $(CHECK)
	@$(MAKE) --no-print-directory FORM=$(CHECK_SLOT_FORM) slot >$(CHECK)/slot-build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/slot-build.log; echo "FAIL   slot build: see $(CHECK)/slot-build.log"; exit 1; }
	@$(MAKE) --no-print-directory FORM=$(CHECK_SLOT_FORM) check-slot-boot

check-slot-boot:
	@rm -rf $(CHECK)/victim $(CHECK)/victim.img
	@mkdir -p $(CHECK)/victim/var/lib/werewolf/a $(CHECK)/victim/boot/grub
	@cp $(OUT)/slot/root.erofs $(CHECK)/victim/var/lib/werewolf/a/
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
	@sed -n '2,17p' Makefile | cut -c3-

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
