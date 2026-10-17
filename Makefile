# werewolf: a Wolfi userland on an Alpine kernel, for virtual machines.
# make builds, tests and releases werewolf; howl builds and runs machines (cmd/howl/README.md).
#
#   make install-deps     install apko, Zig, QEMU and the rest, after asking
#   make howl             build build/host/howl; make install puts it on PATH
#   make test             run every unit test, in seconds
#   make lint             check Zig, YAML and docs; make fix repairs what it can
#   make install-precommit install the test, lint and local howl run hook
#   make precommit         run that hook now
#   make -j check         boot every form and a slot in parallel, and attack each
#   make check-FORM       check one form; check-shellfree-FORM checks it as shipped
#   make check-one        boot FORM REPEAT times, to chase a flake
#   make check-updater    run a whole update, over the network
#   make check-gcp        check prod-ssh on GCP; also check-aws and check-azure
#   make check-gcp-metadata check GCP people, key expiry, precedence and rotation
#   make example-FORM     run that form's local README fence; examples-gcp runs GCP
#   make ci               run CI's check job in an Ubuntu VM under Lima
#   make image|slot|disk  build FORM's initramfs, slot or UEFI disk
#   make list-forms       list the forms and the forms each includes
#   make relock           resolve FORM's packages again
#   make dist             build the released forms, unsigned (docs/releases.md)
#   make posture          build posture; on Linux, run it here as root
#   make clean            remove build/, except the package locks
#
# FORM picks the form (default sshd), ARCH the arch (default this machine's).
# DEV=1 adds a shell, for debugging, never for release. See docs/testing.md.

# := runs uname once; ARCH ?= $(shell ...) would run it at every use.
HOST_ARCH := $(shell uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
ARCH ?= $(HOST_ARCH)
HOST_OS := $(shell uname -s)

FORM ?= sshd
FORM_TOOL = build/host/form
FORM_TOOL_SOURCES = lib/baselayout.zig tools/form.zig lib/form.zig lib/compose.zig lib/package.zig lib/allow.zig lib/sshd.zig lib/service.zig lib/seal.zig lib/settings.zig
# compose_modules NAME is lib/compose.zig as module NAME, with its imports.
compose_modules = --dep allow --dep form --dep seal --dep service --dep package -M$(1)=lib/compose.zig -Mpackage=lib/package.zig \
	--dep allow --dep sshd -Mform=lib/form.zig -Mallow=lib/allow.zig --dep settings -Msshd=lib/sshd.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig
FORM_TOOL_MODULES = --dep form --dep compose -Mroot=tools/form.zig $(call compose_modules,compose)
COMPOSE_MODULES = $(call compose_modules,root)
HOWL = build/host/howl
FORM_REF := $(FORM)
override FORM := $(notdir $(patsubst %/,%,$(FORM)))
# These goals need no form tool, and install-deps runs before there is a Zig.
FORMLESS = install-deps install uninstall howl $(HOWL) clean help \
	lint _lint fix yamllint-lint zig-lint zig-fix doc-lint doc-fix
ifeq ($(filter-out $(FORMLESS),$(or $(MAKECMDGOALS),all)),)
FORM_ASK = :
else
FORM_ASK = $(FORM_TOOL)
# make asks the tool as it reads this file, so build it first.
FORM_TOOL_BUILT := $(shell [ -x $(FORM_TOOL) ] && [ -z "$$(find $(FORM_TOOL_SOURCES) -newer $(FORM_TOOL))" ] || \
	{ mkdir -p build/host && zig build-exe -O ReleaseSafe $(FORM_TOOL_MODULES) -femit-bin=$(FORM_TOOL).$$$$ >&2 && \
		mv $(FORM_TOOL).$$$$ $(FORM_TOOL); })
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
FORM_FILES := $(wildcard $(addsuffix /form.yaml,$(FORM_DIRS)))
# form_list KEY is form.yaml's KEY along the chain; form_check KEY, its check: KEY.
form_list = $(shell $(FORM_ASK) list $(FORM_REF) $(1))
form_check = $(shell $(FORM_ASK) check $(FORM_REF) $(1))
KERNEL_ARGS := $(shell $(FORM_ASK) cmdline $(FORM_REF) $(ARCH))
ifeq ($(KERNEL_ARGS)$(filter :,$(FORM_ASK)),)
$(error form $(FORM) has no kernel arguments, as build/host/form says above)
endif

IPE ?=
BUILD = build/$(ARCH)$(if $(IPE),/ipe)
IPE_KERNEL ?= build/ipe-kernel/$(ARCH)/rootfs.tar
# Test an unpublished kernel without enabling IPE (notably JIT forms).
KERNEL_ROOTFS ?=
WEREWOLF_IPE_CRT ?=
WEREWOLF_IPE_KEY ?=
# What a make-built image is made without, named as howl's --disable takes it
# (docs/security.md): Secure Boot and the TPM, and IPE unless IPE=1. howl
# refuses an image that lacks a protection this does not name.
comma := ,
DISABLE = secureboot$(comma)tpm$(if $(IPE),,$(comma)ipe)
APP ?=
DEV ?=
OUT = $(BUILD)/$(FORM)$(if $(DEV),-dev)$(if $(APP),-app)$(if $(PUBLISHED),-published)$(if $(IPE),-ipe)
TAR ?= $(shell command -v bsdtar || echo tar)
SHA256 ?= $(shell command -v sha256sum || echo shasum -a 256)
.DELETE_ON_ERROR:

# A target named _NAME is a step of another target.
.PHONY: all install uninstall install-deps install-precommit precommit hooks image slot disk list-forms test \
	programs packages posture howl cve-tiers relock release-inputs dist clean help ci check check-forms \
	check-shellfree check-integrity check-cloud check-native check-one check-posture check-adhoc check-bastion check-people \
	check-slot check-compose check-updater check-updater-staged check-updater-published check-nodata \
	check-lease check-dns check-lan check-static check-verity check-deadman check-metadata check-persist \
	check-dist check-gcp check-gcp-metadata check-aws check-azure check-secureboot check-firecracker check-updater-uki seal-learn $(OUT)/disk.qcow2

all: image
install-deps:
	@tools/install-deps
precommit:
	@tools/git-hooks/pre-commit
install-precommit hooks:
	git config core.hooksPath tools/git-hooks
	@echo "pre-commit installed: test, lint, and a local howl run"

# howl always pins locked packages; PUBLISHED=1 takes programs from werewolf's repository.
HOWL_BUILD = $(HOWL) _build --verbose --with $(FORM_REF) --arch $(ARCH) --disable=$(DISABLE) \
	--build $(BUILD) --programs $(PROGRAMS) $(if $(DEV),--dev) $(if $(APP),--app-root $(APP)) \
	$(if $(PUBLISHED),--published) $(if $(IPE),--ipe-kernel $(IPE_KERNEL) --ipe-key $(WEREWOLF_IPE_KEY) --ipe-cert $(WEREWOLF_IPE_CRT)) \
	$(if $(KERNEL_ROOTFS),--kernel-rootfs $(KERNEL_ROOTFS)) \
	$(if $(IPE_UPDATES),--ipe-updates $(IPE_UPDATES) --image-serial $(IMAGE_SERIAL))
image slot: $(HOWL)
	$(HOWL_BUILD) $@
.PHONY: prebuilt
prebuilt: $(HOWL)
	$(HOWL_BUILD) prebuilt
disk: $(HOWL)
	$(HOWL_BUILD) $(if $(DISK),--disk $(DISK)) $(if $(DISK_MIB),--disk-mib $(DISK_MIB)) $(if $(DISK_ARGS),--disk-args "$(DISK_ARGS)") disk
# A released disk never takes DISK_ARGS.
$(OUT)/disk.qcow2: $(HOWL)
	$(HOWL_BUILD) $(if $(DISK_MIB),--disk-mib $(DISK_MIB)) qcow2

# apko locks pin every package; these rules serve relock, and release-inputs's boot locks.
LOCK = build/lock
FORM_LOCK = $(LOCK)/$(FORM)$(if $(DEV),-dev)$(if $(PUBLISHED),-published).lock.json
BOOT_LOCKS = $(LOCK)/kernel.lock.json $(LOCK)/boot.lock.json
LOCKS = $(FORM_LOCK) $(BOOT_LOCKS)
DEV_PACKAGES = busybox-full $(call form_list,dev)
FORM_APKO = $(BUILD)/form/$(FORM)$(if $(DEV),-dev).yaml
# apko_retry COMMAND retries after 15, 30 and 45 s: the package server refuses bursts (HTTP 403).
APKO_NETWORK = status code (403|408|429|5[0-9][0-9])|connection reset|i/o timeout|TLS handshake|deadline exceeded|unexpected EOF|failed to fetch
apko_retry = o=$(CURDIR)/$@.apko && for t in 1 2 3 4; do \
	{ $(1); echo $$? >$$o.rc; } 2>&1 | tee $$o; rc=$$(cat $$o.rc); \
	if [ "$$rc" = 0 ]; then rm -f $$o $$o.rc; break; fi; \
	if ! grep -Eq '$(APKO_NETWORK)' $$o || [ $$t -eq 4 ]; then rm -f $$o $$o.rc; exit 1; fi; \
	echo "apko could not reach the package server; trying again in $$((t * 15))s" >&2; sleep $$((t * 15)); done
# apko_lock CONFIG runs in CONFIG's directory, where apko resolves its paths.
apko_lock = mkdir -p $(LOCK) && cd $(dir $(1)) && \
	$(call apko_retry,apko lock --arch aarch64$(,)x86_64 --output $(CURDIR)/$@ $(notdir $(1)))
, := ,
$(FORM_LOCK): $(FORM_FILES) | $(FORM_APKO)
	$(call apko_lock,$(FORM_APKO))
# Keep an unchanged config's mtime, as howl does, or howl rebuilds the root.
# The config names werewolf's key in $(BUILD)/keys (lib/package.zig's keyring).
$(FORM_APKO): $(FORM_FILES) $(FORM_TOOL)
	mkdir -p $(dir $@) $(BUILD)/keys && $(FORM_TOOL) apko $(FORM_REF) $(if $(DEV),$(DEV_PACKAGES)) >$@.tmp && \
		{ cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@; } && \
		{ cmp -s release/packages.pub $(BUILD)/keys/werewolf-packages.rsa.pub || \
			cp release/packages.pub $(BUILD)/keys/werewolf-packages.rsa.pub; }
$(LOCK)/kernel.lock.json: boot/kernel.yaml release/packages.pub
	mkdir -p $(BUILD)/boot $(BUILD)/keys && \
		cp boot/kernel.yaml $(BUILD)/boot/kernel.yaml && \
		cp release/packages.pub $(BUILD)/keys/werewolf-packages.rsa.pub
	$(call apko_lock,$(BUILD)/boot/kernel.yaml)
$(LOCK)/boot.lock.json: boot/boot.yaml
	$(call apko_lock,$<)
relock:
	rm -f $(LOCKS)
	$(MAKE) --no-print-directory FORM=$(FORM_REF) $(BOOT_LOCKS) _howl-lock

# Zig is pre-1.0, so insist on the version the code is written for.
ZIG_VERSION = 0.17.0
PROGRAMS = build/$(ARCH)/programs
CMDS := $(filter-out howl,$(patsubst cmd/%/,%,$(wildcard cmd/*/)))
# program_bin NAME is where cmd/NAME is built; form_bin DIR, where forms/F/cmd/P is.
program_bin = $(PROGRAMS)/$(1)/$(or $(PROGRAM_AT_$(1)),usr/lib/werewolf/$(1))
PROGRAM_AT_init = init
form_bin = $(PROGRAMS)/forms/$(notdir $(patsubst %/cmd/$(notdir $(1)),%,$(1)))/usr/lib/werewolf/$(notdir $(1))
FORM_CMDS := $(sort $(patsubst %/,%,$(wildcard forms/*/cmd/*/) $(foreach d,$(FORM_DIRS),$(wildcard $(d)/cmd/*/))))
POSTURE_BIN = $(call program_bin,posture)
define zig_check
@[ "$$(zig version)" = "$(ZIG_VERSION)" ] || \
	{ echo "$< is written for zig $(ZIG_VERSION), not $$(zig version)" >&2; exit 1; }
mkdir -p $(dir $@)
endef

# A program may import any library; a library, only what its --dep flags name.
LIB_MODULES = --dep seal -Msandbox=lib/sandbox.zig -Mbroker=lib/broker.zig -Mdm=lib/dm.zig \
	-Mverity=lib/verity.zig -Mipe=lib/ipe.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig \
	-Mupdate-policy=lib/update-policy.zig -Mnetwork=lib/network.zig \
	--dep sandbox -Mnet-rule=lib/net-rule.zig --dep network --dep net-rule --dep sandbox -Mdns=lib/dns.zig -Mhostkey=lib/hostkey.zig \
	--dep allow --dep sshd -Mform=lib/form.zig --dep seal -Maudit=lib/audit.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mallow=lib/allow.zig -Mcve=lib/cve.zig \
	--dep network -Mcmdline=lib/cmdline.zig --dep settings -Msshd=lib/sshd.zig --dep form --dep seal \
	--dep service --dep package --dep allow -Mcompose=lib/compose.zig -Mpackage=lib/package.zig -Mimage=lib/image.zig \
	-Mgpt=boot/gpt.zig --dep package -Mapk=lib/apk.zig -Mfiles=files.zig -Mpeople=lib/people.zig \
	--dep apk --dep update-policy -Mprebuilt=lib/prebuilt.zig -Muki=tools/uki.zig --dep apk -Mtpm=lib/tpm.zig \
	--dep apk --dep tpm -Mbootstrap=lib/tpm-bootstrap.zig --dep apk --dep tpm --dep bootstrap -Menrollment=lib/enrollment.zig
ZIG_MODULES = --dep sandbox --dep broker --dep dm --dep verity --dep ipe --dep prebuilt --dep uki --dep tpm --dep enrollment --dep seal --dep settings --dep update-policy \
	--dep dns --dep net-rule --dep network --dep hostkey --dep form --dep audit --dep service --dep allow --dep cve --dep cmdline \
	--dep sshd --dep compose --dep package --dep image --dep gpt --dep apk --dep files --dep people -Mroot=$(1) $(LIB_MODULES)

# program NAME, BINARY, DIR is the rule that builds DIR (default cmd/NAME) into BINARY.
define program
$(2): $(or $(3),cmd/$(1))/$(1).zig $$(wildcard $(or $(3),cmd/$(1))/*.zig) $$(wildcard lib/*.zig)
	$$(zig_check)
	zig build-exe -O ReleaseSafe -fstrip -target $$(ARCH)-linux-musl $$(call ZIG_MODULES,$$<) -femit-bin=$$@
endef
$(foreach p,$(CMDS),$(eval $(call program,$(p),$(call program_bin,$(p)))))
$(foreach c,$(FORM_CMDS),$(eval $(call program,$(notdir $(c)),$(call form_bin,$(c)),$(c))))

# howl makes programs before it builds an image.
programs: $(foreach p,$(CMDS),$(call program_bin,$(p))) $(foreach c,$(FORM_CMDS),$(call form_bin,$(c)))

VERITY_BIN = build/host/verity
$(VERITY_BIN): tools/verity.zig lib/verity.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep verity -Mroot=$< -Mverity=lib/verity.zig -femit-bin=$@

UKI_BIN = build/host/uki
$(UKI_BIN): tools/uki.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -Mroot=$< -femit-bin=$@

# A release's UKI: kernel, stage0, root and command line as one PE the boot
# key signs (tools/uki; docs/design/verified-boot.md, docs/releases.md).
# Built when WEREWOLF_BOOT_KEY names the key; the certificate is the
# committed release/boot.crt, and UKI_STUB systemd's linuxaa64.efi.stub.
WEREWOLF_BOOT_CRT ?= release/boot.crt
UKI_STUB ?= out/tools/stubs/$(ARCH)/linux.efi.stub
UKI = $(OUT)/slot/uki.efi
UKI_WORK = $(BUILD)/uki
UKI_NATIVE ?=
UKI_ARGS ?= $(if $(UKI_NATIVE),werewolf.native=1 werewolf.slots=57e1f000-77e2-4b0f-8a3c-0000000000a0 werewolf.esp=57E1-F000)
.PHONY: _uki-options
_uki-options:
$(UKI_WORK)/options: _uki-options
	@mkdir -p $(UKI_WORK)
	@printf '%s\n' '$(CONSOLE)' '$(UKI_ARGS)' '$(WEREWOLF_BOOT_KEY)' '$(WEREWOLF_BOOT_CRT)' '$(UKI_STUB)' >$@.new
	@cmp -s $@.new $@ && rm -f $@.new || mv -f $@.new $@
$(UKI): $(OUT)/slot/root.erofs $(OUT)/slot/stage0.zst $(OUT)/slot/cmdline $(BUILD)/vmlinuz $(UKI_BIN) $(WEREWOLF_BOOT_KEY) $(WEREWOLF_BOOT_CRT) $(UKI_STUB) $(UKI_WORK)/options
	@[ -n "$(WEREWOLF_BOOT_KEY)" ] && [ -n "$(WEREWOLF_BOOT_CRT)" ] && [ -f "$(UKI_STUB)" ] || \
		{ echo "$@: WEREWOLF_BOOT_KEY, WEREWOLF_BOOT_CRT and UKI_STUB (= systemd's linuxaa64.efi.stub) name the boot key and the stub (docs/testing.md)" >&2; exit 1; }
	@mkdir -p $(UKI_WORK) && cp $(OUT)/slot/root.erofs $(UKI_WORK)/
	@touch -t 197001010000 $(UKI_WORK)/root.erofs
	@cd $(UKI_WORK) && $(TAR) -cf - --format newc --uid 0 --gid 0 --numeric-owner root.erofs | zstd -1 -q -c >root.cpio.zst
	@cat $(OUT)/slot/stage0.zst $(UKI_WORK)/root.cpio.zst >$(UKI_WORK)/initrd
	@printf '%s console=%s %s\0' "$$(cat $(OUT)/slot/cmdline)" $(CONSOLE) '$(UKI_ARGS)' >$(UKI_WORK)/cmdline
	@rm -f $(UKI).signed
	$(UKI_BIN) $(UKI_STUB) $(UKI).unsigned .linux=$(BUILD)/vmlinuz .initrd=$(UKI_WORK)/initrd .cmdline=$(UKI_WORK)/cmdline
	osslsigncode sign -time 0 -certs $(WEREWOLF_BOOT_CRT) -key $(WEREWOLF_BOOT_KEY) -in $(UKI).unsigned -out $(UKI).signed >/dev/null
	@mv -f $(UKI).signed $(UKI) && rm -f $(UKI).unsigned

# Built under a temporary name, so a running check never finds an empty howl, which sh runs as a pass.
howl: $(HOWL)
$(HOWL): cmd/howl/howl.zig $(wildcard cmd/howl/*.zig) lib/settings.zig lib/update-policy.zig lib/network.zig \
	lib/form.zig lib/allow.zig lib/service.zig lib/seal.zig lib/sshd.zig lib/compose.zig lib/package.zig lib/apk.zig lib/apk-version.zig \
	lib/baselayout.zig lib/verity.zig lib/ipe.zig lib/prebuilt.zig lib/tpm.zig lib/boot-authority.zig lib/machine-transport.zig lib/boot-state.zig lib/image.zig tools/uki.zig boot/gpt.zig files.zig $(shell grep -o '@embedFile("[^"]*")' files.zig | cut -d'"' -f2)
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@

# install-deps installs the Zig that builds howl, so it comes first, even with -j.
INSTALL_DIRS = $(HOME)/bin $(HOME)/.local/bin /usr/local/bin
$(HOWL): | $(if $(filter install,$(MAKECMDGOALS)),install-deps)
install: install-deps $(HOWL)
	@tools/install $(HOWL) $(INSTALL_DIRS)
uninstall:
	@tools/install -u $(INSTALL_DIRS)

TEST_SK = build/host/test-sk.so
$(TEST_SK): tools/test-sk.zig
	$(zig_check)
	t=$@.$$$$ && zig build-lib -dynamic -O ReleaseSafe -lc -femit-bin=$$t $< && mv -f $$t $@

# Each file's tests are a target, so make -j test runs them in parallel.
PROGRAM_SOURCES = $(foreach d,$(wildcard cmd/* forms/*/cmd/*),$(d)/$(notdir $(d)).zig)
TEST_SOURCES = test/native/iterate.zig lib/sandbox.zig lib/seal.zig lib/dm.zig lib/verity.zig lib/settings.zig lib/update-policy.zig \
	lib/network.zig lib/net-rule.zig lib/dns.zig lib/cmdline.zig lib/hostkey.zig lib/audit.zig lib/form.zig lib/compose.zig lib/package.zig \
	lib/allow.zig lib/service.zig lib/cve.zig lib/sshd.zig lib/image.zig lib/apk.zig lib/people.zig tools/form.zig tools/package.zig \
	boot/gpt.zig lib/ipe.zig lib/prebuilt.zig lib/broker.zig lib/tpm.zig lib/boot-authority.zig lib/machine-transport.zig lib/tpm-bootstrap.zig lib/enrollment.zig lib/boot-state.zig tools/cve-tiers.zig tools/test-sk.zig tools/doc-check.zig tools/uki.zig $(PROGRAM_SOURCES)
test: $(addprefix _test/,$(TEST_SOURCES)) _test/howl-smoke _test/howl-lock _test/cloud-console _test/azure-security _test/provider-ab _test/local-publisher _test/local-prerequisites _test/cloud-enrollment _test/bootstrap-image _test/release-signing _test/form-coverage
	@echo "test: $(words $(TEST_SOURCES)) suites passed, and howl's lines"
_test/cloud-console: ; python3 test/cloud-console --test
_test/form-coverage: ; python3 test/form-coverage
_test/bootstrap-image: build/host/tpm-bootstrap ; python3 test/bootstrap-image
_test/release-signing:
	python3 test/release-signing
	python3 test/native-firmware
_test/azure-security: ; python3 test/azure-security --test
_test/provider-ab:
	python3 test/ab_checks.py
	python3 test/ab-provider-tests
_test/local-prerequisites: $(HOWL)
	python3 test/local-prerequisites
	python3 test/lima-state $(HOWL)
	python3 test/build-helper
_test/cloud-enrollment: $(HOWL) ; python3 test/cloud-enrollment $(HOWL)
_test/local-publisher: $(HOWL) build/host/tpm-policy
	python3 test/local-publisher $(HOWL)
	python3 test/boot-images $(HOWL)
	python3 test/boot-download $(HOWL)
	python3 test/protected-release
	python3 test/protected-publication
	python3 test/protected-export
	python3 test/protected-inputs
	python3 test/form-images
	python3 test/publishing-health
_test/lib/sandbox.zig _test/lib/audit.zig: _test/%: ; zig test --dep seal -Mroot=$* -Mseal=lib/seal.zig
_test/lib/dns.zig _test/lib/net-rule.zig: _test/%: ; zig test $(call ZIG_MODULES,$*)
_test/lib/cmdline.zig: ; zig test --dep network -Mroot=lib/cmdline.zig -Mnetwork=lib/network.zig
_test/lib/prebuilt.zig: ; zig test --dep apk --dep update-policy -Mroot=lib/prebuilt.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig -Mupdate-policy=lib/update-policy.zig
_test/lib/tpm.zig: ; zig test --dep apk -Mroot=lib/tpm.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig
_test/lib/boot-authority.zig: ; zig test --dep apk -Mroot=lib/boot-authority.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig
_test/lib/machine-transport.zig: ; zig test --dep apk -Mroot=lib/machine-transport.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig
_test/lib/tpm-bootstrap.zig: ; zig test --dep apk --dep tpm -Mroot=lib/tpm-bootstrap.zig --dep apk -Mtpm=lib/tpm.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig
_test/lib/enrollment.zig: ; zig test --dep apk --dep tpm --dep bootstrap -Mroot=lib/enrollment.zig --dep apk -Mtpm=lib/tpm.zig --dep apk --dep tpm -Mbootstrap=lib/tpm-bootstrap.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig
build/host/tpm-bootstrap: tools/tpm-bootstrap.zig lib/enrollment.zig lib/tpm-bootstrap.zig lib/tpm.zig lib/boot-authority.zig lib/machine-transport.zig lib/boot-state.zig lib/apk.zig lib/package.zig
	@mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe --dep bootstrap --dep enrollment --dep apk --dep tpm -Mroot=$< --dep apk --dep tpm --dep bootstrap -Menrollment=lib/enrollment.zig --dep apk --dep tpm -Mbootstrap=lib/tpm-bootstrap.zig --dep apk -Mtpm=lib/tpm.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig -femit-bin=$@
build/host/tpm-policy: tools/tpm-policy.zig lib/tpm.zig lib/boot-authority.zig lib/machine-transport.zig lib/boot-state.zig lib/apk.zig lib/package.zig
	@mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe --dep apk --dep tpm -Mroot=$< --dep apk -Mtpm=lib/tpm.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig -femit-bin=$@

.PHONY: check-tpm-guest check-tpm-recovery check-tpm-bootstrap-guest check-secure-lima check-secure-qemu check-run-cache check-shared-boot
check-tpm-recovery: build/host/tpm-policy
	python3 test/check-tpm-recovery

check-tpm-bootstrap-guest: build/host/tpm-bootstrap build/host/tpm-policy build/host/uki $(call program_bin,tpm-enroll)
	@[ "$(IPE)" = 1 ] || { echo 'check-tpm-bootstrap-guest: set IPE=1 and a measured UKI_STUB' >&2; exit 1; }
	python3 test/check-tpm-bootstrap-guest --arch $(ARCH) --kernel $(IPE_KERNEL) --stub $(UKI_STUB) \
		--agent $(call program_bin,tpm-enroll) --work $(BUILD)/check/tpm-bootstrap \
		--ipe-key $(WEREWOLF_IPE_KEY) --ipe-cert $(WEREWOLF_IPE_CRT) \
		--unmeasured-stub out/tools/stubs/$(ARCH)/linux.efi.stub --recovery-cuts

check-tpm-guest: $(HOWL) build/host/tpm-policy build/host/uki
	DEBUGFS=$(DEBUGFS) python3 test/check-tpm-qemu $(HOWL) $(ARCH) $(IPE_KERNEL) $(WEREWOLF_IPE_KEY) $(WEREWOLF_IPE_CRT) $(BUILD)/check/tpm-guest

check-secure-lima: $(HOWL)
	python3 test/check-secure-lima $(HOWL) $(IPE_KERNEL) $(WEREWOLF_IPE_KEY) $(WEREWOLF_IPE_CRT) $(UKI_STUB) $(BUILD)/check/secure-lima
check-run-cache: $(HOWL)
	python3 test/check-run-cache $(HOWL) $(IPE_KERNEL) $(WEREWOLF_IPE_KEY) $(WEREWOLF_IPE_CRT) $(UKI_STUB) $(BUILD)/check/run-cache

check-shared-boot: $(HOWL)
	python3 test/check-shared-boot $(HOWL) $(IPE_KERNEL) $(WEREWOLF_IPE_KEY) $(WEREWOLF_IPE_CRT) $(UKI_STUB) $(BUILD)/check/shared-boot

check-secure-qemu: $(HOWL)
	python3 test/check-secure-lima $(HOWL) $(IPE_KERNEL) $(WEREWOLF_IPE_KEY) $(WEREWOLF_IPE_CRT) $(UKI_STUB) $(BUILD)/check/secure-qemu qemu

_test/lib/form.zig: ; zig test --dep allow --dep sshd -Mroot=lib/form.zig -Mallow=lib/allow.zig --dep settings -Msshd=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/sshd.zig: ; zig test --dep settings -Mroot=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/service.zig: ; zig test --dep seal --dep settings -Mroot=lib/service.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig
_test/tools/form.zig: ; zig test $(FORM_TOOL_MODULES)
_test/lib/compose.zig: ; zig test $(COMPOSE_MODULES)
_test/tools/package.zig _test/lib/apk.zig: _test/%: ; zig test --dep package -Mroot=$* -Mpackage=lib/package.zig
_test/tools/cve-tiers.zig: ; zig test $(call ZIG_MODULES,tools/cve-tiers.zig)
_test/tools/test-sk.zig: ; zig test tools/test-sk.zig -lc
_test/cmd/%.zig: ; zig test $(call ZIG_MODULES,cmd/$*.zig)
_test/forms/%.zig: ; zig test $(call ZIG_MODULES,forms/$*.zig)
_test/%.zig: ; zig test $*.zig

SYSLOG_PROBE = $(BUILD)/syslog-init
$(SYSLOG_PROBE): test/syslog-init.zig cmd/syslogd/policy.zig lib/seal.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -target $(ARCH)-linux-musl --dep seal --dep log-policy \
		-Mroot=$< -Mseal=lib/seal.zig -Mlog-policy=cmd/syslogd/policy.zig -femit-bin=$@
.PHONY: check-syslog fuzz-syslog
SYSLOG_FUZZ_RUNS ?= 100000
fuzz-syslog:
	@for target in 'fuzz syslog' 'fuzz kernel' 'fuzz configuration' 'fuzz gzip'; do \
		zig build --build-file cmd/syslogd/build.zig test -Dfilter="$$target" \
			--fuzz=$(SYSLOG_FUZZ_RUNS) --summary all || exit; \
	done

check-syslog: $(HOWL) $(call program_bin,syslogd) $(call program_bin,leash) $(SYSLOG_PROBE)
	@test -r $(BUILD)/vmlinuz || $(HOWL_BUILD) image
	python3 test/check-syslog --arch $(ARCH) --kernel $(BUILD)/vmlinuz \
		--daemon $(call program_bin,syslogd) --probe $(SYSLOG_PROBE) \
		--leash $(call program_bin,leash) --work $(BUILD)/check/syslog \
		$(if $(SYSLOG_MODULES),--modules $(SYSLOG_MODULES))

_test/howl-smoke: $(HOWL)
	@test/howl-smoke $(HOWL) $(BUILD)
	@python3 test/howl-test $(HOWL)
	@python3 test/howl-forms $(HOWL)
	@python3 test/native-tests-regression
	@zig test test/native/driver.zig
	@zig test --dep test-driver -Mroot=forms/greenbone/test/driver.zig -Mtest-driver=test/native/driver.zig
_test/howl-lock: $(HOWL)
	@python3 test/howl-lock $(HOWL)

posture: $(POSTURE_BIN)
ifeq ($(HOST_OS)-$(HOST_ARCH),Linux-$(ARCH))
	$(if $(filter 0,$(shell id -u)),,sudo) $(POSTURE_BIN)
else
	@echo "$(POSTURE_BIN): copy it to a Linux $(ARCH) machine and run it there, as root"
endif

PACKAGE_TOOL = build/host/package
PACKAGES = $(BUILD)/packages
PACKAGE_TIME ?= $(shell git log -1 --format=%ct 2>/dev/null)
# Each program depends on the format its files are in (lib/compose.zig).
PACKAGE_FORMAT = $(shell $(FORM_ASK) format)
$(PACKAGE_TOOL): tools/package.zig lib/package.zig lib/baselayout.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep package -Mroot=$< -Mpackage=lib/package.zig -femit-bin=$@
# Each form CI publishes is NAME-form: the form as an image stages it, with its
# own programs, depending on what it is built on, takes and runs (tools/form.zig).
PACKAGE_FORMS = $(shell $(FORM_ASK) packaged)
packages: $(PACKAGE_TOOL) $(FORM_TOOL) programs
	@[ -n "$(PACKAGE_TIME)" ] || { echo "packages: no commit time; set PACKAGE_TIME" >&2; exit 1; }
	# Where a boot key is given, each release form's slot gains its signed
	# UKI first, so the packages below can carry it (docs/releases.md).
	@[ -z "$(WEREWOLF_BOOT_KEY)" ] || [ -z "$(UKI_STUB)" ] || for f in $(RELEASE_FORMS); do \
		$(MAKE) --no-print-directory FORM=$$f ARCH=$(ARCH) slot && \
		$(MAKE) --no-print-directory FORM=$$f ARCH=$(ARCH) WEREWOLF_BOOT_KEY=$(WEREWOLF_BOOT_KEY) \
			WEREWOLF_BOOT_CRT=$(WEREWOLF_BOOT_CRT) UKI_STUB=$(UKI_STUB) $(BUILD)/$$f/slot/uki.efi || exit 1; done
	rm -rf $(PACKAGES)/$(ARCH) $(PACKAGES)/format $(PACKAGES)/advisories $(PACKAGES)/forms && mkdir -p $(PACKAGES)/$(ARCH) $(PACKAGES)/format/usr/lib/werewolf $(PACKAGES)/advisories/usr/share/werewolf
	echo $(PACKAGE_FORMAT) >$(PACKAGES)/format/usr/lib/werewolf/format && $(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PACKAGES)/format \
		werewolf-format$(PACKAGE_FORMAT) - $(ARCH) $(PACKAGE_TIME) "werewolf's format (lib/compose.zig)" provide:werewolf-format=$(PACKAGE_FORMAT)
	cp release/advisories $(PACKAGES)/advisories/usr/share/werewolf/ && $(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) \
		$(PACKAGES)/advisories werewolf-advisories - $(ARCH) $(PACKAGE_TIME) "werewolf's own advisories (release/advisories)"
	$(PACKAGE_TOOL) baselayout $(PACKAGES)/$(ARCH) $(ARCH) $(PACKAGE_TIME)
	for p in $(CMDS); do $(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PROGRAMS)/$$p werewolf-$$p - \
		$(ARCH) $(PACKAGE_TIME) "werewolf's $$p (cmd/$$p)" depend:werewolf-format$(PACKAGE_FORMAT) || exit 1; done
	# A signed UKI, when the boot key built one (docs/design/verified-boot.md):
	# its package puts it in new roots, where installEsp lays it.
	for f in $(RELEASE_FORMS); do [ ! -f $(BUILD)/$$f/slot/uki.efi ] || { \
		t=$(PACKAGES)/uki/$$f/usr/lib/werewolf/uki && mkdir -p $$t && \
		cp $(BUILD)/$$f/slot/uki.efi $$t/slot.efi && \
		$(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PACKAGES)/uki/$$f uki-$$f - \
		$(ARCH) $(PACKAGE_TIME) "werewolf's signed UKI for $$f (docs/design/verified-boot.md)" \
		depend:werewolf-format$(PACKAGE_FORMAT) || exit 1; }; done
	for f in $(PACKAGE_FORMS); do t=$(PACKAGES)/forms/$$f && $(FORM_TOOL) stage $$f $$t && \
		{ [ ! -d $(PROGRAMS)/forms/$$f ] || cp -R $(PROGRAMS)/forms/$$f/. $$t/; } && \
		$(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $$t $$f-form - $(ARCH) $(PACKAGE_TIME) "werewolf's form $$f (forms/$$f)" \
		$$($(FORM_TOOL) depends $$f | sed 's/^/depend:/') \
		$$([ -f $(BUILD)/$$f/slot/uki.efi ] && [ -f $(PACKAGES)/uki/$$f/usr/lib/werewolf/uki/slot.efi ] && echo depend:uki-$$f) || exit 1; done
	$(PACKAGE_TOOL) index $(PACKAGES)/$(ARCH) -
	@echo "packages: $(words $(CMDS)) programs and $(words $(PACKAGE_FORMS)) forms in $(PACKAGES)/$(ARCH);" \
		"sign APKINDEX.member, then build/host/package sign"

# cve-tiers reads the NVD key in the recipe, so make never prints it (tools/README.md).
CVE_TIERS_BIN = build/host/cve-tiers
NVD_API_KEY_FILE ?= $(HOME)/.tok/werewolf-nvd
$(CVE_TIERS_BIN): tools/cve-tiers.zig lib/cve.zig lib/update-policy.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$@
cve-tiers: $(CVE_TIERS_BIN) $(LOCK)/kernel.lock.json
	mkdir -p build/tiers && FORM_TOOL=$(FORM_TOOL) release/origins build/tiers/origins
	@kernel=$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(linux-werewolf-[^/]*\)\.apk".*|\1|p' $(LOCK)/kernel.lock.json) && \
	NVD_API_KEY=$${NVD_API_KEY:-$$(cat $(NVD_API_KEY_FILE))} \
	$(CVE_TIERS_BIN) "$$kernel" build/tiers/origins build/tiers/nvd build/tiers/in build/tiers/cve-tiers.json

list-forms:
	@$(FORM_TOOL) tree

# CI releases these forms when release-inputs changes; locks pin both runners to the same packages.
RELEASE_FORMS = $(shell $(FORM_ASK) released)
DIST_DIRECT_FORMS = minimal
DIST = dist
RELEASE_SOURCES = Makefile forms boot cmd lib tools release/image.pub release/tiers.pub release/advisories release/packages.pub release/boot.crt release/with-boot-key
# Releases take werewolf's programs from its repository, so a newly published program is an input.
RELEASE_LOCKS = $(addprefix $(LOCK)/,$(addsuffix -published.lock.json,$(RELEASE_FORMS)) kernel.lock.json boot.lock.json)
# The inputs are a digest of the sources' bytes and exec bits, and every package's URL.
release-inputs:
	rm -f $(RELEASE_LOCKS)
	$(MAKE) --no-print-directory -j $(BOOT_LOCKS)
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory _lock/$$f || exit 1; done
	{ echo "tree $$({ find $(RELEASE_SOURCES) -type f ! -name .DS_Store ! -path '*/__pycache__/*' | LC_ALL=C sort | xargs $(SHA256); \
		find $(RELEASE_SOURCES) -type f -perm -100 ! -path '*/__pycache__/*' | LC_ALL=C sort; } | $(SHA256) | cut -c1-64)"; \
	  sed -n 's|.*"url": "\([^"]*\.apk\)".*|\1|p' $(RELEASE_LOCKS) | LC_ALL=C sort -u; } >$(LOCK)/inputs
	@echo "inputs: $$($(SHA256) < $(LOCK)/inputs | cut -c1-16), $$(grep -c '^https' $(LOCK)/inputs) packages"
# A release's forms come from werewolf's repository, so howl writes its config and lock,
# one form at a time: they share the forms it fetches.
_lock/%: $(HOWL)
	@$(MAKE) --no-print-directory PUBLISHED=1 FORM=$* _howl-lock
_howl-lock: $(HOWL)
	$(HOWL_BUILD) lock
dist:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FORM=$$f _dist-form || exit 1; done
# howl build always builds in build/ARCH, without DEV or APP, so refuse them.
_dist-form: $(HOWL)
	@[ "$(BUILD)" = build/$(ARCH) ] && [ -z "$(DEV)$(APP)" ] || \
		{ echo "_dist-form: a release builds in build/$(ARCH), without DEV or APP (howl build --app)" >&2; exit 1; }
	$(HOWL) build --verbose --with $(FORM_REF) --arch $(ARCH) -o $(DIST) \
		--disable=$(if $(WEREWOLF_BOOT_KEY),tpm,secureboot$(comma)tpm)

# check-NAME builds what it boots, then runs test/check-NAME; machines share nothing, so -j works.
MACHINE = $(if $(filter aarch64,$(ARCH)),virt,q35)
CONSOLE = $(if $(filter aarch64,$(ARCH)),ttyAMA0,ttyS0)
# Without KVM, HVF or NVMM (some CI runners, FreeBSD), QEMU emulates.
ifeq ($(ARCH),$(HOST_ARCH))
ACCEL = $(if $(filter Darwin,$(HOST_OS)),hvf,$(or $(shell test -r /dev/kvm && test -w /dev/kvm && echo kvm),$(if $(wildcard /dev/nvmm),nvmm,tcg)))
CPU = $(if $(filter tcg,$(ACCEL)),max,host)
else
ACCEL = tcg
CPU = max
endif
# Checks lend aarch64 guests EL2 where QEMU can, so posture proves kvm-arm.mode=none holds.
EL2 = $(if $(filter aarch64,$(ARCH)),$(shell echo quit | qemu-system-aarch64 -M virt,virtualization=on -accel $(ACCEL) -cpu $(CPU) -nodefaults -display none -monitor stdio -S >/dev/null 2>&1 && echo ,virtualization=on))
QEMU = qemu-system-$(ARCH) -M $(MACHINE)$(EL2) -accel $(ACCEL) -cpu $(CPU) -nographic

FORMS := $(patsubst forms/%/form.yaml,%,$(wildcard forms/*/form.yaml))
FORMS_FOR_ARCH := $(shell $(FORM_ASK) for-arch $(ARCH))
NATIVE_TEST_FORMS := $(filter $(FORMS_FOR_ARCH),$(patsubst forms/%/test/native.json,%,$(wildcard forms/*/test/native.json)))
CHECK = $(BUILD)/check$(if $(SEAL_LEARN),-learn)
# test/checks needs a root shell on the console, so checks build with DEV=1.
CHECK_MAKE = $(MAKE) --no-print-directory DEV=1
# 1 GiB keeps forms lean unless check: memory says more; an offline form gets restrict=on; no boot ROM.
CHECK_MEMORY := $(or $(call form_check,memory),1024)
CHECK_OFFLINE := $(if $(filter true,$(call form_check,offline)),$(,)restrict=on)
CHECK_QEMU = $(QEMU) -smp 2 -m $(CHECK_MEMORY) -no-reboot -device virtio-rng-pci \
	-netdev user,id=n0$(CHECK_OFFLINE) -device virtio-net-pci,netdev=n0,romfile=
# A stall panics and ends QEMU, so a hang fails in seconds with the kernel's reason.
CHECK_STALLS = rcupdate.rcu_cpu_stall_timeout=20 sysctl.kernel.panic_on_rcu_stall=1 \
	sysctl.kernel.hung_task_timeout_secs=120 sysctl.kernel.hung_task_panic=1 sysctl.kernel.softlockup_panic=1
SEAL_ARGS = $(if $(SEAL_LEARN),werewolf.seal=learn)
CHECK_BOOT = console=$(CONSOLE) $(KERNEL_ARGS) panic=1 werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) $(SEAL_ARGS)
CHECK_CMDLINE = $(CHECK_BOOT) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3
# The posture failures test/boot expects: test/posture-known's and the form's weaknesses.
POSTURE_KNOWN_KIND := $(shell awk -v b=$(if $(DEV),dev,*) -v a=$(ARCH) '$$1 == b || $$1 == a { $$1 = ""; k = k $$0 } END { print k }' test/posture-known)
export POSTURE_KNOWN := $(if $(IPE),$(filter-out boot-ipe-enforced,$(POSTURE_KNOWN_KIND)),$(POSTURE_KNOWN_KIND)) $(shell $(FORM_ASK) weaknesses $(FORM_REF))
# A check script's environment (docs/testing.md). Homebrew keeps debugfs off PATH.
SLOTS_UUID = 0e7e1f00-c4ec-4b00-8000-00000000c4ec
DEBUGFS = $(firstword $(shell command -v debugfs) $(wildcard /opt/homebrew/opt/e2fsprogs/sbin/debugfs /usr/local/opt/e2fsprogs/sbin/debugfs))
CHECK_ENV = CHECK=$(CHECK) FORM=$(FORM) OUT=$(OUT) KERNEL=$(BUILD)/vmlinuz BOOT='$(CHECK_BOOT)' \
	CMDLINE='$(CHECK_CMDLINE)' SLOTS=$(SLOTS_UUID) DEBUGFS=$(DEBUGFS) HOWL=$(HOWL) TAR=$(TAR)
# built NAME, COMMAND logs COMMAND to CHECK/NAME-build.log, and shows its tail on failure.
built = mkdir -p $(CHECK) && $(2) >$(CHECK)/$(1)-build.log 2>&1 || \
	{ tail -n 20 $(CHECK)/$(1)-build.log; echo "FAIL   $(1) build: see $(CHECK)/$(1)-build.log"; exit 1; }
# What every check needs, built once, before the forms build in parallel.
_check-shared: $(HOWL) $(TEST_SK)
	@$(call built,shared,$(MAKE) --no-print-directory FORM=minimal DEV=1 APP= image)

# CI runs each group as a job; SHARD=K/N runs every Nth form from the Kth, in name order.
ifneq ($(SHARD),)
ifeq ($(shell echo '$(SHARD)' | awk -F/ '/^[1-9][0-9]*\/[1-9][0-9]*$$/ && $$1 <= $$2'),)
$(error SHARD=$(SHARD): K/N, the Kth of N, 1 <= K <= N)
endif
endif
shard = $(if $(SHARD),$(shell echo $(sort $(1)) | tr ' ' '\n' | \
	awk -F/ -v s=$(SHARD) 'BEGIN { split(s, a, "/") } (NR - 1) % a[2] == a[1] - 1'),$(1))
# Octal keeps Make's comment parser and awk's escape handling portable.
APP_CHECK_FORMS := $(shell awk '!/^\043/ && NF { print $$1 }' test/app-fixtures)
.PHONY: check-apps $(addprefix check-app-,$(APP_CHECK_FORMS))
check-apps: $(addprefix check-app-,$(call shard,$(APP_CHECK_FORMS)))
$(foreach f,$(APP_CHECK_FORMS),$(eval check-$(f): check-app-$(f)))
check-forms:     $(addprefix check-,$(call shard,$(FORMS_FOR_ARCH))) _test/form-coverage
check-shellfree: $(addprefix check-shellfree-,$(call shard,$(FORMS_FOR_ARCH)))
# check-secureboot runs where firmware boots fast enough: an arm64 host
# with its own accelerator. Emulated arm64 skips it, as it skips the UEFI
# boots below.
check-integrity: check-slot check-verity check-deadman check-posture \
	$(if $(filter aarch64-hvf aarch64-kvm,$(ARCH)-$(ACCEL)),check-secureboot)

# IPE is opt-in; enrolled images update through signed prebuilt bundles.
.PHONY: ipe-kernel check-ipe _check-ipe
# A test kernel, IPE trusting WEREWOLF_IPE_CRT (tools/test-kernel). On macOS,
# QEMU_KERNEL_IMAGE and QEMU_BASE_INITRAMFS name melange's guest.
ipe-kernel:
	@[ -n "$(WEREWOLF_IPE_CRT)" ] || \
		{ echo "ipe-kernel: WEREWOLF_IPE_CRT must name the test IPE certificate" >&2; exit 1; }
	tools/test-kernel $(ARCH) $(WEREWOLF_IPE_CRT) $(IPE_KERNEL)

IPE_PROBE = $(BUILD)/test/ipe-probe-root/usr/lib/werewolf/ipe-probe
$(IPE_PROBE): test/ipe-init.zig lib/ipe.zig lib/dm.zig lib/verity.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -target $(ARCH)-linux-musl --dep dm --dep verity --dep ipe \
		-Mroot=$< -Mdm=lib/dm.zig -Mverity=lib/verity.zig -Mipe=lib/ipe.zig -femit-bin=$@
check-ipe: $(HOWL) $(VERITY_BIN) $(IPE_PROBE)
	@[ "$(IPE)" = 1 ] || { echo "check-ipe: set IPE=1 and the kernel, key and certificate paths" >&2; exit 1; }
	$(MAKE) --no-print-directory FORM=minimal DEV=1 APP=$(BUILD)/test/ipe-probe-root image
	$(MAKE) --no-print-directory FORM=minimal DEV=1 APP=$(BUILD)/test/ipe-probe-root _check-ipe
_check-ipe:
	@$(CHECK_ENV) IPE_PROBE=$(IPE_PROBE) VERITY=$(VERITY_BIN) \
		IPE_KEY=$(WEREWOLF_IPE_KEY) IPE_CERT=$(WEREWOLF_IPE_CRT) test/check-ipe $(CHECK_QEMU)
.PHONY: check-image-updater
check-image-updater: $(HOWL)
	@[ "$(IPE)" = 1 ] || { echo "check-image-updater: set IPE=1 and its kernel/key/certificate" >&2; exit 1; }
	@$(CHECK_ENV) ARCH=$(ARCH) IPE_KERNEL=$(IPE_KERNEL) IPE_KEY=$(WEREWOLF_IPE_KEY) \
		IPE_CERT=$(WEREWOLF_IPE_CRT) test/check-image-updater $(QEMU) -smp 2 -m 2048 -no-reboot -device virtio-rng-pci

# Continuous EFI update: the new UKI and external root must agree under IPE.
IPE_UPDATE_SECUREBOOT ?= 1
check-image-updater-uki: $(HOWL)
	@[ "$(IPE)" = 1 ] || { echo "check-image-updater-uki: set IPE=1 and its kernel/key/certificate" >&2; exit 1; }
	@$(CHECK_ENV) ARCH=$(ARCH) IPE_UPDATE_BOOT=efi IPE_UPDATE_SECUREBOOT=$(IPE_UPDATE_SECUREBOOT) \
		FIRMWARE=$(UEFI_FIRMWARE) IPE_KERNEL=$(IPE_KERNEL) IPE_KEY=$(WEREWOLF_IPE_KEY) \
		IPE_CERT=$(WEREWOLF_IPE_CRT) test/check-updater-uki $(QEMU) -smp 2 -m 2048 -device virtio-rng-pci
# check-adhoc pulls an OCI image, too slowly on emulated arm64.
check-cloud:     check-metadata check-nodata check-lease check-static check-people $(if $(filter aarch64-tcg,$(ARCH)-$(ACCEL)),,check-adhoc)
check: check-forms check-shellfree check-integrity check-cloud check-persist check-syslog
	@echo "check: every form, and a slot, passed"

NATIVE_FORMS := $(filter-out $(shell $(FORM_ASK) having native false),$(FORMS_FOR_ARCH))
.PHONY: $(addprefix check-native-,$(NATIVE_FORMS))
check-native: $(addprefix check-native-,$(call shard,$(NATIVE_FORMS)))
$(addprefix check-native-,$(NATIVE_FORMS)): check-native-%: | _check-shared
	@$(call built,$*-native,$(MAKE) --no-print-directory FORM=$* DEV= slot)
	@$(MAKE) --no-print-directory FORM=$* DEV= _check-native
_check-native:
	@test/cage $(FORM) $(OUT)/slot/root.erofs $(CHECK)/$(FORM)-native.log
seal-learn: | _check-shared
	-@$(MAKE) --no-print-directory -k SEAL_LEARN=1 $(addprefix check-,$(FORMS)) check-slot check-persist \
		check-nodata check-lease check-static check-metadata
	@test/seal-learn $(BUILD)/check-learn

REPEAT ?= 10
check-one: | _check-shared
	@$(call built,$(FORM),$(CHECK_MAKE) FORM=$(FORM) image)
	@test/check-one $(REPEAT) $(CHECK) $(FORM) $(CHECK_MAKE) FORM=$(FORM) _check-form

# Repeated and overlapping posture scans, stale fixtures and log evidence.
check-posture: | _check-shared
	@$(CHECK_MAKE) FORM=minimal CHECK_NAME=posture FORM_CHECKS=test/checks-posture _check-form

check-%: | _check-shared
	@$(call built,$*,$(CHECK_MAKE) FORM=$* image)
	@$(CHECK_MAKE) FORM=$* _check-form

# Native clients are a separate generated form, never DEV and never a member
# of /etc/sv. Compare their baseline before booting, then reuse one data disk.
.PHONY: check-native-tests _check-native-tests
check-native-tests: $(addprefix check-native-tests-,$(NATIVE_TEST_FORMS))
$(addprefix check-native-tests-,$(NATIVE_TEST_FORMS)): check-native-tests-%: $(HOWL)
	@$(call built,$*-baseline,$(MAKE) --no-print-directory FORM=$* DEV= image)
	PRODUCTION_OUT=$(BUILD)/$*$(if $(IPE),-ipe) python3 test/native-tests prepare $* $(ARCH)
	@$(call built,$*-native,$(MAKE) --no-print-directory FORM=build/native-tests/$(ARCH)/$*/native-test-$* DEV= image)
	BUILD=$(BUILD) PRODUCTION_OUT=$(BUILD)/$*$(if $(IPE),-ipe) \
		TEST_OUT=$(BUILD)/native-test-$*$(if $(IPE),-ipe) python3 test/native-tests compare $* $(ARCH)
	@$(MAKE) --no-print-directory FORM=build/native-tests/$(ARCH)/$*/native-test-$* DEV= NATIVE_FORM=$* _check-native-tests
_check-native-tests:
	@$(CHECK_ENV) PRODUCTION_OUT=$(BUILD)/$(NATIVE_FORM)$(if $(IPE),-ipe) \
		python3 test/native-tests run $(NATIVE_FORM) $(ARCH) $(CHECK_QEMU)

# Keep legacy checks until all their security assertions have native equivalents.
$(addprefix check-,$(NATIVE_TEST_FORMS)): check-%: check-native-tests-%

# Test the actual application-carrier form with code in its verified image,
# as well as its ordinary boot without code. A separate name avoids sharing
# disks, configuration or logs with check-FORM under make -j.
$(addprefix check-app-,$(APP_CHECK_FORMS)): check-app-%: | _check-shared
	@test/app-fixture $* $(CHECK)/apps/$*
	@$(call built,app-$*,$(CHECK_MAKE) FORM=$* APP=$(CHECK)/apps/$* image)
	@$(CHECK_MAKE) FORM=$* APP=$(CHECK)/apps/$* CHECK_NAME=app-$* CHECK_SKIP= \
		FORM_CHECKS=$(shell awk -v form=$* '$$1 == form { print $$3 }' test/app-fixtures) AGAIN_FORMS= _check-form
# Each form's ports get their own host ports, so forms boot in parallel.
check_port = $(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x '$(2)' | cut -d: -f1 | awk '{ print $(1) + $$1 }')
# A honeypot may offer an SSH banner on 22 without operator logins.
CHECK_SSH := $(if $(and $(filter sshd bastion gitea sftpgo,$(CHAIN)),$(filter 22,$(shell $(FORM_ASK) listens $(FORM_REF)))),$(call check_port,22200,$(FORM)))
CHECK_WEB_PORT := $(call form_check,web)
CHECK_WEB := $(if $(CHECK_WEB_PORT),$(call check_port,23200,$(FORM)))
CHECK_SKIP ?= $(call form_check,skip)
CHECK_FWD = $(if $(CHECK_SSH),$(,)hostfwd=tcp:127.0.0.1:$(CHECK_SSH)-:22$(if $(CHECK_WEB),$(,)hostfwd=tcp:127.0.0.1:$(CHECK_WEB)-:$(CHECK_WEB_PORT)))
# The forms booted again on the disks they left (docs/testing.md).
AGAIN_FORMS ?= minimal sshd prod-ssh gitea vaultwarden demo samba paperless mongodb rabbitmq
ifeq ($(AGAIN_FORMS),all)
override AGAIN_FORMS := $(FORMS)
endif
_check-form: $(HOWL) $(TEST_SK)
	@$(CHECK_ENV) FORM_REF=$(FORM_REF) FORM_DIR=$(FORM_DIR) SKIP='$(CHECK_SKIP)' \
		CHECK_NAME='$(CHECK_NAME)' FORM_CHECKS='$(FORM_CHECKS)' \
		AGAIN=$(filter $(AGAIN_FORMS),$(FORM)) SSH_PORT=$(CHECK_SSH) SSH_SK_PROVIDER=$(CURDIR)/$(TEST_SK) \
		KEPT_KEYS=$(CHECK_KEPT_KEYS) GITEA_PORT=$(CHECK_WEB) test/check-form \
		$(subst user$(,)id=n0,user$(,)id=n0$(CHECK_FWD),$(CHECK_QEMU))

check-adhoc: $(HOWL) | _check-shared
	@mkdir -p $(CHECK) && rm -rf $(BUILD)/adhoc/check-oci
	@$(HOWL) form --build --with prod --services.web.image cgr.dev/chainguard/nginx --services.web.listen tcp/8080 --services.web.write /var/lib/nginx/tmp -o $(BUILD)/adhoc/check-oci >$(CHECK)/check-oci-form.log 2>&1 || \
		{ tail -n 20 $(CHECK)/check-oci-form.log; echo "FAIL   check-oci form: see $(CHECK)/check-oci-form.log"; exit 1; }
	@$(call built,check-oci,$(CHECK_MAKE) FORM=$(BUILD)/adhoc/check-oci image)
	@$(CHECK_MAKE) FORM=$(BUILD)/adhoc/check-oci _check-form

# Generated forms (test/bastion-form, test/people-form): rules of their own, so check-% takes none of these nor check-shellfree-FORM.
# People uses 22199, below the forms' ports, so check-cloud and check-forms can run together.
check-bastion check-people: check-%: $(HOWL) $(TEST_SK) | _check-shared
	@test/$*-form $(CHECK) $(FORM_TOOL) $(CURDIR)/$(TEST_SK)
	@$(call built,$*,$(CHECK_MAKE) FORM=$(CHECK)/$*-check image)
	@$(CHECK_MAKE) FORM=$(CHECK)/$*-check CHECK_SSH=$(if $(filter bastion,$*),$(call check_port,22200,bastion),22199) $(if $(filter bastion,$*),CHECK_KEPT_KEYS=1) _check-form
$(addprefix check-shellfree-,$(FORMS)): check-shellfree-%: $(HOWL)
	@$(call built,$*-shellfree,$(MAKE) --no-print-directory FORM=$* DEV= image)
	@$(MAKE) --no-print-directory FORM=$* DEV= _check-shellfree
_check-shellfree:
	@$(CHECK_ENV) FORM_REF=$(FORM_REF) FORM_DIR=$(FORM_DIR) CONSOLE=$(wildcard $(FORM_DIR)/test/console) test/check-shellfree $(CHECK_QEMU)

# The Linux kernel, private namespaces and a local DNS/TLS/DHCP fixture; no internet.
$(BUILD)/dns-policy: test/dns-policy.zig $(wildcard lib/*.zig)
	$(zig_check)
	zig build-exe -O ReleaseSafe -target $(ARCH)-linux-musl $(call ZIG_MODULES,$<) -femit-bin=$@
$(BUILD)/posture-egress: test/posture-egress.zig $(wildcard cmd/posture/*.zig) $(wildcard lib/*.zig)
	$(zig_check)
	zig build-exe -O ReleaseSafe -target $(ARCH)-linux-musl --dep posture $(call ZIG_MODULES,$<) \
		--dep cmdline --dep allow --dep service --dep audit --dep ipe --dep tpm -Mposture=cmd/posture/posture.zig -femit-bin=$@
check-dns: $(call program_bin,fence) $(call program_bin,dhcp-client) $(BUILD)/dns-policy $(BUILD)/posture-egress
	$(DNS_TEST_RUNNER) python3 test/check-dns $(call program_bin,fence) $(BUILD)/dns-policy $(call program_bin,dhcp-client) $(BUILD)/posture-egress
	$(DNS_TEST_RUNNER) python3 test/check-lan $(call program_bin,fence)

$(BUILD)/updater-installer-test: cmd/slot-update/installer.zig lib/sandbox.zig lib/seal.zig
	$(zig_check)
	mkdir -p $(dir $@)
	zig test -target $(ARCH)-linux-musl --test-no-exec -femit-bin=$@ \
		--dep sandbox -Mroot=$< --dep seal -Msandbox=lib/sandbox.zig -Mseal=lib/seal.zig
$(BUILD)/updater-coordinator-test: $(wildcard cmd/slot-update/*.zig) $(wildcard lib/*.zig)
	$(zig_check)
	mkdir -p $(dir $@)
	zig test -target $(ARCH)-linux-musl --test-filter coordinator --test-no-exec -femit-bin=$@ $(call ZIG_MODULES,cmd/slot-update/slot-update.zig)
.PHONY: check-updater-installer
check-updater-installer: $(BUILD)/updater-installer-test $(BUILD)/updater-coordinator-test
	$(LINUX_TEST_RUNNER) sh test/check-updater-installer $(OUT)/rootfs.tar $(OUT)/overlay.tar $(BUILD)/updater-installer-test
	$(LINUX_TEST_RUNNER) sh test/check-updater-installer $(OUT)/rootfs.tar $(OUT)/overlay.tar $(BUILD)/updater-coordinator-test

check-lan: $(call program_bin,fence)
	$(DNS_TEST_RUNNER) python3 test/check-lan $(call program_bin,fence)

# These boot what a form's check built; prod supplies DHCP, metadata and /data.
check-lease check-nodata check-metadata: | _check-shared check-prod
	@$(CHECK_MAKE) FORM=prod _$@
check-static check-verity: | _check-shared check-minimal
	@$(CHECK_MAKE) FORM=minimal _$@
check-slot: | _check-shared check-minimal
	@$(call built,slot,$(CHECK_MAKE) FORM=minimal slot)
	@$(CHECK_MAKE) FORM=minimal _check-slot
# check-slot builds the same slot in the same place, so these follow it.
check-deadman: | _check-shared check-minimal check-slot
	@$(call built,deadman,$(CHECK_MAKE) FORM=minimal slot)
	@$(CHECK_MAKE) FORM=minimal _check-deadman
check-secureboot: $(HOWL)
	@rm -f $(CHECK)/sb.key $(CHECK)/sb.crt
	@mkdir -p $(CHECK)
	openssl req -newkey rsa:2048 -nodes -keyout $(CHECK)/sb.key -x509 -new \
		-subj /CN=werewolf-secureboot-check -days 30 -out $(CHECK)/sb.crt 2>/dev/null
	@$(MAKE) --no-print-directory FORM=prod ARCH=$(ARCH) _check-secureboot
check-lima-secureboot: check-secureboot
	python3 test/check-lima-secureboot $(CHECK)/secureboot/release/prod-$(ARCH)-disk.qcow2 \
		$(CHECK)/secureboot/enrolled $(CHECK)/lima-secureboot
# check-firecracker builds for x86_64 here and boots on FIRECRACKER_HOST
# (default galadriel) through a cross-compiled howl, so the host needs no
# toolchain (docs/testing.md). The form is sshd relaxed to take a key file,
# which the host has, as a posture weakness it declares.
FIRECRACKER_HOST ?= galadriel
FC_FORM = build/adhoc/check-fc
POSTURE_KNOWN_X64 := $(shell awk -v b='*' -v a=x86_64 '$$1 == b || $$1 == a { $$1 = ""; k = k $$0 } END { print k }' test/posture-known) \
	network-no-login programs-no-downloaders programs-no-interpreters programs-no-shell network-ssh-security-keys
check-firecracker: | _check-shared
	@rm -rf $(FC_FORM) && $(HOWL) form --build --with sshd --sshd.pubkey-accepted-algorithms ssh-ed25519 -o $(FC_FORM)/
	@$(call built,firecracker,$(MAKE) --no-print-directory ARCH=x86_64 FORM=$(FC_FORM) DEV= programs disk)
	@mkdir -p $(CHECK) build/x86_64/tools
	zig build-exe -O ReleaseSafe -target x86_64-linux-musl $(call ZIG_MODULES,cmd/howl/howl.zig) -femit-bin=build/x86_64/tools/howl
	zig build-exe -O ReleaseSafe -target x86_64-linux-musl $(FORM_TOOL_MODULES) -femit-bin=build/x86_64/tools/form
	zig build-exe -O ReleaseSafe -target x86_64-linux-musl --dep verity -Mroot=tools/verity.zig -Mverity=lib/verity.zig -femit-bin=build/x86_64/tools/verity
	@$(CHECK_ENV) FIRECRACKER_HOST=$(FIRECRACKER_HOST) FORM_DIR=$(FC_FORM) \
		POSTURE_KNOWN='$(POSTURE_KNOWN_X64)' test/check-firecracker
_check-lease _check-nodata _check-static _check-verity _check-slot _check-deadman: $(HOWL)
	@$(CHECK_ENV) test/$(@:_%=%) $(CHECK_QEMU)
_check-secureboot: $(HOWL)
	@$(CHECK_ENV) ARCH=$(ARCH) SECUREBOOT_DIR=$(SECUREBOOT_DIR) \
		BOOT_KEY=$(CHECK)/sb.key BOOT_CRT=$(CHECK)/sb.crt test/check-secureboot \
		qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic -smp 2 \
		-m $(CHECK_MEMORY) -no-reboot
_check-metadata:
	@$(CHECK_ENV) ARCH=$(ARCH) FIRMWARE=$(if $(filter aarch64,$(ARCH)),$(UEFI_FIRMWARE)) \
		test/check-metadata $(QEMU) -smp 2 -m 1024 -no-reboot -device virtio-rng-pci

# Each run copies x86_64's UEFI variables, sparing the template; splash-time=0 skips edk2's 5 s wait.
UEFI_FIRMWARE = $(firstword $(wildcard $(if $(filter aarch64,$(ARCH)), \
	/opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/local/share/qemu/edk2-aarch64-code.fd \
	/usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd, \
	/opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/local/share/qemu/edk2-x86_64-code.fd \
	/usr/share/qemu/edk2-x86_64-code.fd /usr/share/ovmf/OVMF.fd \
	/usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
	/usr/share/edk2/x64/OVMF_CODE.4m.fd)))
UEFI_VARS = $(firstword $(wildcard /opt/homebrew/share/qemu/edk2-i386-vars.fd /usr/local/share/qemu/edk2-i386-vars.fd \
	/usr/share/qemu/edk2-i386-vars.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd \
	/usr/share/edk2/x64/OVMF_VARS.4m.fd))
UEFI_VARS_COPY = $(CHECK)/ovmf-vars.fd
UEFI_FLAGS = -boot menu=on,splash-time=0 $(if $(filter aarch64,$(ARCH)),-bios $(UEFI_FIRMWARE),\
	-drive if=pflash,format=raw,unit=0,readonly=on,file=$(UEFI_FIRMWARE) \
	-drive if=pflash,format=raw,unit=1,file=$(UEFI_VARS_COPY))
UEFI_ENV = CHECK=$(CHECK) FORM=$(FORM) ARCH=$(ARCH) FIRMWARE=$(UEFI_FIRMWARE) \
	UEFI_VARS=$(UEFI_VARS) UEFI_VARS_COPY=$(UEFI_VARS_COPY)

# Emulated arm64 skips the UEFI boots: edk2 never reaches systemd-boot in time.
check-dist:
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   dist               emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@failed=0; for f in $(filter-out $(DIST_DIRECT_FORMS),$(RELEASE_FORMS)); do \
		$(MAKE) --no-print-directory FORM=$$f _check-dist || failed=1; done; exit $$failed
endif
_check-dist:
	@$(UEFI_ENV) DIST=$(DIST) HOWL=$(HOWL) FORM_REF=$(FORM_REF) FORM_DIR=$(FORM_DIR) \
		CONSOLE=$(wildcard $(FORM_DIR)/test/console) \
		POSTURE_KNOWN="$(filter-out boot-ipe-enforced,$(POSTURE_KNOWN))" \
		test/check-dist qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) \
		-nographic -smp 2 -m $(or $(call form_check,memory),2048) -snapshot -no-reboot $(UEFI_FLAGS) -device virtio-rng-pci \
		-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile=

# check-persist boots without EL2 (edk2 under HVF never boots) and offline; CI sets PERSIST_AFTER=.
PERSIST_ARGS = console=$(CONSOLE) werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) $(SEAL_ARGS)
PERSIST_AFTER ?= check-demo
check-persist: | _check-shared $(PERSIST_AFTER)
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   persist            emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@[ -n "$(UEFI_FIRMWARE)" ] || { echo "FAIL   persist            no UEFI firmware for $(ARCH) (edk2 or OVMF)"; exit 1; }
	@[ "$(ARCH)" = aarch64 ] || [ -n "$(UEFI_VARS)" ] || { echo "FAIL   persist            no UEFI variables template for $(ARCH) (edk2-i386-vars.fd or OVMF_VARS.fd)"; exit 1; }
	@rm -f $(CHECK)/persist.img
	@$(call built,persist,$(CHECK_MAKE) FORM=demo disk DISK=$(CHECK)/persist.img DISK_MIB=2048 DISK_ARGS="$(PERSIST_ARGS)")
	@$(CHECK_MAKE) FORM=demo _check-persist
endif
_check-persist:
	@$(UEFI_ENV) test/check-persist qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic \
		-smp 2 -m 2048 -no-reboot -device virtio-rng-pci $(UEFI_FLAGS) \
		-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile= \
		-drive file=$(CHECK)/persist.img,format=raw,if=virtio

check-gcp-metadata: $(HOWL) $(TEST_SK)
	@python3 test/gcp-metadata $(HOWL) $(CURDIR)/$(TEST_SK) $(ARCH)

check-gcp check-aws check-azure: check-%:
	@$(MAKE) --no-print-directory FORM=prod-ssh CLOUD=$* _check-cloud

# Explicit live lifecycle tests; cloud credentials are never required by PR CI.
.PHONY: check-ab-qemu check-ab-lima-qemu check-ab-lima-vz check-ab-aws check-ab-gcp check-ab-azure check-ab-bhyve check-ab-firecracker check-ab-proxmox check-bhyve-secureboot _check-provider-ab
check-ab-qemu check-ab-lima-qemu check-ab-lima-vz check-ab-aws check-ab-gcp check-ab-azure check-ab-bhyve check-ab-firecracker check-ab-proxmox: check-ab-%:
	@$(MAKE) --no-print-directory AB_PROVIDER=$* _check-provider-ab
check-bhyve-secureboot: $(HOWL)
	@test -n "$(AB_FIXTURE)" || { echo 'set AB_FIXTURE to a signed x86_64 fixture.json' >&2; exit 1; }
	@CHECK=$(CHECK) python3 test/check-bhyve-secureboot $(HOWL) $(AB_FIXTURE)
_check-provider-ab: $(HOWL)
	@CHECK=$(CHECK) IPE_KERNEL=$(IPE_KERNEL) IPE_KEY=$(WEREWOLF_IPE_KEY) IPE_CERT=$(WEREWOLF_IPE_CRT) \
		python3 test/check-provider-ab $(HOWL) $(AB_PROVIDER) $(ARCH)

build/x86_64/tools/howl-linux: cmd/howl/howl.zig $(HOWL) $(wildcard cmd/howl/*.zig) files.zig
	@mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -target x86_64-linux-musl $(call ZIG_MODULES,$<) -femit-bin=$@
build/x86_64/tools/howl-freebsd: cmd/howl/howl.zig $(HOWL) $(wildcard cmd/howl/*.zig) files.zig
	@mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -target x86_64-freebsd $(call ZIG_MODULES,$<) -femit-bin=$@

# A form README's fences (docs/design/examples.md). Not part of make check:
# the console checks stay, and a README with no Getting Started is skipped.
example-%: $(HOWL)
	@test/example local $*
examples examples-gcp: $(HOWL)
examples:
	@status=0; for f in $(call shard,$(FORMS)); do test/example local $$f || status=1; done; exit $$status
examples-gcp:
	@status=0; for f in $(call shard,$(FORMS)); do test/example gcp $$f || status=1; done; exit $$status
_check-cloud: $(HOWL)
	@mkdir -p $(CHECK)
	@runner=$$(mktemp '$(CHECK)/cloud-$(CLOUD).XXXXXXXX') && \
		trap 'rm -f "$$runner"' EXIT && cp test/cloud "$$runner" && chmod 700 "$$runner" && \
		HOWL=$(HOWL) "$$runner" $(CLOUD) $(FORM) $(ARCH)
check-compose: slot
	@OUT=$(OUT) FORM=$(FORM) ARCH=$(ARCH) DEV=$(DEV) \
		FORM_TOOL=$(abspath $(FORM_TOOL)) TAR=$(TAR) test/check-compose

# EROFS_OPTS must match the options lib/image.zig gives mkfs.erofs.
EROFS_OPTS = -b 4096 -zzstd,level=9 -C65536 -Eall-fragments,dedupe
check-updater check-updater-staged check-updater-published: | _check-shared
	@$(MAKE) --no-print-directory DEV=1 $(if $(filter %-staged,$@),STAGED=1) $(if $(filter %-published,$@),PUBLISHED=1 FORM=test/published-form,FORM=prod) _check-updater
_check-updater: $(VERITY_BIN)
	@mkdir -p $(CHECK)/update-$(FORM) && $(MAKE) --no-print-directory slot >$(CHECK)/update-$(FORM)/build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/update-$(FORM)/build.log; echo "FAIL   update build: see $(CHECK)/update-$(FORM)/build.log"; exit 1; }
	@CHECK=$(CHECK) FORM=$(FORM) OUT=$(OUT) TAR=$(TAR) DEBUGFS=$(DEBUGFS) SLOTS=$(SLOTS_UUID) PRUNE='$(call form_list,prune)' \
		EROFS_OPTS='$(EROFS_OPTS)' VERITY=$(VERITY_BIN) CONSOLE=$(CONSOLE) SEAL_ARGS='$(SEAL_ARGS)' STAGED='$(STAGED)' PUBLISHED='$(PUBLISHED)' \
		test/check-updater $(QEMU) -smp 2 -m 2048 -no-reboot -device virtio-rng-pci -netdev user,id=n0 \
		-device virtio-net-pci,netdev=n0,romfile=

ci:
	test/lima-ci

# Signed UKIs travel with the exact root they seal, not a locally composed root.
.PHONY: check-updater-uki check-image-updater-uki
check-updater-uki: check-image-updater-uki
# clean keeps the locks, so the next build is the same as the last.
clean:
	rm -rf $(filter-out $(LOCK),$(wildcard build/*))
# help prints this file's opening comment, up to its first empty line.
help:
	@sed -n '2,/^$$/s/^# \{0,1\}//p' Makefile

# BEGIN: lint-install .
LINTERS := yamllint-lint zig-lint doc-lint
FIXERS := zig-fix doc-fix
.PHONY: lint _lint fix $(LINTERS) $(FIXERS)
lint: _lint
_lint:
	@$(MAKE) --no-print-directory -k -j3 $(LINTERS)
fix:
	@status=0; for t in $(FIXERS); do $(MAKE) $$t || status=1; done; exit $$status
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

YAMLLINT_VERSION ?= 1.37.1
YAMLLINT_ROOT := $(LINT_ROOT)/out/linters/yamllint-$(YAMLLINT_VERSION)
YAMLLINT_BIN := $(YAMLLINT_ROOT)/dist/bin/yamllint
$(YAMLLINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yamllint-*
	curl -sSfL https://github.com/adrienverge/yamllint/archive/refs/tags/v$(YAMLLINT_VERSION).tar.gz | tar -C $(LINT_ROOT)/out/linters -zxf -
	cd $(YAMLLINT_ROOT) && pip3 install --target dist . || pip install --target dist .
yamllint-lint: $(YAMLLINT_BIN)
	PYTHONPATH=$(YAMLLINT_ROOT)/dist $(YAMLLINT_BIN) $(YAML_SOURCES)
# END: lint-install .

# zigfix --check uses Zig's AstGen, including functions nothing calls.
# Prune generated trees before descending: image roots contain millions of files.
source_find = find . -type d \( -name .git -o -path './build' -o -path './out' -o -path './.zig-cache' -o -path './.claude' $(1) \) -prune -o -type f $(2) -print
ZIG_SOURCES := $(shell $(call source_find,,-name '*.zig'))
YAML_SOURCES := $(shell $(call source_find,-o -path './dist' -o -path './config',\( -name '*.yaml' -o -name '*.yml' -o -name '.yamllint' \)))
ZIGFIX := $(LINT_ROOT)/out/tools/zigfix
$(ZIGFIX): tools/zigfix.zig
	mkdir -p $(dir $@)
	zig build-exe -O Debug -femit-bin=$@ tools/zigfix.zig
# The sha256s are those of ziglint's checksums.txt when it was pinned.
ZIGLINT_VERSION ?= 0.5.3
ZIGLINT_PLATFORM := $(subst arm64,aarch64,$(shell uname -m))-$(if $(filter Darwin,$(HOST_OS)),macos,linux)
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
zig-lint: $(ZIGFIX) $(ZIGLINT_BIN)
	$(ZIGFIX) --check $(ZIG_SOURCES)
	$(ZIGLINT_BIN) $(ZIG_SOURCES)
zig-fix: $(ZIGFIX)
	$(ZIGFIX) $(ZIG_SOURCES)

DOC_SOURCES := $(shell $(call source_find,-o -path './dist',-name '*.md'))
DOC_CHECK := $(LINT_ROOT)/out/tools/doc-check
$(DOC_CHECK): tools/doc-check.zig
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -femit-bin=$@ tools/doc-check.zig
doc-lint: $(DOC_CHECK)
	$(DOC_CHECK) $(DOC_SOURCES)
doc-fix: $(DOC_CHECK)
	$(DOC_CHECK) --fix $(DOC_SOURCES)
